"""服务器在线检测 API 与只读运维可视化入口。

服务器部署应启动 ``uvicorn src.runtime_api:app``。本模块不导入本地训练 Dashboard、
训练代码、数据集或载荷生成器，因此可随最小运行包单独上传。
"""

from __future__ import annotations

from collections import defaultdict
import os
import re
import threading
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .parser import parse_auto
from .ops_dashboard import create_ops_router, require_control_auth
from .pipeline import DetectionPipeline
from .settings import MODEL_ROOT


class UTF8JSONResponse(JSONResponse):
    """为旧客户端显式声明 UTF-8。"""

    media_type = "application/json; charset=utf-8"


DESCRIPTION = """纯在线 Web 攻击检测服务。

提供载荷检测、完整 HTTP 请求检测、批量检测、健康检查、内存统计与服务器运维
可视化；不包含数据集、训练、生成器和本地训练后台。
"""

app = FastAPI(
    title="Web 攻击载荷在线检测服务",
    description=DESCRIPTION,
    version="1.0.0",
    default_response_class=UTF8JSONResponse,
)

_cors_origins = [
    value.strip()
    for value in os.environ.get(
        "CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
    ).split(",")
    if value.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _load_pipeline() -> tuple[DetectionPipeline, list[str]]:
    detector = DetectionPipeline()
    errors: list[str] = []
    model_paths = (
        ("lgbm", os.environ.get("LGBM_MODEL_PATH") or str(MODEL_ROOT / "lgbm_v4.pkl"), detector.load_lgbm),
        ("text_model", os.environ.get("TEXT_MODEL_PATH") or str(MODEL_ROOT / "text_lr_v4.pkl"), detector.load_text_model),
    )
    for name, path, loader in model_paths:
        try:
            loader(path)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
    return detector, errors


pipeline, MODEL_ERRORS = _load_pipeline()


def replace_pipeline(new_pipeline: DetectionPipeline) -> None:
    """原子替换活动管线，供本地 Dashboard 切换模型。"""

    global pipeline, MODEL_ERRORS
    pipeline = new_pipeline
    MODEL_ERRORS = []


def _require_models() -> None:
    if pipeline.lgbm_model is None or pipeline.text_model is None:
        raise HTTPException(
            status_code=503,
            detail="Detection models not fully loaded; service is not ready",
        )


class DetectRequest(BaseModel):
    payload: str = Field(..., min_length=1, max_length=8192)
    param_location: str = Field(default="query", pattern="^(query|body|header|cookie|path)$")
    param_name: str = Field(default="value", max_length=256)


class BatchDetectRequest(BaseModel):
    items: list[DetectRequest] = Field(..., min_length=1, max_length=100)


class DetectResponse(BaseModel):
    verdict: str
    confidence: float
    layer: str
    elapsed_ms: float
    rule_hits: list[str] = Field(default_factory=list)
    l2_score: Optional[float] = None
    l3_score: Optional[float] = None
    normalized: str = ""
    confusion_meta: dict = Field(default_factory=dict)
    features: dict[str, float] = Field(default_factory=dict)


class HttpDetectResponse(BaseModel):
    verdict: str
    total_params: int
    attack_count: int
    benign_count: int
    uncertain_count: int = 0
    elapsed_ms: float
    params: list[dict] = Field(default_factory=list)


_stats_lock = threading.Lock()
_stats = {
    "total_requests": 0,
    "attack_count": 0,
    "benign_count": 0,
    "uncertain_count": 0,
    "by_type": defaultdict(int),
    "by_layer": defaultdict(int),
    "recent_alerts": [],
    "latency_sum_ms": 0.0,
    "start_time": time.time(),
}


def _record_stats(verdict: str, layer: str, payload: str, elapsed_ms: float, rule_hits: list[str]) -> None:
    with _stats_lock:
        _stats["total_requests"] += 1
        _stats["by_layer"][layer] += 1
        _stats["latency_sum_ms"] += elapsed_ms
        if verdict == "attack":
            _stats["attack_count"] += 1
            attack_type = rule_hits[0] if rule_hits else "ml_detected"
            _stats["by_type"][attack_type] += 1
            _stats["recent_alerts"].insert(0, {
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "payload": payload[:80],
                "type": attack_type,
                "elapsed_ms": round(elapsed_ms, 2),
            })
            del _stats["recent_alerts"][50:]
        elif verdict == "benign":
            _stats["benign_count"] += 1
        else:
            _stats["uncertain_count"] += 1


def _detect_one(item: DetectRequest) -> DetectResponse:
    result = pipeline.detect(item.payload, item.param_location, item.param_name)
    _record_stats(result.verdict, result.layer, item.payload, result.elapsed_ms, result.rule_hits)
    return DetectResponse(
        verdict=result.verdict,
        confidence=round(result.confidence, 4),
        layer=result.layer,
        elapsed_ms=round(result.elapsed_ms, 3),
        rule_hits=result.rule_hits,
        l2_score=round(result.l2_score, 4) if result.l2_score is not None else None,
        l3_score=round(result.l3_score, 4) if result.l3_score is not None else None,
        normalized=result.normalized,
        confusion_meta=result.confusion_meta,
        features=result.features,
    )


@app.get("/health", tags=["system"])
def health():
    ready = pipeline.lgbm_model is not None and pipeline.text_model is not None
    return {
        "status": "ok" if ready else "degraded",
        "lgbm_loaded": pipeline.lgbm_model is not None,
        "text_model_loaded": pipeline.text_model is not None,
        "cache_size": len(pipeline.cache),
        "model_errors": MODEL_ERRORS,
    }


@app.post("/detect", response_model=DetectResponse, tags=["detection"])
def detect(req: DetectRequest):
    _require_models()
    try:
        return _detect_one(req)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Detection failed: {exc}") from exc


@app.post("/batch-detect", tags=["detection"])
def batch_detect(req: BatchDetectRequest):
    _require_models()
    results = []
    for item in req.items:
        try:
            detected = _detect_one(item)
            results.append(detected.model_dump(exclude={
                "normalized", "confusion_meta", "features", "l2_score", "l3_score",
            }))
        except Exception as exc:
            results.append({"verdict": "error", "error": str(exc)})
    return {"count": len(results), "results": results}


@app.post("/detect-http", response_model=HttpDetectResponse, tags=["detection"])
async def detect_http(request: Request):
    raw_body = await request.body()
    if len(raw_body) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="Request body exceeds 1 MiB limit")
    body = raw_body.decode("utf-8", errors="replace")
    started = time.perf_counter()

    smuggling_hits = []
    if re.search(r"(?i)content-length:", body) and re.search(r"(?i)transfer-encoding:", body):
        smuggling_hits.append("CL_TE_ambiguity")
    if len(re.findall(r"(?i)content-length:", body)) > 1:
        smuggling_hits.append("duplicate_content_length")
    if smuggling_hits:
        elapsed = (time.perf_counter() - started) * 1000
        for hit in smuggling_hits:
            _record_stats("attack", "L1-Raw", hit, 0.0, [hit])
        return HttpDetectResponse(
            verdict="attack",
            total_params=0,
            attack_count=len(smuggling_hits),
            benign_count=0,
            elapsed_ms=round(elapsed, 3),
            params=[{
                "param_name": "_protocol", "location": "header", "value": hit,
                "verdict": "attack", "layer": "L1-Raw", "elapsed_ms": 0.0,
                "rule_hits": [hit],
            } for hit in smuggling_hits],
        )

    _require_models()
    results = []
    for param in parse_auto(body):
        detected = _detect_one(DetectRequest(
            payload=param.value,
            param_location=param.location,
            param_name=param.name,
        ))
        item = detected.model_dump(exclude={"normalized", "confusion_meta", "features", "l2_score", "l3_score"})
        item.update({"param_name": param.name, "location": param.location, "value": param.value[:200]})
        results.append(item)

    attacks = sum(item["verdict"] == "attack" for item in results)
    uncertain = sum(item["verdict"] == "uncertain" for item in results)
    elapsed = (time.perf_counter() - started) * 1000
    return HttpDetectResponse(
        verdict="attack" if attacks else ("uncertain" if uncertain else "benign"),
        total_params=len(results),
        attack_count=attacks,
        benign_count=len(results) - attacks - uncertain,
        uncertain_count=uncertain,
        elapsed_ms=round(elapsed, 3),
        params=results,
    )


@app.get("/stats", tags=["monitoring"])
def get_stats():
    with _stats_lock:
        total = _stats["total_requests"]
        denominator = max(total, 1)
        return {
            "uptime_seconds": round(time.time() - _stats["start_time"], 1),
            "total_requests": total,
            "attack_count": _stats["attack_count"],
            "benign_count": _stats["benign_count"],
            "uncertain_count": _stats["uncertain_count"],
            "attack_rate": round(_stats["attack_count"] / denominator * 100, 2),
            "avg_latency_ms": round(_stats["latency_sum_ms"] / denominator, 2),
            "by_type": dict(sorted(_stats["by_type"].items(), key=lambda pair: -pair[1])[:20]),
            "by_layer": dict(_stats["by_layer"]),
            "recent_alerts": list(_stats["recent_alerts"][:20]),
        }


@app.post("/stats/reset", tags=["monitoring"])
def reset_stats(_: None = Depends(require_control_auth)):
    with _stats_lock:
        for key in ("total_requests", "attack_count", "benign_count", "uncertain_count"):
            _stats[key] = 0
        _stats["by_type"].clear()
        _stats["by_layer"].clear()
        _stats["recent_alerts"].clear()
        _stats["latency_sum_ms"] = 0.0
        _stats["start_time"] = time.time()
    return {"status": "ok"}


app.include_router(create_ops_router())
