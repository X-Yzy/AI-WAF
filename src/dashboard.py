"""可视化控制台后端。

控制台只暴露固定白名单任务（训练、测试、验证、WAF 对比、完整流程、数据审计），不会接受
任意命令或文件路径。耗时任务在单个后台线程中执行，页面通过轮询获取日志。
"""

from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .normalizer import normalize
from .obfuscator import generate, list_strategies
from .pipeline import DetectionPipeline
from .settings import (
    ATTACK_DATA_ROOT,
    LAB_CAPTURE_DATA_ROOT,
    MODEL_ROOT,
    MODERN_ATTACK_DATA_ROOT,
    NORMAL_DATA_ROOT,
    ORGANIZED_DATA_ROOT,
    PROJECT_ROOT,
    RAW_ATTACK_DATA_ROOT,
    RUNTIME_ROOT,
    SPECIALIZED_DATA_ROOT,
    VALIDATION_DATA_ROOT,
)


class ModelSelection(BaseModel):
    model_id: str = Field(description="由 /dashboard/models 返回的模型 ID")


class ObfuscationRequest(BaseModel):
    payload: str = Field(min_length=1, max_length=8192)
    strategies: list[str] = Field(default_factory=list, max_length=10)
    count: int = Field(default=5, ge=1, le=20)
    max_layers: int = Field(default=2, ge=1, le=5)
    seed: int = Field(default=42)
    param_location: str = Field(default="query", pattern="^(query|body|header|cookie|path)$")
    param_name: str = Field(default="value", max_length=128)


class JobRequest(BaseModel):
    action: str = Field(pattern="^(train|test|evaluate|compare-waf|all|validate-data)$")
    max_text_features: int = Field(default=140_000, ge=10_000, le=300_000)
    min_recall: float = Field(default=0.95, ge=0.80, le=1.0)


def evaluation_gates(evaluation: dict) -> dict[str, bool]:
    """Calculate delivery gates only from metrics present in the report."""

    def number(value: object) -> float | None:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed == parsed else None

    metrics = evaluation.get("metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    external = evaluation.get("external_sources")
    if not isinstance(external, dict):
        external = evaluation.get("external_fuzzdb")
    external = external if isinstance(external, dict) else {}
    latency = evaluation.get("latency_ms")
    latency = latency if isinstance(latency, dict) else {}
    fpr = number(metrics.get("fpr"))
    recall = number(metrics.get("recall"))
    external_recall = number(external.get("recall"))
    p99 = number(latency.get("p99", latency.get("heldout_p99")))
    return {
        "heldout_field_fpr_le_0_001": fpr is not None and fpr <= 0.001,
        "heldout_attack_recall_ge_0_97": recall is not None and recall >= 0.97,
        "external_fuzzdb_recall_ge_0_90": (
            external_recall is not None and external_recall >= 0.90
        ),
        "pipeline_p99_le_10_ms": p99 is not None and p99 <= 10.0,
    }


class DashboardService:
    """维护活动模型和唯一后台任务。"""

    def __init__(
        self,
        get_pipeline: Callable[[], DetectionPipeline],
        replace_pipeline: Callable[[DetectionPipeline], None],
        initial_model_id: str = "final-model",
    ) -> None:
        self.get_pipeline = get_pipeline
        self.replace_pipeline = replace_pipeline
        self.active_model_id = initial_model_id
        self.model_lock = threading.Lock()
        self.job_lock = threading.Lock()
        self.job: dict = {
            "id": None,
            "action": None,
            "status": "idle",
            "stage": "等待任务",
            "progress": 0,
            "started_at": None,
            "finished_at": None,
            "exit_code": None,
            "logs": [],
            "detail": "尚未启动后台任务",
            "events": [],
        }

    @staticmethod
    def _read_json(path: Path) -> dict:
        if not path.is_file():
            return {}
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def model_registry(self) -> list[dict]:
        candidates = [{
            "id": "final-model",
            "name": "最终竞赛模型",
            "version": "final",
            "feature": MODEL_ROOT / "lgbm_v4.pkl",
            "text": MODEL_ROOT / "text_lr_v4.pkl",
            "meta": MODEL_ROOT / "lgbm_v4.meta.json",
            "recommended": True,
        }]
        result = []
        for item in candidates:
            metadata = self._read_json(item["meta"])
            available = item["feature"].is_file() and item["text"].is_file()
            metrics = metadata.get("test_family_holdout") or metadata.get("test_all") or metadata.get("test") or {}
            result.append({
                "id": item["id"],
                "name": item["name"],
                "version": item["version"],
                "available": available,
                "active": item["id"] == self.active_model_id,
                "recommended": item["recommended"],
                "threshold": metadata.get("thresholds", {}).get("high"),
                "fusion": metadata.get("fusion", {}),
                "metrics": {
                    key: metrics.get(key) for key in ("precision", "recall", "f1", "fpr")
                },
                "environment": metadata.get("environment", {}),
                "files": {
                    "feature_mb": round(item["feature"].stat().st_size / 1048576, 2) if item["feature"].is_file() else 0,
                    "text_mb": round(item["text"].stat().st_size / 1048576, 2) if item["text"].is_file() else 0,
                },
            })
        return result

    def select_model(self, model_id: str) -> dict:
        record = next((item for item in self.model_registry() if item["id"] == model_id), None)
        if record is None or not record["available"]:
            raise HTTPException(status_code=404, detail="模型不存在或文件不完整")
        candidate = DetectionPipeline()
        try:
            candidate.load_lgbm(str(MODEL_ROOT / "lgbm_v4.pkl"))
            candidate.load_text_model(str(MODEL_ROOT / "text_lr_v4.pkl"))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"模型加载失败：{exc}") from exc
        with self.model_lock:
            self.replace_pipeline(candidate)
            self.active_model_id = model_id
        return {"status": "ok", "active_model_id": model_id}

    def overview(self) -> dict:
        raw = self._read_json(RAW_ATTACK_DATA_ROOT / "manifest.json")
        attack = self._read_json(ATTACK_DATA_ROOT / "manifest.json")
        organized = self._read_json(ORGANIZED_DATA_ROOT / "manifest.json")
        normal = self._read_json(NORMAL_DATA_ROOT / "manifest.json")
        modern = self._read_json(MODERN_ATTACK_DATA_ROOT / "manifest.json")
        specialized = self._read_json(SPECIALIZED_DATA_ROOT / "manifest.json")
        lab_captures = self._read_json(LAB_CAPTURE_DATA_ROOT / "manifest.json")
        raw_types = raw.get("attack_types", {})
        attack_types = attack.get("attack_types", {})
        normal_counts = normal.get("counts", {})
        organized_labels = organized.get("label_counts", {})
        representation_counts = organized.get("attack_representation_counts", {})
        representation_types = organized.get("attack_representation_type_counts", {})
        original_types = representation_types.get("original", {})
        obfuscated_types = representation_types.get("obfuscated", {})
        categories = list_strategies()
        return {
            "datasets": {
                "normal": {
                    "total": organized_labels.get(
                        "normal", normal.get("total_records", sum(normal_counts.values()) if normal_counts else 0)
                    ),
                    "groups": normal_counts,
                    "splits": normal.get("splits", {}),
                },
                "obfuscated_attack": {
                    "total": representation_counts.get("obfuscated", attack.get("total", 0)),
                    "types": obfuscated_types or {
                        name: int(info.get("count", 0)) for name, info in attack_types.items()
                    },
                    "legacy_subset_total": attack.get("total", 0),
                },
                "raw_attack": {
                    "total": representation_counts.get(
                        "original", sum(int(info.get("records", 0)) for info in raw_types.values())
                    ),
                    "types": original_types or {
                        name: int(info.get("records", 0)) for name, info in raw_types.items()
                    },
                    "legacy_subset_total": sum(
                        int(info.get("records", 0)) for info in raw_types.values()
                    ),
                    "sources": raw.get("sources", {}),
                },
                "organized": {
                    "total": organized.get("total_records", 0),
                    "normal": organized_labels.get("normal", 0),
                    "attack": organized_labels.get("attack", 0),
                    "attack_types": organized.get("attack_families", 0),
                },
                "modern_attack": {
                    "total": modern.get("total_records", 0),
                    "types": modern.get("attack_type_counts", {}),
                    "splits": modern.get("splits", {}),
                    "cves": modern.get("filter_audit", {}).get("cves", 0),
                    "known_exploited_records": modern.get("known_exploited_records", 0),
                    "sources": modern.get("sources", {}),
                },
                "specialized": {
                    "total": specialized.get("total_records", 0),
                    "groups": specialized.get("counts", {}),
                    "attack_types": specialized.get("attack_type_counts", {}),
                    "scope": specialized.get("payload_model_scope"),
                },
                "lab_captures": {
                    "total": lab_captures.get("total_records", 0),
                    "splits": lab_captures.get("splits", {}),
                    "campaigns": lab_captures.get("campaigns", 0),
                    "attack_types": lab_captures.get("attack_type_counts", {}),
                    "targets": lab_captures.get("capture_targets", []),
                    "scope": lab_captures.get("payload_model_scope"),
                },
                "validation_files": len(list(VALIDATION_DATA_ROOT.glob("*.json"))),
            },
            "obfuscation": {
                "strategy_count": sum(len(items) for items in categories.values()),
                "categories": categories,
            },
            "pipeline": [
                {"id": "parse", "name": "HTTP 解析", "detail": "URL / Body / Headers / Cookie"},
                {"id": "raw", "name": "L1-Raw", "detail": "原文高危结构"},
                {"id": "normalize", "name": "深度归一化", "detail": "多层编码与混淆还原"},
                {"id": "rules", "name": "高置信规则", "detail": "快速确定性拦截"},
                {"id": "models", "name": "双模型融合", "detail": "LightGBM + 字符 n-gram"},
                {"id": "verdict", "name": "检测结论", "detail": "证据、置信度与耗时"},
            ],
        }

    def results(self) -> dict:
        train = self._read_json(MODEL_ROOT / "training_results.json")
        evaluation = self._read_json(MODEL_ROOT / "pipeline_evaluation.json")
        waf_comparison = self._read_json(MODEL_ROOT / "waf_comparison.json")
        waf_cache = self._read_json(
            MODEL_ROOT / "waf_comparison.last_verified.json"
        )
        if (
            waf_cache
            and not waf_comparison.get("systems")
            and not waf_comparison.get("cached_report")
        ):
            waf_comparison["cached_report"] = waf_cache


        # Current validated artifacts use the organized-dataset report schema.
        # Adapt it for the original dashboard without changing the stored report.
        metrics = evaluation.get("metrics", {})
        if metrics and "heldout_family_pipeline" not in evaluation:
            evaluation["heldout_family_pipeline"] = metrics
        if "type_recall" in evaluation and "heldout_attack_by_type" not in evaluation:
            evaluation["heldout_attack_by_type"] = evaluation["type_recall"]
        latency = evaluation.setdefault("latency_ms", {})
        if "p50" in latency:
            latency.setdefault("heldout_p50", latency["p50"])
        if "p99" in latency:
            latency.setdefault("heldout_p99", latency["p99"])

        if "counts" not in train:
            sampling = train.get("sampling", {})
            loaded = train.get("data_audit", {}).get("loaded", {})
            train["counts"] = {
                "train": {
                    "total": int(sampling.get("train_normal", 0))
                    + int(sampling.get("train_attack", 0))
                },
                "validation": {
                    "total": sum(int(value) for value in loaded.get("validation", {}).values())
                },
                "test": {
                    "total": sum(int(value) for value in loaded.get("test", {}).values())
                },
            }

        evaluation["gates"] = evaluation_gates(evaluation)
        evaluation["production_candidate_gates"] = evaluation["gates"]
        evaluation["all_candidate_gates_passed"] = bool(
            evaluation["gates"]
        ) and all(evaluation["gates"].values())

        # WAF comparison metrics retain their own same-record evaluation scope.

        return {
            "training": train,
            "evaluation": evaluation,
            "waf_comparison": waf_comparison,
            "updated_at": datetime.fromtimestamp(
                max(
                    (MODEL_ROOT / "training_results.json").stat().st_mtime if (MODEL_ROOT / "training_results.json").exists() else 0,
                    (MODEL_ROOT / "pipeline_evaluation.json").stat().st_mtime if (MODEL_ROOT / "pipeline_evaluation.json").exists() else 0,
                    (MODEL_ROOT / "waf_comparison.json").stat().st_mtime if (MODEL_ROOT / "waf_comparison.json").exists() else 0,
                ),
                tz=timezone.utc,
            ).isoformat(),
        }

    @staticmethod
    def _tail_jsonl(path: Path, limit: int = 5000) -> list[dict]:
        '''只读取代理日志尾部，避免实时页面反复扫描整个大文件。'''

        if not path.is_file():
            return []
        try:
            with path.open('rb') as handle:
                size = handle.seek(0, os.SEEK_END)
                handle.seek(max(0, size - 4 * 1024 * 1024))
                chunk = handle.read()
            if size > 4 * 1024 * 1024:
                chunk = chunk.split(b'\n', 1)[-1]
            rows = []
            for raw in chunk.splitlines()[-limit:]:
                try:
                    value = json.loads(raw.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(value, dict):
                    rows.append(value)
            return rows
        except OSError:
            return []

    def proxy_activity(self, limit: int = 100) -> dict:
        path = Path(os.environ.get(
            'WAD_PROXY_LOG_FILE', str(RUNTIME_ROOT / 'proxy_access.jsonl')
        ))
        rows = self._tail_jsonl(path)
        by_outcome: dict[str, int] = {}
        by_method: dict[str, int] = {}
        latencies: list[float] = []
        for row in rows:
            outcome = str(row.get('outcome', 'unknown'))
            method = str(row.get('method', 'UNKNOWN'))
            by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
            by_method[method] = by_method.get(method, 0) + 1
            try:
                latencies.append(float(row.get('elapsed_ms', 0)))
            except (TypeError, ValueError):
                pass
        sorted_latency = sorted(latencies)
        p95_index = max(0, round((len(sorted_latency) - 1) * 0.95))
        attacks = sum(int(x.get('threat_count', 0) or 0) > 0 for x in rows)
        latest = rows[-1] if rows else {}
        file_exists = path.is_file()
        result = {
            'status': 'online' if rows else (
                'waiting' if file_exists else 'not_configured'
            ),
            'mode': latest.get(
                'mode', os.environ.get('WAD_PROXY_MODE', 'unknown')
            ),
            'log_file': str(path),
            'last_event_at': latest.get('timestamp'),
            'window_records': len(rows),
            'by_outcome': by_outcome,
            'by_method': by_method,
            'records': list(reversed(rows[-limit:])),
        }
        result['summary'] = {
            'requests': len(rows),
            'attacks': attacks,
            'blocked': by_outcome.get('blocked', 0),
            'backend_errors': by_outcome.get('backend_error', 0),
            'attack_rate': round(attacks / max(len(rows), 1) * 100, 2),
            'avg_latency_ms': round(sum(latencies) / max(len(latencies), 1), 3),
            'p95_latency_ms': (
                round(sorted_latency[p95_index], 3) if sorted_latency else 0
            ),
        }
        return result

    def obfuscate(self, request: ObfuscationRequest) -> dict:
        valid = {name for items in list_strategies().values() for name in items}
        invalid = sorted(set(request.strategies) - valid)
        if invalid:
            raise HTTPException(status_code=422, detail=f"未知混淆策略：{', '.join(invalid)}")
        state = random.getstate()
        try:
            random.seed(request.seed)
            variants = generate(
                request.payload,
                request.strategies,
                request.count,
                request.max_layers,
            )
        finally:
            random.setstate(state)
        detector = self.get_pipeline()
        rows = []
        for variant in variants:
            restored, meta = normalize(variant, param_location=request.param_location)
            result = detector.detect(variant, request.param_location, request.param_name)
            rows.append({
                "variant": variant,
                "normalized": restored,
                "decode_depth": meta.decode_depth,
                "verdict": result.verdict,
                "confidence": round(result.confidence, 6),
                "layer": result.layer,
                "elapsed_ms": round(result.elapsed_ms, 4),
                "rule_hits": result.rule_hits,
            })
        return {"input": request.payload, "count": len(rows), "variants": rows}

    @staticmethod
    def _python() -> str:
        override = os.environ.get("WAD_PYTHON")
        if override:
            return override
        # Windows Python Manager 可能让 sys.executable 指向不可直接启动的
        # pythoncore，并让 PATH 命中 WindowsApps 登录会话代理。优先使用同一
        # 安装根目录下可重新启动的 bin/python.exe 包装器。
        managed_wrapper = Path(sys.executable).parent.parent / "bin" / "python.exe"
        if managed_wrapper.is_file():
            return str(managed_wrapper)
        candidate = shutil.which("python")
        if (
            candidate
            and "WindowsApps" not in candidate
            and Path(candidate).resolve() != Path(sys.executable).resolve()
        ):
            return candidate
        return sys.executable

    @staticmethod
    def _command(request: JobRequest) -> list[str]:
        command = [DashboardService._python(), str(PROJECT_ROOT / "run.py"), request.action]
        if request.action in {"train", "all"}:
            command.extend([
                "--min-recall", str(request.min_recall),
                "--max-text-features", str(request.max_text_features),
            ])
        if request.action == "validate-data":
            command.append("--deep")
        return command

    @staticmethod
    def _progress(action: str, line: str, current: int) -> tuple[int, str]:
        if "训练最终融合模型" in line:
            return max(current, 8 if action == "all" else 3), "加载数据并训练模型"
        if '"counts"' in line and action in {"train", "all"}:
            return max(current, 62 if action == "all" else 92), "模型训练完成"
        if "单元测试与集成测试" in line:
            return max(current, 68 if action == "all" else 3), "运行自动化测试"
        if "passed" in line:
            return max(current, 78 if action == "all" else 96), "自动化测试通过"
        if "独立测试集" in line or "独立 organized 测试集" in line:
            return max(current, 82 if action == "all" else 3), "运行独立验证与性能评测"
        if "真实 ModSecurity + OWASP CRS 产品对比" in line:
            return max(current, 90 if action == "all" else 3), "对比最终模型与真实 WAF 产品"
        if "全部阶段通过" in line:
            return 99, "整理最终报告"
        if '"status": "PASS"' in line and action == "validate-data":
            return max(current, 96), "数据审计通过"
        return current, "任务运行中"

    @staticmethod
    def _decode_output(raw: bytes) -> str:
        """优先按 UTF-8 解码，并兼容仍使用 Windows 中文代码页的原生程序。"""
        for encoding in ("utf-8-sig", "gb18030"):
            try:
                return raw.decode(encoding).rstrip("\r\n")
            except UnicodeDecodeError:
                continue
        return raw.decode("utf-8", errors="replace").rstrip("\r\n")

    @staticmethod
    def _event_progress(action: str, scope: str, fraction: float) -> int:
        """将子任务局部进度映射到当前任务的整体进度。"""
        fraction = max(0.0, min(float(fraction), 1.0))
        if action == "all":
            ranges = {
                "train": (5, 60),
                "test": (62, 76),
                "evaluate": (78, 90),
                "compare-waf": (91, 99),
            }
            start, end = ranges.get(scope, (5, 99))
            return round(start + fraction * (end - start))
        return round(2 + fraction * 96)

    def _record_event(self, stage: str, detail: str, progress: int) -> None:
        """记录阶段变化，供前端绘制实时任务时间线。"""
        self.job["stage"] = stage
        self.job["detail"] = detail
        self.job["progress"] = max(int(self.job.get("progress", 0)), int(progress))
        events = self.job.setdefault("events", [])
        if not events or events[-1].get("stage") != stage:
            events.append({
                "stage": stage,
                "detail": detail,
                "progress": self.job["progress"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            self.job["events"] = events[-30:]
        else:
            events[-1].update({
                "detail": detail,
                "progress": self.job["progress"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def start_job(self, request: JobRequest) -> dict:
        with self.job_lock:
            if self.job.get("status") in {"queued", "running"}:
                raise HTTPException(status_code=409, detail="已有任务正在运行")
            job_id = f"{int(time.time())}-{request.action}"
            self.job = {
                "id": job_id,
                "action": request.action,
                "status": "queued",
                "stage": "准备环境",
                "progress": 1,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "exit_code": None,
                "logs": [],
                "detail": "正在创建隔离的后台子进程",
                "events": [{
                    "stage": "准备环境",
                    "detail": "正在创建隔离的后台子进程",
                    "progress": 1,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }],
                "command": self._command(request),
            }
        threading.Thread(target=self._run_job, args=(request,), daemon=True).start()
        return self.public_job()

    def _run_job(self, request: JobRequest) -> None:
        with self.job_lock:
            self.job["status"] = "running"
            self._record_event("启动任务", "UTF-8 输出通道已建立，正在执行统一命令", 2)
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["PYTHONUTF8"] = "1"
        environment["WAD_STRUCTURED_PROGRESS"] = "1"
        try:
            process = subprocess.Popen(
                self._command(request),
                cwd=PROJECT_ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,
                bufsize=0,
            )
            assert process.stdout is not None
            for raw_line in iter(process.stdout.readline, b""):
                line = self._decode_output(raw_line)
                with self.job_lock:
                    if line.startswith("@@WAD_PROGRESS "):
                        try:
                            event = json.loads(line.removeprefix("@@WAD_PROGRESS "))
                            self._record_event(
                                str(event.get("stage", "训练进行中")),
                                str(event.get("detail", "正在处理训练任务")),
                                self._event_progress(
                                    request.action,
                                    str(event.get("scope", request.action)),
                                    float(event.get("fraction", 0)),
                                ),
                            )
                        except (ValueError, TypeError, json.JSONDecodeError):
                            self.job["logs"].append(line)
                        continue
                    self.job["logs"].append(line)
                    self.job["logs"] = self.job["logs"][-800:]
                    progress, stage = self._progress(
                        request.action, line, int(self.job.get("progress", 1))
                    )
                    if progress > int(self.job.get("progress", 1)) or stage != "任务运行中":
                        self._record_event(stage, line or "后台任务正在运行", progress)
            exit_code = process.wait()
            if exit_code == 0 and request.action in {"train", "all"}:
                self.select_model("final-model")
            with self.job_lock:
                self.job["exit_code"] = exit_code
                self.job["status"] = "completed" if exit_code == 0 else "failed"
                self._record_event(
                    "全部完成" if exit_code == 0 else "任务失败",
                    "所有阶段均已通过" if exit_code == 0 else "请查看下方日志定位失败原因",
                    100,
                )
                self.job["finished_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as exc:
            with self.job_lock:
                self.job["logs"].append(f"Dashboard job error: {exc}")
                self.job["status"] = "failed"
                self._record_event("任务异常", str(exc), 100)
                self.job["exit_code"] = -1
                self.job["finished_at"] = datetime.now(timezone.utc).isoformat()

    def public_job(self) -> dict:
        with self.job_lock:
            return {
                key: (list(value) if isinstance(value, list) else value)
                for key, value in self.job.items()
            }

    def sample_records(self, kind: str, attack_type: str | None, limit: int) -> dict:
        paths: list[Path]
        if kind == "obfuscated_attack":
            if not attack_type:
                attack_type = "sqli"
            paths = sorted(
                (ORGANIZED_DATA_ROOT / "attack" / "obfuscated" / attack_type).glob("*/*.jsonl")
            )
        elif kind == "raw_attack":
            if not attack_type:
                attack_type = "sqli"
            paths = sorted(
                (ORGANIZED_DATA_ROOT / "attack" / "original" / attack_type).glob("*/*.jsonl")
            )
        elif kind == "modern_attack":
            paths = sorted(MODERN_ATTACK_DATA_ROOT.glob("dataset_modern_attack_*.json"))
        elif kind == "normal":
            paths = sorted((ORGANIZED_DATA_ROOT / "normal" / "field").glob("*.jsonl"))
        else:
            raise HTTPException(status_code=422, detail="未知数据集类型")
        if not paths or any(not path.is_file() for path in paths):
            raise HTTPException(status_code=404, detail="样本文件不存在")
        records = []
        for path in paths:
            try:
                if path.suffix == ".jsonl":
                    with path.open(encoding="utf-8") as handle:
                        values = (json.loads(line) for line in handle if line.strip())
                        for item in values:
                            if not isinstance(item, dict):
                                continue
                            records.append(self._sample_record(item))
                            if len(records) >= limit:
                                break
                else:
                    values = json.loads(path.read_text(encoding="utf-8"))
                    if not isinstance(values, list):
                        raise HTTPException(status_code=500, detail="样本文件不是 JSON 数组")
                    for item in values:
                        if not isinstance(item, dict):
                            continue
                        if (
                            kind == "modern_attack"
                            and attack_type
                            and item.get("attack_type") != attack_type
                        ):
                            continue
                        records.append(self._sample_record(item))
                        if len(records) >= limit:
                            break
            except (OSError, json.JSONDecodeError) as exc:
                raise HTTPException(status_code=500, detail=f"样本文件读取失败：{exc}") from exc
            if len(records) >= limit:
                break
        return {"kind": kind, "attack_type": attack_type, "records": records}

    @staticmethod
    def _sample_record(item: dict) -> dict:
        return {
            "id": item.get("id"),
            "payload": item.get(
                "obfuscated_payload",
                item.get("payload", item.get("raw_request", item.get("decoded_payload", ""))),
            ),
            "original": item.get("original_payload"),
            "attack_type": item.get("attack_type", "normal"),
            "profile": item.get("obfuscation_profile", item.get("attack_subtype")),
            "location": item.get("param_location"),
        }


def create_dashboard_router(
    get_pipeline: Callable[[], DetectionPipeline],
    replace_pipeline: Callable[[DetectionPipeline], None],
    initial_model_id: str = "final-model",
) -> APIRouter:
    service = DashboardService(get_pipeline, replace_pipeline, initial_model_id)
    router = APIRouter(prefix="/dashboard", tags=["可视化控制台"])

    @router.get("/overview")
    def overview():
        return service.overview()

    @router.get("/models")
    def models():
        return {"models": service.model_registry(), "active_model_id": service.active_model_id}

    @router.post("/models/select")
    def select_model(request: ModelSelection):
        return service.select_model(request.model_id)

    @router.get("/results")
    def results():
        return service.results()

    @router.post("/obfuscate")
    def obfuscate(request: ObfuscationRequest):
        return service.obfuscate(request)

    @router.post("/jobs")
    def start_job(request: JobRequest):
        return service.start_job(request)

    @router.get("/jobs/current")
    def current_job():
        return service.public_job()

    @router.get("/samples")
    def samples(
        kind: str = Query(default="obfuscated_attack"),
        attack_type: str | None = Query(default=None),
        limit: int = Query(default=6, ge=1, le=20),
    ):
        return service.sample_records(kind, attack_type, limit)

    @router.get('/proxy/activity')
    def proxy_activity(limit: int = Query(default=100, ge=10, le=500)):
        return service.proxy_activity(limit)

    return router
