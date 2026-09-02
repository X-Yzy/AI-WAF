#!/usr/bin/env python3
"""Compare the final detector with a real ModSecurity + OWASP CRS product."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.pipeline import DetectionPipeline  # noqa: E402
from training import train_organized_full as core  # noqa: E402
from training.real_waf import (  # noqa: E402
    DEFAULT_IMAGE,
    PRODUCT_KEY,
    ResilientModSecurityCRSProduct,
    payload_of,
)
def emit_progress(fraction: float, stage: str, detail: str) -> None:
    if os.environ.get("WAD_STRUCTURED_PROGRESS") != "1":
        return
    event = {
        "scope": "compare-waf",
        "fraction": max(0.0, min(float(fraction), 1.0)),
        "stage": stage,
        "detail": detail,
    }
    print("@@WAD_PROGRESS " + json.dumps(event, ensure_ascii=False), flush=True)


def latency_summary(values: list[float]) -> dict:
    array = np.asarray(values, dtype=np.float64)
    return {
        "mean_ms": round(float(array.mean()), 6),
        "p50_ms": round(float(np.percentile(array, 50)), 6),
        "p95_ms": round(float(np.percentile(array, 95)), 6),
        "p99_ms": round(float(np.percentile(array, 99)), 6),
    }


def classification_metrics(labels: list[int], predictions: list[int]) -> dict:
    actual = np.asarray(labels, dtype=np.int8)
    predicted = np.asarray(predictions, dtype=np.int8)
    tn = int(np.sum((actual == 0) & (predicted == 0)))
    fp = int(np.sum((actual == 0) & (predicted == 1)))
    fn = int(np.sum((actual == 1) & (predicted == 0)))
    tp = int(np.sum((actual == 1) & (predicted == 1)))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(
            2 * precision * recall / max(precision + recall, 1e-15), 6
        ),
        "fpr": round(fp / max(fp + tn, 1), 6),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def recall_for_indices(predictions: list[int], indices: list[int]) -> dict:
    detected = sum(predictions[index] for index in indices)
    return {
        "records": len(indices),
        "detected": int(detected),
        "recall": round(detected / max(len(indices), 1), 6),
    }


def portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checkpoint(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(state, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model-dir", type=Path, default=ROOT / "models" / "current"
    )
    parser.add_argument("--data-root", type=Path, default=ROOT / "data" / "organized")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "models" / "current" / "waf_comparison.json",
    )
    parser.add_argument(
        "--waf-image",
        default=DEFAULT_IMAGE,
        help="fixed official ModSecurity + CRS image",
    )
    parser.add_argument(
        "--pull",
        choices=("missing", "always", "never"),
        default="missing",
        help="official image pull policy",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="development smoke-test limit; zero evaluates the complete split",
    )
    parser.add_argument(
        "--request-timeout",
        type=float,
        default=30.0,
        help="per-request product timeout; timeout fails the experiment",
    )
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="ignore a matching full-run checkpoint",
    )
    args = parser.parse_args()

    emit_progress(0.02, "加载独立测试集", "读取 organized 字段级测试记录")
    data_root = core.resolve_data_root(args.data_root)
    datasets, audit = core.load_organized_fields(
        data_root, include_unspecified_in_train=True
    )
    records = list(datasets["test"])
    if args.limit:
        if args.limit < 2:
            raise SystemExit("--limit must be at least 2")
        records = records[: args.limit]
    labels = [int(record.get("label", 0)) for record in records]
    attack_count = sum(labels)
    normal_count = len(labels) - attack_count
    if not attack_count or not normal_count:
        raise SystemExit("comparison scope must contain normal and attack records")

    signature = {
        "schema": "real-waf-checkpoint-v1",
        "image": args.waf_image,
        "records": len(records),
        "data_manifest_sha256": sha256_file(data_root / "manifest.json"),
        "lgbm_sha256": sha256_file(args.model_dir / "lgbm_v4.pkl"),
        "text_model_sha256": sha256_file(args.model_dir / "text_lr_v4.pkl"),
    }
    checkpoint_path = args.checkpoint
    if checkpoint_path is None and args.limit == 0:
        checkpoint_path = ROOT / "runtime" / "real_waf_comparison.checkpoint.json"

    detector = DetectionPipeline()
    detector.load_lgbm(str(args.model_dir / "lgbm_v4.pkl"))
    detector.load_text_model(str(args.model_dir / "text_lr_v4.pkl"))
    for record in records[:20]:
        detector.detect(
            payload_of(record),
            str(record.get("param_location", "query")),
            str(record.get("param_name", "value")),
        )

    system_order = ["final_model", PRODUCT_KEY]
    predictions = {key: [] for key in system_order}
    latencies = {key: [] for key in system_order}
    processed = 0
    restored_execution: dict = {}
    if checkpoint_path and checkpoint_path.is_file() and not args.no_resume:
        candidate = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if candidate.get("signature") == signature:
            processed = int(candidate.get("processed", 0))
            if not 0 <= processed <= len(records):
                raise SystemExit("invalid real-WAF checkpoint processed count")
            saved_predictions = candidate.get("predictions", {})
            saved_latencies = candidate.get("latencies", {})
            for key in system_order:
                predictions[key] = [int(value) for value in saved_predictions.get(key, [])]
                latencies[key] = [float(value) for value in saved_latencies.get(key, [])]
                if len(predictions[key]) != processed or len(latencies[key]) != processed:
                    raise SystemExit("invalid real-WAF checkpoint vector lengths")
            restored_execution = dict(candidate.get("product_execution", {}))
            emit_progress(
                0.10 + 0.82 * processed / len(records),
                "恢复真实 WAF 检查点",
                f"模型、数据和镜像签名一致，从 {processed:,} 条继续",
            )

    emit_progress(
        0.06,
        "启动真实 WAF 产品",
        f"启动官方镜像 {args.waf_image}，阻断模式 PL1 / 入站阈值 5",
    )
    product_manager = ResilientModSecurityCRSProduct(
        image=args.waf_image,
        pull=args.pull,
        request_timeout=args.request_timeout,
    )
    if restored_execution:
        product_manager.restore_execution_state(restored_execution)
    with product_manager as product:
        emit_progress(
            0.10,
            "真实产品冒烟测试通过",
            "正常请求到达后端，SQL 注入请求由 ModSecurity + CRS 阻断",
        )
        for index, record in enumerate(records[processed:], processed + 1):
            value = payload_of(record)
            location = str(record.get("param_location", "query"))
            name = str(record.get("param_name", "value"))

            started = time.perf_counter()
            result = detector.detect(value, location, name)
            latencies["final_model"].append(
                (time.perf_counter() - started) * 1000
            )
            predictions["final_model"].append(int(result.verdict == "attack"))

            try:
                product_result = product.inspect(record)
            except Exception as exc:
                raise RuntimeError(
                    "Real WAF failed at "
                    f"record={index}/{len(records)}, id={record.get('id')}, "
                    f"label={record.get('label')}, type={record.get('attack_type')}, "
                    f"location={record.get('param_location')}, bytes={len(value.encode('utf-8'))}"
                ) from exc
            latencies[PRODUCT_KEY].append(product_result.elapsed_ms)
            predictions[PRODUCT_KEY].append(int(product_result.blocked))

            if index % 1000 == 0 or index == len(records):
                emit_progress(
                    0.10 + 0.82 * index / len(records),
                    "逐条真实 HTTP 公平评测",
                    f"已完成 {index:,} / {len(records):,} 条",
                )
                if checkpoint_path:
                    execution = product.execution_summary()
                    execution["identity"] = product.identity()
                    write_checkpoint(
                        checkpoint_path,
                        {
                            "signature": signature,
                            "processed": index,
                            "predictions": predictions,
                            "latencies": latencies,
                            "product_execution": execution,
                        },
                    )

        product_identity = product.identity()
        product_execution = product.execution_summary()

    type_indices: dict[str, list[int]] = defaultdict(list)
    representation_indices: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        if labels[index] != 1:
            continue
        attack_type = str(record.get("attack_type", "unknown"))
        representation = str(
            (record.get("_organized") or {}).get(
                "attack_representation", "unknown"
            )
        )
        type_indices[attack_type].append(index)
        representation_indices[representation].append(index)

    systems = {
        key: {
            **classification_metrics(labels, predictions[key]),
            "latency": latency_summary(latencies[key]),
        }
        for key in system_order
    }
    systems["final_model"].update(
        {
            "display_name": "最终 AI-WAF",
            "kind": "live_model",
            "execution": "in-process field detector",
            "latency_scope": "in-process inference",
        }
    )
    systems[PRODUCT_KEY].update(
        {
            "display_name": product_identity["name"],
            "kind": "real_waf_product",
            "execution": product_identity["implementation"],
            "latency_scope": "loopback HTTP + Nginx + ModSecurity + backend proof",
        }
    )

    full_split = args.limit == 0
    report = {
        "schema": "final_model_vs_real_waf_product_v3",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_definition": (
            "对照组为实际运行的官方 ModSecurity 3.0.16 + OWASP CRS 4.28.0 "
            "Docker 产品，不是关键词模拟器。每条记录构造成真实 HTTP 请求；"
            "请求未到达带随机令牌的临时后端即记为产品阻断。配置采用阻断模式、"
            "Paranoia Level 1、入站异常阈值 5。效果指标使用同一记录与标签；"
            "延迟列需按各自 latency_scope 解读。"
        ),
        "baseline_identity": product_identity,
        "product_execution": product_execution,
        "fairness": {
            "same_records": True,
            "same_labels": True,
            "same_order": True,
            "complete_independent_test_split": full_split,
            "known_duplicate_excluded": True,
            "product_uses_real_http": True,
            "product_is_simulated": False,
            "effectiveness_comparable": True,
            "latency_directly_comparable": False,
            "latency_note": (
                "AI-WAF 为进程内字段推理；真实 WAF 包含本机 HTTP、Nginx、"
                "ModSecurity 和后端到达证明，因此延迟仅展示各自运行开销，"
                "不据此宣称纯引擎性能优劣。"
            ),
        },
        "dataset": {
            "source": portable_path(data_root),
            "split": "test",
            "eligible_only": True,
            "known_duplicate_excluded": True,
            "attack": attack_count,
            "normal": normal_count,
            "total": len(records),
            "audit": audit,
        },
        "system_order": system_order,
        "systems": systems,
        "attack_form_recall": {
            representation: {
                key: recall_for_indices(
                    predictions[key], representation_indices[representation]
                )
                for key in system_order
            }
            for representation in sorted(representation_indices)
        },
        "attack_type_recall": {
            attack_type: {
                key: recall_for_indices(predictions[key], type_indices[attack_type])
                for key in system_order
            }
            for attack_type in sorted(type_indices)
        },
    }
    report["dataset"]["audit"]["data_root"] = "data/organized"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if checkpoint_path:
        checkpoint_path.unlink(missing_ok=True)
    emit_progress(1.0, "真实 WAF 对比完成", f"报告已写入 {args.output}")
    print(
        json.dumps(
            {
                "output": portable_path(args.output),
                "records": len(records),
                "systems": systems,
                "real_product": product_identity,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
