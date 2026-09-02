#!/usr/bin/env python3
"""Evaluate a candidate through the real cascade on the organized test split."""

from __future__ import annotations

import argparse
from collections import Counter
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
EXTERNAL_SOURCE_PREFIXES = (
    "external_traffic/",
    "external_deserialization/",
    "modern_attack_traffic",
)


def payload(record: dict) -> str:
    return str(record.get("obfuscated_payload") or record.get("payload") or "")


def source_dataset(record: dict) -> str:
    organized = record.get("_organized") or {}
    return str(
        organized.get("source_dataset")
        or record.get("source_dataset")
        or "unknown"
    )


def is_external_source(name: str) -> bool:
    return any(
        name == prefix or name.startswith(prefix)
        for prefix in EXTERNAL_SOURCE_PREFIXES
    )


def portable_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def emit_progress(fraction: float, stage: str, detail: str) -> None:
    if os.environ.get("WAD_STRUCTURED_PROGRESS") != "1":
        return
    print(
        "@@WAD_PROGRESS "
        + json.dumps(
            {
                "scope": "evaluate",
                "fraction": max(0.0, min(float(fraction), 1.0)),
                "stage": stage,
                "detail": detail,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )


def aggregate_recall(
    source_names: list[str],
    totals: Counter[str],
    hits: Counter[str],
) -> dict:
    records = sum(totals[name] for name in source_names)
    detected = sum(hits[name] for name in source_names)
    return {
        "records": int(records),
        "detected": int(detected),
        "recall": round(detected / max(records, 1), 6),
        "sources": source_names,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    emit_progress(0.02, "加载独立测试集", "读取 organized 字段级测试记录")
    data_root = core.resolve_data_root(args.data_root)
    datasets, audit = core.load_organized_fields(
        data_root, include_unspecified_in_train=True
    )
    records = datasets["test"]
    audit = dict(audit)
    audit["data_root"] = portable_path(data_root)

    detector = DetectionPipeline()
    detector.load_lgbm(str(args.model_dir / "lgbm_v4.pkl"))
    detector.load_text_model(str(args.model_dir / "text_lr_v4.pkl"))

    predictions: list[int] = []
    latencies: list[float] = []
    layers: Counter[str] = Counter()
    rule_false_positives: Counter[str] = Counter()
    false_positive_examples: list[dict] = []
    false_negative_examples: list[dict] = []
    type_totals: Counter[str] = Counter()
    type_hits: Counter[str] = Counter()
    representation_totals: Counter[str] = Counter()
    representation_hits: Counter[str] = Counter()
    source_totals: Counter[str] = Counter()
    source_hits: Counter[str] = Counter()

    emit_progress(
        0.07,
        "执行完整检测链路",
        f"对 {len(records):,} 条独立测试记录运行规则、上下文与双模型融合",
    )
    wall_start = time.perf_counter()
    for index, record in enumerate(records, 1):
        result = detector.detect(
            payload(record),
            str(record.get("param_location", "query")),
            str(record.get("param_name", "value")),
        )
        predicted = int(result.verdict == "attack")
        actual = int(record.get("label", 0))
        predictions.append(predicted)
        latencies.append(float(result.elapsed_ms))
        layers[result.layer] += 1

        if actual == 1:
            attack_type = str(record.get("attack_type", "unknown"))
            representation = str(
                (record.get("_organized") or {}).get(
                    "attack_representation", "unknown"
                )
            )
            source = source_dataset(record)
            type_totals[attack_type] += 1
            representation_totals[representation] += 1
            source_totals[source] += 1
            if predicted:
                type_hits[attack_type] += 1
                representation_hits[representation] += 1
                source_hits[source] += 1
            elif len(false_negative_examples) < 30:
                false_negative_examples.append(
                    {
                        "id": record.get("id"),
                        "type": attack_type,
                        "representation": representation,
                        "source_dataset": source,
                        "payload": payload(record)[:240],
                        "layer": result.layer,
                        "l2_score": result.l2_score,
                        "text_score": result.l3_score,
                    }
                )
        elif predicted:
            for rule in result.rule_hits:
                rule_false_positives[rule] += 1
            if len(false_positive_examples) < 30:
                false_positive_examples.append(
                    {
                        "id": record.get("id"),
                        "subtype": record.get("attack_subtype"),
                        "source_dataset": source_dataset(record),
                        "payload": payload(record)[:240],
                        "layer": result.layer,
                        "rules": result.rule_hits,
                        "l2_score": result.l2_score,
                        "text_score": result.l3_score,
                    }
                )

        if index % 5000 == 0:
            emit_progress(
                0.07 + 0.84 * index / len(records),
                "执行完整检测链路",
                f"已完成 {index:,} / {len(records):,} 条",
            )

    wall_seconds = time.perf_counter() - wall_start
    actual = np.asarray(
        [int(record.get("label", 0)) for record in records], dtype=np.int8
    )
    predicted = np.asarray(predictions, dtype=np.int8)
    tn = int(np.sum((actual == 0) & (predicted == 0)))
    fp = int(np.sum((actual == 0) & (predicted == 1)))
    fn = int(np.sum((actual == 1) & (predicted == 0)))
    tp = int(np.sum((actual == 1) & (predicted == 1)))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-15)
    values = np.asarray(latencies, dtype=np.float64)

    source_recall = {
        source: {
            "records": int(source_totals[source]),
            "detected": int(source_hits[source]),
            "recall": round(source_hits[source] / source_totals[source], 6),
        }
        for source in sorted(source_totals)
    }
    external_names = sorted(
        source for source in source_totals if is_external_source(source)
    )
    fuzzdb_compatible_names = sorted(
        source
        for source in source_totals
        if source.startswith("external_traffic/")
    )
    external_sources = aggregate_recall(
        external_names, source_totals, source_hits
    )
    external_sources["definition"] = (
        "organized 独立测试集中 source_dataset 属于 external_traffic、"
        "external_deserialization 或 modern_attack_traffic 的合格攻击记录"
    )

    report = {
        "model_dir": portable_path(args.model_dir),
        "data_root": portable_path(data_root),
        "dataset_audit": audit,
        "records": len(records),
        "metrics": {
            "f1": round(f1, 6),
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "fpr": round(fp / max(fp + tn, 1), 6),
            "confusion_matrix": [[tn, fp], [fn, tp]],
        },
        "type_recall": {
            attack_type: {
                "records": int(type_totals[attack_type]),
                "detected": int(type_hits[attack_type]),
                "recall": round(
                    type_hits[attack_type] / type_totals[attack_type], 6
                ),
            }
            for attack_type in sorted(type_totals)
        },
        "representation_recall": {
            representation: {
                "records": int(representation_totals[representation]),
                "detected": int(representation_hits[representation]),
                "recall": round(
                    representation_hits[representation]
                    / representation_totals[representation],
                    6,
                ),
            }
            for representation in sorted(representation_totals)
        },
        "source_recall": source_recall,
        "external_sources": external_sources,
        # Backward-compatible field for the original dashboard/report reader.
        "external_fuzzdb": aggregate_recall(
            fuzzdb_compatible_names, source_totals, source_hits
        ),
        "latency_ms": {
            "mean": round(float(values.mean()), 6),
            "p50": round(float(np.percentile(values, 50)), 6),
            "p95": round(float(np.percentile(values, 95)), 6),
            "p99": round(float(np.percentile(values, 99)), 6),
            "max": round(float(values.max()), 6),
            "wall_seconds": round(wall_seconds, 3),
            "throughput_records_per_second": round(
                len(records) / wall_seconds, 3
            ),
        },
        "layers": dict(layers.most_common()),
        "rule_false_positives": dict(rule_false_positives.most_common()),
        "false_positive_examples": false_positive_examples,
        "false_negative_examples": false_negative_examples,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    emit_progress(1.0, "独立评测完成", f"报告已写入 {portable_path(args.output)}")
    print(
        json.dumps(
            {
                "message": "pipeline_evaluation_completed",
                "output": portable_path(args.output),
                "records": len(records),
                "metrics": report["metrics"],
                "external_sources": external_sources,
                "latency_ms": report["latency_ms"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
