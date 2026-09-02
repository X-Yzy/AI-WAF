#!/usr/bin/env python3
"""Run the six ablation variants on the retained 95% direct-route test set."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

import numpy as np


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))

from experiments.ablation import run_ablation_study as ablation  # noqa: E402
from routing_support import build_operational_test_set, safe_normal_rule  # noqa: E402
from training import train_organized_full as core  # noqa: E402
from training.search_sampling_strategy import metadata_arrays, operating_point  # noqa: E402


MODEL_DIR = ROOT / "models" / "current"
DATA_ROOT = ROOT / "data" / "organized"
OUTPUT = HERE / "results" / "direct_95_six_way_ablation.json"
MARKDOWN = ROOT / "docs" / "experiments" / "DIRECT_95_SIX_WAY_ABLATION.md"
TARGET_RECORDS = 9_500
NORMAL_SHARE = 8_500 / TARGET_RECORDS
SEED = 20_260_801
DIRECT_SHARES = (0.95,)
PERCENTILES = ("p80", "p85", "p90", "p95", "p99")


def validation_thresholds(records: list[dict], feature_model, text_model) -> dict:
    labels, attack_types, representations = metadata_arrays(records)
    feature, text = ablation.validation_probabilities(
        records, feature_model, text_model
    )
    return {
        "lightgbm": ablation.single_model_point(
            labels,
            feature,
            attack_types,
            representations,
            min_recall=0.95,
            max_fpr=0.001,
        ),
        "character": ablation.single_model_point(
            labels,
            text,
            attack_types,
            representations,
            min_recall=0.95,
            max_fpr=0.001,
        ),
        "fusion": operating_point(
            labels,
            feature,
            text,
            attack_types,
            representations,
            min_recall=0.95,
            max_fpr=0.001,
        ),
    }


def compact_variants(variants: dict) -> dict:
    return {
        key: {
            metric: value[metric]
            for metric in (
                "precision",
                "recall",
                "f1",
                "fpr",
                "obfuscated_attack_recall",
                "confusion_matrix",
                "latency_ms",
            )
        }
        for key, value in variants.items()
    }


def render_markdown(report: dict) -> str:
    lines = [
        "# 95% 前置直出测试集六组组件消融实验",
        "",
        "| 测试场景 | 方案 | 精确率 | 召回率 | F1 综合指标 | 误报率 | 混淆攻击召回率 | P80/ms | P85/ms | P90/ms | P95/ms | P99/ms |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for scenario in report["scenarios"]:
        first = True
        for key, label in ablation.VARIANT_LABELS.items():
            timing = scenario["variants"][key]["latency_ms"]
            lines.append(
                "| {} | {} | {:.4%} | {:.4%} | {:.4%} | {:.4%} | {:.4%} | {:.4f} | {:.4f} | {:.4f} | {:.4f} | {:.4f} |".format(
                    scenario["label"] if first else "",
                    label,
                    scenario["variants"][key]["precision"],
                    scenario["variants"][key]["recall"],
                    scenario["variants"][key]["f1"],
                    scenario["variants"][key]["fpr"],
                    scenario["variants"][key]["obfuscated_attack_recall"],
                    *(timing[name] for name in PERCENTILES),
                )
            )
            first = False
    lines.extend(
        [
            "",
            "该测试集共 9,500 条，包含 8,500 条正常记录和 1,000 条攻击记录，使用固定种子无放回抽样；前置直出 9,025 条（95%），双模型 475 条（5%）。训练、验证、模型、阈值和融合参数保持不变。",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    data, audit = core.load_organized_fields(
        core.resolve_data_root(DATA_ROOT), include_unspecified_in_train=True
    )
    feature_model = ablation.load_pickle(MODEL_DIR / "lgbm_v4.pkl")
    text_model = ablation.load_pickle(MODEL_DIR / "text_lr_v4.pkl")
    thresholds = validation_thresholds(
        data["validation"], feature_model, text_model
    )
    source = data["test"]

    started = time.perf_counter()
    source_routes: list[str] = []
    _, _ = ablation.evaluate_test_records(
        source,
        feature_model,
        text_model,
        thresholds,
        safe_normal_rule_fn=safe_normal_rule,
        route_output=source_routes,
    )
    scenarios = []
    source_route_by_object = {
        id(record): route for record, route in zip(source, source_routes)
    }

    for direct_share in DIRECT_SHARES:
        selected, selection = build_operational_test_set(
            source,
            source_routes,
            target_records=TARGET_RECORDS,
            normal_share=NORMAL_SHARE,
            model_share=1.0 - direct_share,
            seed=SEED,
        )
        selected_routes = [source_route_by_object[id(record)] for record in selected]
        variants, _ = ablation.evaluate_test_records(
            selected,
            feature_model,
            text_model,
            thresholds,
            complete_routes=selected_routes,
            safe_normal_rule_fn=safe_normal_rule,
        )
        direct_records = sum(
            route != "lightgbm_and_character_model"
            for route in selected_routes
        )
        actual_direct = direct_records / len(selected)
        if abs(actual_direct - direct_share) > 1e-9:
            raise RuntimeError("direct-route allocation mismatch")
        scenarios.append(
            {
                "label": f"前置直接完成 {direct_share:.0%}",
                "records": len(selected),
                "normal_records": sum(
                    int(item.get("label", 0)) == 0 for item in selected
                ),
                "attack_records": sum(
                    int(item.get("label", 0)) == 1 for item in selected
                ),
                "direct_records": direct_records,
                "model_records": len(selected) - direct_records,
                "direct_share": round(actual_direct, 6),
                "model_share": round(1.0 - actual_direct, 6),
                "selection": selection,
                "variants": compact_variants(variants),
            }
        )

    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "six-way ablation on retained 95% direct-route test set",
        "unchanged": (
            "training data, validation data, model artifacts, threshold-selection "
            "method, fusion weights and fusion threshold"
        ),
        "dataset_audit": audit,
        "selection": thresholds,
        "timing": {
            "unit": "milliseconds per field payload",
            "percentiles": [80, 85, 90, 95, 99],
            "experiment_wall_seconds": round(time.perf_counter() - started, 3),
        },
        "scenarios": scenarios,
    }
    for scenario in scenarios:
        for name, variant in scenario["variants"].items():
            values = [variant["latency_ms"][key] for key in PERCENTILES]
            if values != sorted(values) or values[0] <= 0:
                raise RuntimeError(
                    f"invalid latency percentiles: {scenario['label']}.{name}"
                )

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    MARKDOWN.write_text(render_markdown(report), encoding="utf-8")
    print(
        json.dumps(
            {
                "status": "PASS",
                "scenarios": [item["label"] for item in scenarios],
                "output": str(OUTPUT),
                "markdown": str(MARKDOWN),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
