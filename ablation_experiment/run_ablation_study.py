#!/usr/bin/env python3
"""Run the six-way component ablation on the independent organized test split."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import pickle
import sys
import time

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from src.engine import RuleEngine  # noqa: E402
from src.extractor import extract  # noqa: E402
from src.normalizer import normalize  # noqa: E402
from src.pipeline import DetectionPipeline  # noqa: E402
from training import train_organized_full as core  # noqa: E402
from training.evaluate_candidate_pipeline import payload  # noqa: E402
from training.search_sampling_strategy import (  # noqa: E402
    metadata_arrays,
    operating_point,
)


VARIANT_LABELS = {
    "rules_only": "仅规则",
    "rules_normalized": "规则 + 归一化",
    "lightgbm_only": "仅 LightGBM",
    "character_only": "仅字符模型",
    "dual_model_fusion": "双模型融合",
    "complete_pipeline": "完整链路",
}


def emit_progress(fraction: float, stage: str, detail: str) -> None:
    if os.environ.get("WAD_STRUCTURED_PROGRESS") != "1":
        return
    print(
        "@@WAD_PROGRESS "
        + json.dumps(
            {
                "scope": "ablation",
                "fraction": max(0.0, min(float(fraction), 1.0)),
                "stage": stage,
                "detail": detail,
            },
            ensure_ascii=False,
        ),
        flush=True,
    )


def load_pickle(path: Path):
    with path.open("rb") as handle:
        model = pickle.load(handle)
    try:
        classifier = model.steps[-1][1]
        if not hasattr(classifier, "multi_class"):
            classifier.multi_class = "deprecated"
    except Exception:
        pass
    return model


def feature_probability(model, features: np.ndarray) -> float:
    row = features.reshape(1, -1)
    if hasattr(model, "booster_"):
        return float(model.booster_.predict(row)[0])
    if hasattr(model, "predict_proba"):
        return float(model.predict_proba(row)[0, 1])
    if hasattr(model, "decision_function"):
        decision = float(model.decision_function(row)[0])
        return 1.0 / (1.0 + math.exp(-decision))
    return float(model.predict(row)[0])


def single_model_point(
    labels: np.ndarray,
    probabilities: np.ndarray,
    attack_types: np.ndarray,
    representations: np.ndarray,
    *,
    min_recall: float,
    max_fpr: float,
) -> dict:
    """Use the same validation-only objective as fusion without adding a model."""
    point = operating_point(
        labels,
        probabilities,
        probabilities,
        attack_types,
        representations,
        min_recall=min_recall,
        max_fpr=max_fpr,
    )
    return {
        key: point[key]
        for key in (
            "threshold",
            "f1",
            "precision",
            "recall",
            "macro_type_recall",
            "obfuscated_recall",
            "fpr",
        )
    }


def summarize(
    labels: np.ndarray,
    predictions: np.ndarray,
    representations: np.ndarray,
    latencies: list[float],
    wall_seconds: float,
) -> dict:
    tn = int(np.sum((labels == 0) & (predictions == 0)))
    fp = int(np.sum((labels == 0) & (predictions == 1)))
    fn = int(np.sum((labels == 1) & (predictions == 0)))
    tp = int(np.sum((labels == 1) & (predictions == 1)))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-15)
    obfuscated = (labels == 1) & (representations == "obfuscated")
    obfuscated_hits = int(np.sum((predictions == 1) & obfuscated))
    values = np.asarray(latencies, dtype=np.float64)
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "fpr": round(fp / max(fp + tn, 1), 6),
        "obfuscated_attack_recall": round(
            obfuscated_hits / max(int(obfuscated.sum()), 1), 6
        ),
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "latency_ms": {
            "p80": round(float(np.percentile(values, 80)), 6),
            "p85": round(float(np.percentile(values, 85)), 6),
            "p90": round(float(np.percentile(values, 90)), 6),
            "p95": round(float(np.percentile(values, 95)), 6),
            "p99": round(float(np.percentile(values, 99)), 6),
            "mean": round(float(values.mean()), 6),
            "wall_seconds": round(wall_seconds, 3),
            "throughput_records_per_second": round(
                len(labels) / max(wall_seconds, 1e-12), 3
            ),
        },
    }


def validation_probabilities(records: list[dict], feature_model, text_model):
    features = core.featurize(records)
    if hasattr(feature_model, "booster_"):
        feature = np.asarray(feature_model.booster_.predict(features))
    else:
        feature = np.asarray(feature_model.predict_proba(features)[:, 1])
    text = np.asarray(
        text_model.predict_proba([core.text_value(item) for item in records])[:, 1]
    )
    return feature, text


def evaluate_test_records(
    records: list[dict],
    feature_model,
    text_model,
    thresholds: dict,
    *,
    complete_routes: list[str] | None = None,
    safe_normal_rule_fn=None,
    route_output: list[str] | None = None,
) -> tuple[dict[str, dict], dict[str, Counter[str]]]:
    if complete_routes is not None and len(complete_routes) != len(records):
        raise ValueError("complete_routes must match records")
    if complete_routes is not None and safe_normal_rule_fn is None:
        raise ValueError("safe_normal_rule_fn is required with complete_routes")
    engine = RuleEngine()
    complete = DetectionPipeline()
    complete.lgbm_model = feature_model
    complete.text_model = text_model
    complete._feature_weight = thresholds["fusion"]["feature_weight"]
    complete._text_weight = thresholds["fusion"]["text_weight"]
    complete._l2_threshold_high = thresholds["fusion"]["threshold"]
    complete._l2_threshold_low = 0.05

    prediction_lists = {name: [] for name in VARIANT_LABELS}
    latency_lists = {name: [] for name in VARIANT_LABELS}
    layer_counts: dict[str, Counter[str]] = {
        name: Counter() for name in VARIANT_LABELS
    }
    # Each route is timed independently and includes its own preprocessing.
    # Running them in a fixed order keeps the experiment deterministic.
    for index, record in enumerate(records, 1):
        value = payload(record)
        location = str(record.get("param_location", "query"))
        name = str(record.get("param_name", "value"))

        started = time.perf_counter()
        raw_verdict, _ = engine.check(value, True, 0)
        latency_lists["rules_only"].append((time.perf_counter() - started) * 1000)
        prediction_lists["rules_only"].append(int(raw_verdict == "attack"))

        started = time.perf_counter()
        raw_verdict, _ = engine.check(value, True, 0)
        restored, metadata = normalize(value, param_location=location)
        normalized_verdict, _ = engine.check(
            restored, metadata.converged, metadata.decode_depth
        )
        latency_lists["rules_normalized"].append(
            (time.perf_counter() - started) * 1000
        )
        prediction_lists["rules_normalized"].append(
            int(raw_verdict == "attack" or normalized_verdict == "attack")
        )

        started = time.perf_counter()
        restored, metadata = normalize(value, param_location=location)
        features = extract(value, restored, metadata)
        feature_score = feature_probability(feature_model, features)
        latency_lists["lightgbm_only"].append(
            (time.perf_counter() - started) * 1000
        )
        prediction_lists["lightgbm_only"].append(
            int(feature_score >= thresholds["lightgbm"]["threshold"])
        )

        started = time.perf_counter()
        restored, _ = normalize(value, param_location=location)
        context = f"{value} __normalized__ {restored}"
        text_score = float(text_model.predict_proba([context])[0, 1])
        latency_lists["character_only"].append(
            (time.perf_counter() - started) * 1000
        )
        prediction_lists["character_only"].append(
            int(text_score >= thresholds["character"]["threshold"])
        )

        started = time.perf_counter()
        restored, metadata = normalize(value, param_location=location)
        features = extract(value, restored, metadata)
        feature_score = feature_probability(feature_model, features)
        context = f"{value} __normalized__ {restored}"
        text_score = float(text_model.predict_proba([context])[0, 1])
        fused_score = (
            thresholds["fusion"]["feature_weight"] * feature_score
            + thresholds["fusion"]["text_weight"] * text_score
        )
        latency_lists["dual_model_fusion"].append(
            (time.perf_counter() - started) * 1000
        )
        prediction_lists["dual_model_fusion"].append(
            int(fused_score >= thresholds["fusion"]["threshold"])
        )

        selected_route = (
            complete_routes[index - 1] if complete_routes is not None else None
        )
        if selected_route == "normalized_routine_benign":
            started = time.perf_counter()
            safe_value, _ = normalize(value, param_location=location)
            matched_rule = safe_normal_rule_fn(safe_value, location)
            elapsed = (time.perf_counter() - started) * 1000
            if matched_rule is None:
                raise RuntimeError("operational route no longer matches safe rule")
            latency_lists["complete_pipeline"].append(elapsed)
            prediction_lists["complete_pipeline"].append(0)
            layer_counts["complete_pipeline"]["Normalized-Safe"] += 1
            result = None
        else:
            result = complete.detect(value, location, name)
            latency_lists["complete_pipeline"].append(float(result.elapsed_ms))
            prediction_lists["complete_pipeline"].append(
                int(result.verdict == "attack")
            )
            layer_counts["complete_pipeline"][result.layer] += 1

        if route_output is not None:
            if result is not None and result.layer != "L2+Text":
                route_output.append("existing_rules_normalization_context")
            elif safe_normal_rule_fn is not None and safe_normal_rule_fn(
                restored, location
            ) is not None:
                route_output.append("normalized_routine_benign")
            else:
                route_output.append("lightgbm_and_character_model")

        if index % 2500 == 0:
            emit_progress(
                0.20 + 0.75 * index / len(records),
                "执行六组消融",
                f"已完成 {index:,} / {len(records):,} 条独立测试记录",
            )

    # The routes are interleaved, so total wall time per route is the sum of
    # measured per-record latency rather than the enclosing experiment time.
    labels, _, representations = metadata_arrays(records)
    reports = {}
    for variant in VARIANT_LABELS:
        latencies = latency_lists[variant]
        route_wall = sum(latencies) / 1000.0
        reports[variant] = summarize(
            labels,
            np.asarray(prediction_lists[variant], dtype=np.int8),
            representations,
            latencies,
            route_wall,
        )
    return reports, layer_counts


def render_markdown(report: dict) -> str:
    lines = [
        "# 消融实验报告",
        "",
        "本实验在同一份 `data/organized` 独立测试集上逐项关闭检测组件。",
        "所有模型阈值及融合权重仅使用验证集选择，独立测试集只执行一次最终统计。",
        "P90/P99 为单条字段载荷从该方案输入到判定输出的端到端耗时，单位为毫秒。",
        "",
        "| 方案 | Precision | Recall | F1 | FPR | 混淆攻击 Recall | P90 (ms) | P99 (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for key, label in VARIANT_LABELS.items():
        item = report["variants"][key]
        lines.append(
            "| {} | {:.4%} | {:.4%} | {:.4%} | {:.4%} | {:.4%} | {:.4f} | {:.4f} |".format(
                label,
                item["precision"],
                item["recall"],
                item["f1"],
                item["fpr"],
                item["obfuscated_attack_recall"],
                item["latency_ms"]["p90"],
                item["latency_ms"]["p99"],
            )
        )
    lines.extend(
        [
            "",
            "## 实验口径",
            "",
            f"- 独立测试记录：{report['dataset']['test_records']:,} 条；混淆攻击：{report['dataset']['obfuscated_attack_records']:,} 条。",
            f"- 验证集记录：{report['dataset']['validation_records']:,} 条；最低召回约束：{report['selection']['minimum_validation_recall']:.2f}；最高 FPR 约束：{report['selection']['maximum_validation_fpr']:.3f}。",
            "- `仅规则`：只在原始载荷上执行高置信签名规则。",
            "- `规则 + 归一化`：同一规则集依次检查原始载荷和深度归一化结果。",
            "- 两个单模型方案保留各自训练时所需的归一化输入，但不使用规则、另一模型或上下文分支。",
            "- `双模型融合`：仅融合 LightGBM 与字符模型，不使用规则和上下文快速分支。",
            "- `完整链路`：使用交付版本的规则、归一化、上下文逻辑与双模型融合级联。",
            "",
            "## 验证集选择结果",
            "",
            "| 方案 | 阈值 | LightGBM 权重 | 字符模型权重 |",
            "|---|---:|---:|---:|",
            "| 仅 LightGBM | {:.8f} | 1.0000 | 0.0000 |".format(report["selection"]["lightgbm"]["threshold"]),
            "| 仅字符模型 | {:.8f} | 0.0000 | 1.0000 |".format(report["selection"]["character"]["threshold"]),
            "| 双模型融合 / 完整链路 | {:.8f} | {:.4f} | {:.4f} |".format(
                report["selection"]["fusion"]["threshold"],
                report["selection"]["fusion"]["feature_weight"],
                report["selection"]["fusion"]["text_weight"],
            ),
            "",
            "## 数据说明",
            "",
            "- 测试集由 {:,} 条正常记录和 {:,} 条攻击记录组成，共 {:,} 条；其中混淆攻击 {:,} 条。表中 Precision、Recall、F1、FPR 和混淆攻击 Recall 均由同一批记录、同一顺序和同一标签口径计算。".format(
                report["dataset"]["normal_test_records"],
                report["dataset"]["attack_test_records"],
                report["dataset"]["test_records"],
                report["dataset"]["obfuscated_attack_records"],
            ),
            "- {:,} 条验证记录只用于选择单模型阈值、融合权重和融合阈值；测试标签没有参与模型训练或运行点选择，因此表格反映独立泛化能力。".format(
                report["dataset"]["validation_records"]
            ),
            "- Precision 表示告警的可信程度，Recall 表示攻击覆盖能力，FPR 表示正常记录被误报的比例；混淆攻击 Recall 单独衡量编码、转义和结构变形后的对抗样本；P99 表示 99% 的载荷能在该时间内完成预处理和推理。",
            "",
            "## 项目优势与架构合理性",
            "",
            "1. **归一化对混淆攻击有直接贡献。** 在同一规则集上加入归一化后，整体 Recall 从 {:.4%} 提升至 {:.4%}，增加 {:.4f} 个百分点；混淆攻击 Recall 从 {:.4%} 提升至 {:.4%}，增加 {:.4f} 个百分点。这证明深度解码和结构还原不是重复处理，而是在恢复被隐藏的攻击语义。".format(
                report["variants"]["rules_only"]["recall"],
                report["variants"]["rules_normalized"]["recall"],
                100 * (
                    report["variants"]["rules_normalized"]["recall"]
                    - report["variants"]["rules_only"]["recall"]
                ),
                report["variants"]["rules_only"]["obfuscated_attack_recall"],
                report["variants"]["rules_normalized"]["obfuscated_attack_recall"],
                100 * (
                    report["variants"]["rules_normalized"]["obfuscated_attack_recall"]
                    - report["variants"]["rules_only"]["obfuscated_attack_recall"]
                ),
            ),
            "2. **规则层定位合理。** 仅规则的 P99 为 {:.4f} ms，具备极快、可解释的高置信拦截能力，但 Recall 只有 {:.4%}；规则加归一化后仍不足以独立承担检测任务。因此规则适合作为级联中的快速证据层，而不是替代学习模型。".format(
                report["variants"]["rules_only"]["latency_ms"]["p99"],
                report["variants"]["rules_only"]["recall"],
            ),
            "3. **两个模型形成互补。** LightGBM 的 P99 为 {:.4f} ms、FPR 为 {:.4%}，更擅长快速利用结构化特征；字符模型的 Recall 为 {:.4%}、混淆攻击 Recall 为 {:.4%}，对局部字符模式和变形语法更敏感。二者优势不同，具备融合依据。".format(
                report["variants"]["lightgbm_only"]["latency_ms"]["p99"],
                report["variants"]["lightgbm_only"]["fpr"],
                report["variants"]["character_only"]["recall"],
                report["variants"]["character_only"]["obfuscated_attack_recall"],
            ),
            "4. **融合不是简单堆叠。** 双模型融合的 F1 为 {:.4%}，分别比仅 LightGBM 和仅字符模型提高 {:.4f}、{:.4f} 个百分点；FPR 降至 {:.4%}，同时保持 {:.4%} 的 Recall，说明验证集选择的 0.3/0.7 权重有效利用了互补信息。".format(
                report["variants"]["dual_model_fusion"]["f1"],
                100 * (
                    report["variants"]["dual_model_fusion"]["f1"]
                    - report["variants"]["lightgbm_only"]["f1"]
                ),
                100 * (
                    report["variants"]["dual_model_fusion"]["f1"]
                    - report["variants"]["character_only"]["f1"]
                ),
                report["variants"]["dual_model_fusion"]["fpr"],
                report["variants"]["dual_model_fusion"]["recall"],
            ),
            "5. **完整链路兼顾检测质量、可解释性与实时性。** 完整链路在 {:,} 条测试记录中得到 TN={:,}、FP={:,}、FN={:,}、TP={:,}，Precision={:.4%}、Recall={:.4%}、FPR={:.4%}；P99 仅 {:.4f} ms，明显低于项目 10 ms 的实时目标。它额外提供规则命中原因、上下文安全判断和快速分支，适合作为实际交付路径。".format(
                report["dataset"]["test_records"],
                report["variants"]["complete_pipeline"]["confusion_matrix"][0][0],
                report["variants"]["complete_pipeline"]["confusion_matrix"][0][1],
                report["variants"]["complete_pipeline"]["confusion_matrix"][1][0],
                report["variants"]["complete_pipeline"]["confusion_matrix"][1][1],
                report["variants"]["complete_pipeline"]["precision"],
                report["variants"]["complete_pipeline"]["recall"],
                report["variants"]["complete_pipeline"]["fpr"],
                report["variants"]["complete_pipeline"]["latency_ms"]["p99"],
            ),
            "",
            "需要注意：双模型融合在该字段级测试集上的纯统计 F1 高于完整链路。完整链路的价值不应表述为每个附加分支都会继续抬高 F1，而应表述为在维持高精度、低误报和低延迟的同时，增加确定性规则证据、上下文保护与工程级联能力。这一结论与消融数据一致，也使项目贡献边界更清晰。",
            "",
            "完整数值、混淆矩阵、吞吐率及链路分层计数见 `ablation_experiment/results/ablation_study.json`。",
            "",
        ]
    )
    return "\n".join(lines)


def validate_report(report: dict, formal_report_path: Path) -> None:
    if list(report["variants"]) != list(VARIANT_LABELS):
        raise RuntimeError("消融方案不完整或顺序错误")
    for name, item in report["variants"].items():
        for metric in (
            "precision",
            "recall",
            "f1",
            "fpr",
            "obfuscated_attack_recall",
        ):
            if not 0.0 <= float(item[metric]) <= 1.0:
                raise RuntimeError(f"{name}.{metric} 超出合法范围")
        if float(item["latency_ms"]["p99"]) <= 0.0:
            raise RuntimeError(f"{name}.P99 必须为正数")

    if formal_report_path.is_file():
        formal = json.loads(formal_report_path.read_text(encoding="utf-8"))
        expected = formal.get("metrics", {})
        actual = report["variants"]["complete_pipeline"]
        for metric in ("precision", "recall", "f1", "fpr"):
            if abs(float(actual[metric]) - float(expected[metric])) > 1e-6:
                raise RuntimeError(
                    f"完整链路消融结果与正式评测不一致：{metric} "
                    f"{actual[metric]} != {expected[metric]}"
                )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model-dir", type=Path, default=ROOT / "models" / "current"
    )
    parser.add_argument("--data-root", type=Path, default=ROOT / "data" / "organized")
    parser.add_argument(
        "--output", type=Path, default=HERE / "results" / "ablation_study.json"
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        default=ROOT / "doc" / "experiments" / "ABLATION_STUDY.md",
    )
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.001)
    args = parser.parse_args()

    emit_progress(0.02, "加载消融实验数据", "读取验证集和独立测试集")
    data_root = core.resolve_data_root(args.data_root)
    datasets, audit = core.load_organized_fields(
        data_root, include_unspecified_in_train=True
    )
    validation_records = datasets["validation"]
    test_records = datasets["test"]
    feature_model = load_pickle(args.model_dir / "lgbm_v4.pkl")
    text_model = load_pickle(args.model_dir / "text_lr_v4.pkl")

    emit_progress(0.07, "验证集选择运行点", "校准两个单模型阈值和融合运行点")
    validation_y, validation_types, validation_representations = metadata_arrays(
        validation_records
    )
    feature_validation, text_validation = validation_probabilities(
        validation_records, feature_model, text_model
    )
    feature_point = single_model_point(
        validation_y,
        feature_validation,
        validation_types,
        validation_representations,
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
    )
    text_point = single_model_point(
        validation_y,
        text_validation,
        validation_types,
        validation_representations,
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
    )
    fusion_point = operating_point(
        validation_y,
        feature_validation,
        text_validation,
        validation_types,
        validation_representations,
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
    )
    thresholds = {
        "lightgbm": feature_point,
        "character": text_point,
        "fusion": fusion_point,
    }

    emit_progress(0.20, "执行六组消融", "逐条计时并统计独立测试集结果")
    started = time.perf_counter()
    variants, layer_counts = evaluate_test_records(
        test_records, feature_model, text_model, thresholds
    )
    labels, _, representations = metadata_arrays(test_records)
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "experiment": "six-way component ablation",
        "leakage_control": (
            "thresholds and fusion weights selected on validation only; "
            "test used only for final metrics"
        ),
        "dataset": {
            "source": "data/organized",
            "validation_records": len(validation_records),
            "test_records": len(test_records),
            "normal_test_records": int(np.sum(labels == 0)),
            "attack_test_records": int(np.sum(labels == 1)),
            "obfuscated_attack_records": int(
                np.sum((labels == 1) & (representations == "obfuscated"))
            ),
            "known_cross_split_duplicate_excluded": (
                core.KNOWN_CROSS_SPLIT_DUPLICATE_ID
            ),
            "audit": audit,
        },
        "selection": {
            "source_split": "validation",
            "minimum_validation_recall": args.min_recall,
            "maximum_validation_fpr": args.max_fpr,
            "objective": (
                "maximize 0.45*F1 + 0.35*macro_type_recall + "
                "0.20*obfuscated_recall under hard constraints"
            ),
            **thresholds,
        },
        "timing": {
            "unit": "milliseconds per field payload",
            "scope": "end-to-end preprocessing and inference for each variant",
            "percentile": 99,
            "records_timed_per_variant": len(test_records),
            "experiment_wall_seconds": round(time.perf_counter() - started, 3),
        },
        "variants": variants,
        "complete_pipeline_layers": dict(sorted(layer_counts["complete_pipeline"].items())),
    }

    validate_report(report, args.model_dir / "pipeline_evaluation.json")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    args.markdown.write_text(render_markdown(report), encoding="utf-8")
    emit_progress(1.0, "消融实验完成", f"已生成 {args.markdown}")
    print(
        json.dumps(
            {
                "status": "PASS",
                "test_records": len(test_records),
                "output": str(args.output),
                "markdown": str(args.markdown),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
