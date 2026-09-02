#!/usr/bin/env python3
"""Extend the existing same-record report with SafeLine and open-appsec.

The script never substitutes local keyword rules for a missing product.  A
candidate enters the ranking only after its real reverse-proxy endpoint passes
both smoke gates and completes every record in the independent test split.
"""

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
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from training import train_organized_full as core  # noqa: E402
from training.external_waf import (  # noqa: E402
    ExternalProductSpec,
    ExternalReverseProxyWAF,
    OPENAPPSEC_KEY,
    PRODUCT_CATALOG,
    SAFELINE_KEY,
    candidate_statuses,
)
from training.real_waf import payload_of  # noqa: E402
def emit_progress(fraction: float, stage: str, detail: str) -> None:
    if os.environ.get("WAD_STRUCTURED_PROGRESS") != "1":
        return
    event = {
        "scope": "compare-external-waf",
        "fraction": max(0.0, min(float(fraction), 1.0)),
        "stage": stage,
        "detail": detail,
    }
    print("@@WAD_PROGRESS " + json.dumps(event, ensure_ascii=False), flush=True)


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return 0.0
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def latency_summary(values: list[float]) -> dict[str, float]:
    return {
        "mean_ms": round(sum(values) / max(len(values), 1), 6),
        "p50_ms": round(percentile(values, 0.50), 6),
        "p95_ms": round(percentile(values, 0.95), 6),
        "p99_ms": round(percentile(values, 0.99), 6),
    }


def classification_metrics(
    labels: list[int], predictions: list[int]
) -> dict[str, Any]:
    tn = fp = fn = tp = 0
    for actual, predicted in zip(labels, predictions):
        if actual == 0 and predicted == 0:
            tn += 1
        elif actual == 0 and predicted == 1:
            fp += 1
        elif actual == 1 and predicted == 0:
            fn += 1
        else:
            tp += 1
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(2 * precision * recall / max(precision + recall, 1e-15), 6),
        "fpr": round(fp / max(fp + tn, 1), 6),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def recall_for_indices(
    predictions: list[int], indices: list[int]
) -> dict[str, Any]:
    detected = sum(predictions[index] for index in indices)
    return {
        "records": len(indices),
        "detected": int(detected),
        "recall": round(detected / max(len(indices), 1), 6),
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def build_specs(args: argparse.Namespace) -> tuple[dict[str, ExternalProductSpec], list[str]]:
    configured: dict[str, ExternalProductSpec] = {}
    errors: list[str] = []
    values = {
        SAFELINE_KEY: (args.safeline_url, args.safeline_version),
        OPENAPPSEC_KEY: (args.openappsec_url, args.openappsec_version),
    }
    for key, (endpoint, version) in values.items():
        endpoint = str(endpoint or "").strip()
        version = str(version or "").strip()
        metadata = PRODUCT_CATALOG[key]
        if not endpoint and not version:
            continue
        if not endpoint or not version:
            errors.append(
                f"{metadata['display_name']} 必须同时设置 "
                f"{metadata['endpoint_env']} 和 {metadata['version_env']}"
            )
            continue
        configured[key] = ExternalProductSpec(
            key=key,
            name=f"{metadata['display_name']} {version}",
            endpoint=endpoint,
            version=version,
            project_url=str(metadata["project_url"]),
            deployment_note=str(metadata["deployment_note"]),
        )
    return configured, errors


def comparison_interpretation(report: dict[str, Any]) -> dict[str, Any]:
    systems = report.get("systems", {})
    final = systems.get("final_model", {})
    final_f1 = float(final.get("f1", 0.0))
    outperformers = []
    for key in report.get("system_order", []):
        if key == "final_model" or key not in systems:
            continue
        system = systems[key]
        f1 = float(system.get("f1", 0.0))
        if f1 > final_f1 + 1e-12:
            outperformers.append(
                {
                    "key": key,
                    "display_name": system.get("display_name", key),
                    "f1_delta": round(f1 - final_f1, 6),
                    "recall_delta": round(
                        float(system.get("recall", 0.0))
                        - float(final.get("recall", 0.0)),
                        6,
                    ),
                    "fpr_delta": round(
                        float(system.get("fpr", 0.0))
                        - float(final.get("fpr", 0.0)),
                        6,
                    ),
                }
            )
    if outperformers:
        summary = (
            "存在真实 WAF 在同集 F1 上高于当前模型。为避免结果筛选，"
            "该结果仍保留在排名中；界面会说明差距，应继续检查分类型召回、"
            "误报率、产品策略与学习状态。"
        )
    else:
        summary = "当前已完成的真实 WAF 中，没有产品在同集 F1 上超过最终模型。"
    return {
        "primary_metric": "f1",
        "products_outperforming_final": outperformers,
        "summary": summary,
    }


def evaluate_product(
    spec: ExternalProductSpec,
    records: list[dict],
    labels: list[int],
    *,
    request_timeout: float,
    checkpoint_dir: Path,
    signature_base: dict[str, Any],
    no_resume: bool,
    progress_start: float,
    progress_span: float,
) -> tuple[list[int], list[float], dict[str, Any], dict[str, Any]]:
    checkpoint = checkpoint_dir / f"{spec.key}.checkpoint.json"
    signature = {
        **signature_base,
        "product": spec.key,
        "version": spec.version,
        "endpoint_sha256": hashlib.sha256(spec.endpoint.encode("utf-8")).hexdigest(),
    }
    predictions: list[int] = []
    latencies: list[float] = []
    restored_execution: dict[str, Any] = {}
    processed = 0
    if checkpoint.is_file() and not no_resume:
        saved = json.loads(checkpoint.read_text(encoding="utf-8"))
        if saved.get("signature") == signature:
            predictions = [int(value) for value in saved.get("predictions", [])]
            latencies = [float(value) for value in saved.get("latencies", [])]
            processed = int(saved.get("processed", 0))
            if len(predictions) != processed or len(latencies) != processed:
                raise RuntimeError(f"{spec.name} checkpoint vector length mismatch")
            restored_execution = dict(saved.get("execution", {}))

    product = ExternalReverseProxyWAF(
        spec,
        request_timeout=request_timeout,
    )
    if restored_execution:
        product.restore_execution_state(restored_execution)
    with product:
        emit_progress(
            progress_start,
            f"{spec.name} 冒烟门禁通过",
            "正常请求到达基准后端，SQL 注入请求由真实产品阻断",
        )
        for index, record in enumerate(records[processed:], processed + 1):
            decision = product.inspect(record)
            predictions.append(int(decision.blocked))
            latencies.append(decision.elapsed_ms)
            if index % 1000 == 0 or index == len(records):
                emit_progress(
                    progress_start + progress_span * index / len(records),
                    f"{spec.name} 同集 HTTP 评测",
                    f"已完成 {index:,} / {len(records):,} 条",
                )
                atomic_write(
                    checkpoint,
                    {
                        "signature": signature,
                        "processed": index,
                        "predictions": predictions,
                        "latencies": latencies,
                        "execution": product.execution_summary(),
                    },
                )
        identity = product.identity()
        execution = product.execution_summary()
    checkpoint.unlink(missing_ok=True)
    return predictions, latencies, identity, execution



def project_env() -> dict[str, str]:
    """Read simple KEY=VALUE entries from project .env without a dependency."""
    values: dict[str, str] = {}
    path = ROOT / ".env"
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def merged_candidate_statuses(
    report: dict[str, Any],
    configured: dict[str, ExternalProductSpec],
) -> dict[str, dict[str, Any]]:
    """Keep verified full-run results while another product is evaluated.

    A later invocation may intentionally configure only one external WAF.  A
    previously completed product remains comparable because its metrics and
    product identity are already stored in the same report.  The result is
    labelled as cached instead of being incorrectly downgraded to
    ``not_configured``.
    """

    statuses = candidate_statuses(configured)
    previous = report.get("candidate_products", {})
    systems = report.get("systems", {})
    identities = report.get("product_identities", {})
    if not isinstance(previous, dict) or not isinstance(systems, dict):
        return statuses
    for key in (SAFELINE_KEY, OPENAPPSEC_KEY):
        item = previous.get(key)
        if (
            key not in configured
            and isinstance(item, dict)
            and item.get("status") == "evaluated"
            and item.get("included_in_ranking") is True
            and key in systems
            and key in identities
        ):
            statuses[key] = {
                **item,
                "configured": False,
                "status": "evaluated",
                "included_in_ranking": True,
                "result_origin": "last_completed_full_run",
                "reason": "保留最近一次已完成的全量同集真实产品结果",
            }
    return statuses

def main() -> None:
    defaults = project_env()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "models" / "current" / "waf_comparison.json",
    )
    parser.add_argument(
        "--data-root",
        type=Path,
        default=ROOT / "data" / "organized",
    )
    parser.add_argument(
        "--safeline-url",
        default=os.environ.get("WAD_SAFELINE_URL", defaults.get("WAD_SAFELINE_URL", "")),
    )
    parser.add_argument(
        "--safeline-version",
        default=os.environ.get("WAD_SAFELINE_VERSION", defaults.get("WAD_SAFELINE_VERSION", "")),
    )
    parser.add_argument(
        "--openappsec-url",
        default=os.environ.get("WAD_OPENAPPSEC_URL", defaults.get("WAD_OPENAPPSEC_URL", "")),
    )
    parser.add_argument(
        "--openappsec-version",
        default=os.environ.get("WAD_OPENAPPSEC_VERSION", defaults.get("WAD_OPENAPPSEC_VERSION", "")),
    )
    parser.add_argument("--request-timeout", type=float, default=30.0)
    parser.add_argument(
        "--checkpoint-dir",
        type=Path,
        default=ROOT / "runtime" / "external_waf_checkpoints",
    )
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    if not args.report.is_file():
        raise SystemExit(
            f"缺少基础报告 {args.report}；请先运行 python run.py compare-waf"
        )
    report = json.loads(args.report.read_text(encoding="utf-8"))
    configured, configuration_errors = build_specs(args)
    report["candidate_products"] = merged_candidate_statuses(report, configured)
    report["selection_policy"] = {
        "performance_based_exclusion": False,
        "policy": (
            "任何通过真实产品门禁并完成相同记录评测的 WAF 都保留；"
            "效果优于最终模型不是排除理由。仅未配置、门禁失败、基础设施错误"
            "或未完成全量同集评测的产品不进入排名，并记录原因。"
        ),
    }
    if configuration_errors:
        for key, candidate in report["candidate_products"].items():
            endpoint_set = bool(
                args.safeline_url if key == SAFELINE_KEY else args.openappsec_url
            )
            version_set = bool(
                args.safeline_version
                if key == SAFELINE_KEY
                else args.openappsec_version
            )
            if endpoint_set != version_set:
                candidate["status"] = "invalid_configuration"
                candidate["reason"] = next(
                    (error for error in configuration_errors if candidate["display_name"] in error),
                    "端点与版本配置不完整",
                )
        report["comparison_interpretation"] = comparison_interpretation(report)
        atomic_write(args.report, report)
        raise SystemExit("；".join(configuration_errors))

    if not configured:
        report["schema"] = "final_model_vs_real_waf_products_v4"
        report["generated_at"] = datetime.now(timezone.utc).isoformat()
        report["comparison_interpretation"] = comparison_interpretation(report)
        atomic_write(args.report, report)
        emit_progress(
            1.0,
            "外部 WAF 未配置",
            "SafeLine/open-appsec 保留为未配置候选，不生成模拟指标",
        )
        print(
            json.dumps(
                {
                    "output": str(args.report),
                    "configured_products": [],
                    "candidate_products": report["candidate_products"],
                },
                ensure_ascii=False,
            )
        )
        return

    emit_progress(0.02, "加载外部 WAF 同集数据", "读取 organized 独立测试记录")
    data_root = core.resolve_data_root(args.data_root)
    datasets, _audit = core.load_organized_fields(
        data_root,
        include_unspecified_in_train=True,
    )
    records = list(datasets["test"])
    labels = [int(record.get("label", 0)) for record in records]
    raw_expected_total = report.get("dataset", {}).get("total")
    expected_total = (
        int(raw_expected_total)
        if isinstance(raw_expected_total, int) and not isinstance(raw_expected_total, bool)
        else None
    )
    if expected_total is not None and expected_total != len(records):
        raise SystemExit(
            f"基础报告记录数 {expected_total} 与当前独立测试集 {len(records)} 不一致"
        )
    if expected_total is None:
        attack_count = sum(labels)
        report["dataset"] = {
            "source": "data/organized",
            "split": "test",
            "eligible_only": True,
            "known_duplicate_excluded": True,
            "attack": attack_count,
            "normal": len(labels) - attack_count,
            "total": len(records),
        }

    type_indices: dict[str, list[int]] = defaultdict(list)
    representation_indices: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        if labels[index] != 1:
            continue
        type_indices[str(record.get("attack_type", "unknown"))].append(index)
        representation = str(
            (record.get("_organized") or {}).get(
                "attack_representation",
                "unknown",
            )
        )
        representation_indices[representation].append(index)

    report.setdefault("product_identities", {})
    report.setdefault("product_executions", {})
    report.setdefault("attack_form_recall", {})
    report.setdefault("attack_type_recall", {})
    order = list(report.get("system_order", []))
    signature_base = {
        "schema": "external-real-waf-checkpoint-v1",
        "records": len(records),
        "data_manifest_sha256": sha256_file(data_root / "manifest.json"),
    }
    configured_items = list(configured.items())
    for product_index, (key, spec) in enumerate(configured_items):
        start_fraction = 0.05 + 0.90 * product_index / max(len(configured_items), 1)
        span = 0.90 / max(len(configured_items), 1)
        try:
            predictions, latencies, identity, execution = evaluate_product(
                spec,
                records,
                labels,
                request_timeout=args.request_timeout,
                checkpoint_dir=args.checkpoint_dir,
                signature_base=signature_base,
                no_resume=args.no_resume,
                progress_start=start_fraction,
                progress_span=span,
            )
        except Exception as exc:
            candidate = report["candidate_products"][key]
            candidate["status"] = "failed_validation"
            candidate["included_in_ranking"] = False
            candidate["reason"] = (
                "真实产品端点未完成双冒烟门禁或全量同集评测："
                f"{type(exc).__name__}: {exc}"
            )
            report["comparison_interpretation"] = comparison_interpretation(report)
            report["generated_at"] = datetime.now(timezone.utc).isoformat()
            atomic_write(args.report, report)
            raise

        report.setdefault("systems", {})[key] = {
            **classification_metrics(labels, predictions),
            "latency": latency_summary(latencies),
            "display_name": identity["name"],
            "kind": "real_waf_product",
            "execution": identity["implementation"],
            "latency_scope": "real external reverse proxy + HTTP + backend proof",
        }
        if key not in order:
            order.append(key)
        report["product_identities"][key] = identity
        report["product_executions"][key] = execution
        for representation, indices in representation_indices.items():
            report["attack_form_recall"].setdefault(representation, {})[key] = (
                recall_for_indices(predictions, indices)
            )
        for attack_type, indices in type_indices.items():
            report["attack_type_recall"].setdefault(attack_type, {})[key] = (
                recall_for_indices(predictions, indices)
            )
        report["candidate_products"][key].update(
            {
                "status": "evaluated",
                "configured": True,
                "included_in_ranking": True,
                "reason": "真实产品双冒烟门禁通过，并完成全部同集记录",
            }
        )

    report["system_order"] = order
    report["schema"] = "final_model_vs_real_waf_products_v4"
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    report["comparison_interpretation"] = comparison_interpretation(report)
    atomic_write(args.report, report)
    emit_progress(1.0, "多 WAF 对比完成", f"报告已更新：{args.report}")
    print(
        json.dumps(
            {
                "output": str(args.report),
                "configured_products": list(configured),
                "candidate_products": report["candidate_products"],
                "comparison_interpretation": report["comparison_interpretation"],
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
