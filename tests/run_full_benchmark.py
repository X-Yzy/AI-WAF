#!/usr/bin/env python3
"""Run the delivery benchmark on the authoritative organized dataset.

The data benchmark covers every eligible field-level original and obfuscated
attack record.  It also loads the current deployable models through the public
``DetectionPipeline`` API and checks that their feature contract matches the
runtime extractor.  No data, report, or model artifact is modified.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.extractor import FEATURE_NAMES, extract, extract_with_names  # noqa: E402
from src.normalizer import normalize  # noqa: E402
from src.obfuscator import generate_online, list_strategies  # noqa: E402
from src.pipeline import DetectionPipeline  # noqa: E402


DEFAULT_DATA_ROOT = ROOT / "data" / "organized"
DEFAULT_MODEL_DIR = ROOT / "models" / "current"


def configure_utf8_console() -> None:
    """Keep Chinese benchmark output portable on Windows code pages."""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


configure_utf8_console()


def _is_lfs_pointer(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.readline().strip() == b"version https://git-lfs.github.com/spec/v1"
    except OSError:
        return False


def resolve_data_root(explicit: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    if configured := os.environ.get("WAD_ORGANIZED_ROOT"):
        candidates.append(Path(configured))
    candidates.append(DEFAULT_DATA_ROOT)

    checked: list[str] = []
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if str(resolved) in checked:
            continue
        checked.append(str(resolved))
        manifest = resolved / "manifest.json"
        field_files = list((resolved / "attack" / "original").glob("*/field/*.jsonl"))
        if manifest.is_file() and field_files and not all(_is_lfs_pointer(path) for path in field_files):
            return resolved
    raise FileNotFoundError(
        "No usable organized dataset was found. Checked: "
        + ", ".join(checked)
        + ". Pass --data-root or set WAD_ORGANIZED_ROOT to the extracted data/organized directory."
    )


def iter_jsonl(path: Path):
    if _is_lfs_pointer(path):
        raise RuntimeError(f"Git LFS pointer found instead of JSONL data: {path}")
    with path.open(encoding="utf-8-sig") as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected a JSON object at {path}:{line_number}")
            yield value


def payload_of(record: dict) -> str:
    return str(record.get("obfuscated_payload") or record.get("payload") or "")


def is_eligible_field(record: dict) -> bool:
    metadata = record.get("_organized")
    payload = payload_of(record)
    return (
        isinstance(metadata, dict)
        and metadata.get("payload_model_eligible") is True
        and str(metadata.get("data_level", "")) == "field"
        and bool(payload)
        and len(payload) <= 8192
    )


def load_family_records(data_root: Path, representation: str, attack_type: str) -> list[dict]:
    family_root = data_root / "attack" / representation / attack_type / "field"
    records: list[dict] = []
    for path in sorted(family_root.glob("*.jsonl")):
        records.extend(record for record in iter_jsonl(path) if is_eligible_field(record))
    return records


def attack_types(data_root: Path, representation: str) -> list[str]:
    base = data_root / "attack" / representation
    return sorted(path.name for path in base.iterdir() if path.is_dir())


# ===================================================================
# 1. 原始载荷归一化
# ===================================================================

def benchmark_raw_normalizer(data_root: Path):
    print("=" * 72)
    print("1. organized 原始攻击字段归一化基准")
    print("=" * 72)

    atype_stats = {}
    total_payloads = 0
    total_changed = 0
    total_time = 0.0

    for atype in attack_types(data_root, "original"):
        records = load_family_records(data_root, "original", atype)
        if not records:
            continue

        changed = 0
        converged = 0
        t0 = time.perf_counter()
        for record in records:
            payload = payload_of(record)
            restored, meta = normalize(
                payload,
                param_location=str(record.get("param_location", "query")),
            )
            changed += int(restored != payload)
            converged += int(meta.converged)
        elapsed = (time.perf_counter() - t0) * 1000
        count = len(records)

        atype_stats[atype] = {
            "total": count,
            "changed": changed,
            "converged": converged,
            "unchanged": count - changed,
            "time_ms": round(elapsed, 2),
            "avg_us": round(elapsed * 1000 / count, 1),
        }
        total_payloads += count
        total_changed += changed
        total_time += elapsed
        print(
            f"  {atype:34s} | {count:5d} 条 | 变化 {changed:5d} | "
            f"收敛 {converged:5d} | {elapsed / count * 1000:7.1f} µs/条"
        )

    if not total_payloads:
        raise RuntimeError("No eligible original field attack records were found")
    print(
        f"\n  总计: {total_payloads:,} 条 | 变化 {total_changed:,} 条 "
        f"({total_changed / total_payloads * 100:.1f}%) | "
        f"总耗时 {total_time:.1f} ms | "
        f"平均 {total_time / total_payloads * 1000:.1f} µs/条"
    )
    return atype_stats, total_payloads, total_changed, total_time


# ===================================================================
# 2. 混淆载荷归一化（按 profile 分组）
# ===================================================================

def benchmark_obfuscated_normalizer(data_root: Path):
    print("\n" + "=" * 72)
    print("2. organized 混淆攻击字段归一化基准")
    print("=" * 72)

    profile_stats = defaultdict(
        lambda: {"total": 0, "exact": 0, "partial": 0, "failed": 0, "converged": 0}
    )
    atype_stats = {}
    total = 0
    exact_total = 0
    total_time = 0.0

    for atype in attack_types(data_root, "obfuscated"):
        records = load_family_records(data_root, "obfuscated", atype)
        if not records:
            continue

        t0 = time.perf_counter()
        exact = 0
        partial = 0
        failed = 0
        converged = 0
        for record in records:
            obfuscated = payload_of(record)
            original = str(record.get("original_payload") or "").strip()
            profile = str(record.get("obfuscation_profile") or "unlabelled")
            restored, meta = normalize(
                obfuscated,
                param_location=str(record.get("param_location", "query")),
            )
            restored = restored.strip()

            profile_stats[profile]["total"] += 1
            if original and restored == original:
                exact += 1
                profile_stats[profile]["exact"] += 1
            elif original and original in restored:
                partial += 1
                profile_stats[profile]["partial"] += 1
            else:
                failed += 1
                profile_stats[profile]["failed"] += 1
            if meta.converged:
                converged += 1
                profile_stats[profile]["converged"] += 1

        elapsed = (time.perf_counter() - t0) * 1000
        count = len(records)
        atype_stats[atype] = {
            "total": count,
            "exact": exact,
            "partial": partial,
            "failed": failed,
            "exact_pct": round(exact / count * 100, 1),
            "converged": converged,
            "time_ms": round(elapsed, 2),
            "avg_us": round(elapsed * 1000 / count, 1),
        }
        total += count
        exact_total += exact
        total_time += elapsed
        print(
            f"  {atype:34s} | {count:5d} 条 | exact {exact:5d} ({exact / count * 100:5.1f}%) | "
            f"partial {partial:5d} | failed {failed:5d} | "
            f"收敛 {converged:5d} | {elapsed / count * 1000:7.1f} µs/条"
        )

    if not total:
        raise RuntimeError("No eligible obfuscated field attack records were found")
    print(
        f"\n  总计: {total:,} 条混淆 | exact {exact_total:,} "
        f"({exact_total / total * 100:.1f}%) | 总耗时 {total_time:.1f} ms | "
        f"平均 {total_time / total * 1000:.1f} µs/条"
    )
    print("\n  按 profile 分组:")
    for profile in sorted(profile_stats):
        stats = profile_stats[profile]
        print(
            f"    {profile:32s} | {stats['total']:6d} 条 | "
            f"exact {stats['exact']:6d} ({stats['exact'] / stats['total'] * 100:5.1f}%) | "
            f"partial {stats['partial']:5d} | failed {stats['failed']:5d}"
        )
    return atype_stats, profile_stats, total, exact_total, total_time


# ===================================================================
# 3. 正式模型接口与特征契约
# ===================================================================

def benchmark_final_pipeline(model_dir: Path):
    print("\n" + "=" * 72)
    print("3. 正式 DetectionPipeline 冒烟验证")
    print("=" * 72)

    model_dir = model_dir.expanduser().resolve()
    manifest_path = model_dir / "model_manifest_v4.json"
    lgbm_path = model_dir / "lgbm_v4.pkl"
    text_path = model_dir / "text_lr_v4.pkl"
    missing = [path for path in (manifest_path, lgbm_path, text_path) if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing deployable model artifacts: " + ", ".join(map(str, missing)))

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("feature_count") != len(FEATURE_NAMES):
        raise RuntimeError("Model manifest feature_count does not match src.extractor.FEATURE_NAMES")
    if manifest.get("feature_order") != list(FEATURE_NAMES):
        raise RuntimeError("Model manifest feature_order does not match the runtime extractor")

    detector = DetectionPipeline()
    detector.load_lgbm(str(lgbm_path))
    detector.load_text_model(str(text_path))
    cases = [
        ("SQL 注入", "' OR 1=1 --", "query", "id", "attack"),
        ("XSS", "<svg onload=alert(1)>", "body", "content", "attack"),
        ("路径穿越", "../../../../etc/passwd", "path", "path", "attack"),
        ("普通搜索", "今天天气怎么样", "query", "q", "benign"),
        ("SQL 教程", "SELECT 和 JOIN 的区别是什么？", "body", "content", "benign"),
        ("普通 JSON", '{"name":"张三","age":25}', "body", "value", "benign"),
    ]
    mismatches = []
    latencies = []
    for label, payload, location, name, expected in cases:
        result = detector.detect(payload, location, name)
        latencies.append(float(result.elapsed_ms))
        if result.verdict != expected:
            mismatches.append(f"{label}: expected {expected}, got {result.verdict}")
        print(
            f"  {label:10s} | {result.verdict:6s} | {result.layer:10s} | "
            f"confidence {result.confidence:.4f} | {result.elapsed_ms:.3f} ms"
        )
    if mismatches:
        raise AssertionError("Formal pipeline smoke cases failed: " + "; ".join(mismatches))
    print(
        f"\n  特征契约: {len(FEATURE_NAMES)} 维，顺序一致 | "
        f"代表样本平均 {sum(latencies) / len(latencies):.3f} ms/条"
    )
    return latencies


# ===================================================================
# 4. 特征提取器验证
# ===================================================================

def benchmark_extractor():
    print("\n" + "=" * 72)
    print("4. 运行时特征提取器验证")
    print("=" * 72)

    samples = {
        "SQL注入(干净)": "' UNION SELECT 1,2,3--",
        "SQL注入(URL编码)": "%27%20UNION%20SELECT%201%2C2%2C3--",
        "SQL注入(Base64)": "JyBVTklPTiBTRUxFQ1QgMSwyLDMtLQ==",
        "XSS(干净)": "<script>alert('XSS')</script>",
        "XSS(HTML实体)": "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;",
        "命令注入(干净)": "; cat /etc/passwd",
        "命令注入(IFS绕过)": "; cat${IFS}/etc/passwd",
        "正常搜索": "今天天气怎么样",
        "正常JSON": '{"name":"张三","age":25}',
        "边界样本(SQL讨论)": "comment=SELECT 和 JOIN 的区别是什么",
    }

    results = []
    for label, payload in samples.items():
        restored, meta = normalize(payload)
        vector = extract(payload, restored, meta)
        named = extract_with_names(payload, restored, meta)
        if vector.shape != (len(FEATURE_NAMES),) or list(named) != list(FEATURE_NAMES):
            raise AssertionError(f"Feature contract mismatch for {label}")
        if not all(math.isfinite(float(value)) for value in vector):
            raise AssertionError(f"Non-finite feature value for {label}")

        raw_nz = sum(1 for value in vector[:12] if abs(value) > 0.001)
        restored_nz = sum(1 for value in vector[12:26] if abs(value) > 0.001)
        process_nz = sum(1 for value in vector[26:] if abs(value) > 0.001)
        results.append(
            {
                "label": label,
                "payload": payload[:60],
                "restored": restored[:60],
                "changed": restored != payload,
                "converged": meta.converged,
                "decode_depth": meta.decode_depth,
                "url_layers": meta.url_decode_layers,
                "base64_ok": meta.base64_decode_success,
                "raw_nz": raw_nz,
                "restored_nz": restored_nz,
                "process_nz": process_nz,
                "total_nz": raw_nz + restored_nz + process_nz,
                "entropy_delta": round(meta.entropy_before - meta.entropy_after, 3),
            }
        )
        print(
            f"  {label:25s} | raw={raw_nz} restored={restored_nz} process={process_nz} | "
            f"depth={meta.decode_depth} url_layers={meta.url_decode_layers} "
            f"b64={meta.base64_decode_success} "
            f"Δent={meta.entropy_before - meta.entropy_after:+.3f}"
        )

    print(f"\n  NaN/Inf: 0 | 全部样本 {len(FEATURE_NAMES)} 维输出有效")
    return results


# ===================================================================
# 5. 混淆生成器统计
# ===================================================================

def benchmark_obfuscator():
    print("\n" + "=" * 72)
    print("5. 混淆生成器统计")
    print("=" * 72)

    categories = list_strategies()
    for category, names in categories.items():
        print(f"  {category}: {len(names)} 种 — {names}")

    test_payloads = [
        ("SQL注入", "' OR 1=1 --"),
        ("XSS", "<script>alert(1)</script>"),
        ("命令注入", "; ls -la"),
        ("SSTI", "{{7*7}}"),
        ("路径穿越", "../../../etc/passwd"),
    ]
    print()
    for label, payload in test_payloads:
        variants = [generate_online(payload) for _ in range(5)]
        unique = len(set(variants))
        average_ratio = sum(len(value) / max(len(payload), 1) for value in variants) / len(variants)
        print(
            f"  {label:10s} | 原始 {len(payload):3d} 字符 | "
            f"5 变种中 {unique} 种不同 | 平均长度变化 ×{average_ratio:.1f}"
        )
    return test_payloads


# ===================================================================
# 6. 性能总结
# ===================================================================

def benchmark_perf(raw_time: float, obfuscated_time: float, raw_n: int, obfuscated_n: int):
    print("\n" + "=" * 72)
    print("6. 归一化性能总结")
    print("=" * 72)

    print(f"  原始载荷: {raw_n:,} 条, {raw_time:.1f} ms, {raw_time / raw_n * 1000:.1f} µs/条")
    print(
        f"  混淆载荷: {obfuscated_n:,} 条, {obfuscated_time:.1f} ms, "
        f"{obfuscated_time / obfuscated_n * 1000:.1f} µs/条"
    )
    total_time = raw_time + obfuscated_time
    total_records = raw_n + obfuscated_n
    average_ms = total_time / total_records
    print(
        f"  总计: {total_records:,} 条, {total_time:.1f} ms, "
        f"{average_ms * 1000:.1f} µs/条"
    )
    print(
        f"  归一化平均耗时参考 ≤10ms/条: {'PASS' if average_ms <= 10 else 'FAIL'} "
        "（正式检测时延以独立评测的 P99 为准）"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-root",
        type=Path,
        help="organized 数据根目录；默认读取 data/organized 或 WAD_ORGANIZED_ROOT",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=Path(os.environ.get("WAD_MODEL_ROOT", DEFAULT_MODEL_DIR)),
        help="正式模型目录；默认读取 models/current 或 WAD_MODEL_ROOT",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    data_root = resolve_data_root(args.data_root)
    print(f"organized 数据: {data_root}")
    print(f"正式模型: {args.model_dir.expanduser().resolve()}")
    started = time.perf_counter()

    raw = benchmark_raw_normalizer(data_root)
    obfuscated = benchmark_obfuscated_normalizer(data_root)
    benchmark_final_pipeline(args.model_dir)
    benchmark_extractor()
    benchmark_obfuscator()
    benchmark_perf(raw[3], obfuscated[4], raw[1], obfuscated[2])

    elapsed = time.perf_counter() - started
    print(f"\n{'=' * 72}")
    print(f"全量基准完成，总耗时 {elapsed:.1f}s")
    print(f"{'=' * 72}")


if __name__ == "__main__":
    main()
