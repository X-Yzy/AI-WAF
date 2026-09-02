#!/usr/bin/env python3
"""数据集验收脚本 — 13 项质量指标检查（T2.4）。

用法:
  python training/validate_dataset.py data/validation/semantic_edge_cases.json
  python training/validate_dataset.py --all   # 扫描 data/validation 下所有 JSON
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


CHECKS = [
    ("总条数", lambda d: len(d) > 0),
    ("有效JSON", lambda d: True),  # already parsed
    ("每条目含id", lambda d: all("id" in item for item in d)),
    ("每条目含payload", lambda d: all("payload" in item for item in d)),
    ("每条目含label", lambda d: all("label" in item for item in d)),
    ("label为0或1", lambda d: all(item.get("label") in {0, 1} for item in d)),
    ("payload非空", lambda d: all(len(item.get("payload", "")) > 0 for item in d)),
    ("label分布合理(10-90%)", lambda d: 0.1 <= sum(item["label"] for item in d) / len(d) <= 0.9),
    ("有attack_type字段", lambda d: all("attack_type" in item for item in d)),
    ("id无重复", lambda d: len(set(item["id"] for item in d)) == len(d)),
    ("payload去重率>50%", lambda d: len(set(item["payload"] for item in d)) / len(d) >= 0.5 if len(d) > 1 else True),
    ("无超长payload(>8KB)", lambda d: all(len(item.get("payload", "")) <= 8192 for item in d)),
    ("param_location合法", lambda d: all(item.get("param_location", "query") in {"query", "body", "header", "cookie", "path"} for item in d)),
]


def validate(filepath: Path) -> dict:
    print(f"\n{'=' * 60}")
    print(f"📋 验收: {filepath.name}")
    print(f"{'=' * 60}")

    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ❌ 无法解析: {e}")
        return {"file": str(filepath), "error": str(e)}

    if not isinstance(data, list):
        print(f"  ❌ 顶层不是数组")
        return {"file": str(filepath), "error": "not a list"}

    passed = 0
    failed = 0
    for label, check in CHECKS:
        try:
            result = check(data)
            if result:
                print(f"  ✅ {label}")
                passed += 1
            else:
                print(f"  ❌ {label}")
                failed += 1
        except Exception as e:
            print(f"  ⚠️ {label}: {e}")
            failed += 1

    # Extra stats
    labels = [item["label"] for item in data]
    attack_count = sum(labels)
    normal_count = len(labels) - attack_count
    types = set(item.get("attack_type", "?") for item in data)

    print(f"\n  统计: {len(data)} 条 | attack={attack_count} | normal={normal_count}")
    print(f"  攻击类型: {len(types)} 种 → {sorted(types)[:10]}{'...' if len(types) > 10 else ''}")
    print(f"  ✅ {passed}/{passed + failed} 项通过")

    # Per-type breakdown
    by_type = {}
    for item in data:
        t = item.get("attack_type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
    if len(by_type) > 1:
        print(f"  按类型分布: {dict(sorted(by_type.items(), key=lambda x: -x[1])[:10])}")

    return {"file": str(filepath), "passed": passed, "failed": failed, "total": len(data), "attack_count": attack_count, "normal_count": normal_count, "types": len(types)}


def main():
    if "--all" in sys.argv:
        dataset_dir = Path(__file__).parent.parent / "data" / "validation"
        json_files = list(dataset_dir.glob("*.json")) + list(dataset_dir.glob("**/*.json"))
        json_files = [f for f in json_files if not f.name.startswith(".")]
    elif len(sys.argv) > 1:
        json_files = [Path(f) for f in sys.argv[1:]]
    else:
        print("用法: python training/validate_dataset.py <file.json> [--all]")
        sys.exit(1)

    all_results = []
    for f in sorted(set(json_files)):
        if f.suffix == ".json":
            all_results.append(validate(f))

    total_passed = sum(r.get("passed", 0) for r in all_results)
    total_checks = sum(r.get("passed", 0) + r.get("failed", 0) for r in all_results)
    print(f"\n{'=' * 60}")
    print(f"📊 总计: {total_passed}/{total_checks} 项通过 ({len(all_results)} 个文件)")
    if total_passed < total_checks:
        sys.exit(1)


if __name__ == "__main__":
    main()
