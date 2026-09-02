#!/usr/bin/env python3
"""Relocatable entry point for the validated organized-data trainer."""

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from training import train_final_impl as implementation  # noqa: E402


def output_directory() -> Path:
    if "--output-dir" in sys.argv:
        index = sys.argv.index("--output-dir") + 1
        if index < len(sys.argv):
            return Path(sys.argv[index])
    return ROOT / "models" / "candidate"


def make_report_relocatable(path: Path) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(report.get("data_audit"), dict):
        report["data_audit"]["data_root"] = "data/organized"
    if isinstance(report.get("sampling"), dict):
        report["sampling"]["data_root"] = "data/organized"
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    implementation.main()
    if "--dry-run" in sys.argv:
        return
    output = output_directory()
    for name in ("lgbm_v4.meta.json", "training_results.json"):
        path = output / name
        if not path.is_file():
            raise SystemExit(f"training completed without required report: {path}")
        make_report_relocatable(path)


if __name__ == "__main__":
    main()
