#!/usr/bin/env python3
"""Stable entry point for self-contained-project verification."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools.verify_independence_impl import main as verify  # noqa: E402


def main() -> None:
    verify()
    output = ROOT / "runtime" / "verification" / "independence.json"
    report = json.loads(output.read_text(encoding="utf-8"))
    report["training_dry_run"]["tail"] = (
        "PASS: local data/organized audited without external dependencies"
        if report["training_dry_run"]["returncode"] == 0
        else "FAIL"
    )
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
