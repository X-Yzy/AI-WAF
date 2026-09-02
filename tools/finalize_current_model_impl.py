#!/usr/bin/env python3
"""Build compact runtime metadata for the validated current model."""

from __future__ import annotations

import json
from pathlib import Path

from src.extractor import FEATURE_NAMES


ROOT = Path(__file__).resolve().parents[1]
MODEL_ROOT = ROOT / "models" / "current"


def main() -> None:
    report_path = MODEL_ROOT / "training_results.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    metadata = {
        "format": "ai-waf-runtime-metadata-v4",
        "feature_order": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "threshold": report["threshold"],
        "thresholds": report["thresholds"],
        "fusion": report["fusion"],
        "models": report.get("models", {}),
        "training_results": report_path.name,
        "deployment_status": "validated-current",
    }
    metadata_path = MODEL_ROOT / "lgbm_v4.meta.json"
    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"current model finalized with {len(FEATURE_NAMES)} ordered features")


if __name__ == "__main__":
    main()
