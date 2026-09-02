#!/usr/bin/env python3
"""Create the integrity and deployment manifest for a validated model directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument(
        "--output-name", default="model_manifest_v4.json"
    )
    args = parser.parse_args()
    root = args.model_dir.resolve()
    required = ("lgbm_v4.pkl", "text_lr_v4.pkl", "lgbm_v4.meta.json")
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise SystemExit("missing model files: " + ", ".join(missing))

    metadata = json.loads((root / "lgbm_v4.meta.json").read_text(encoding="utf-8"))
    training_path = root / "training_results.json"
    training = (
        json.loads(training_path.read_text(encoding="utf-8"))
        if training_path.is_file()
        else {}
    )
    evaluation_path = root / "pipeline_evaluation.json"
    evaluation = (
        json.loads(evaluation_path.read_text(encoding="utf-8"))
        if evaluation_path.is_file()
        else {}
    )
    files = []
    for name in sorted(
        path.name
        for path in root.iterdir()
        if path.is_file() and path.name != args.output_name
    ):
        path = root / name
        files.append(
            {"path": name, "bytes": path.stat().st_size, "sha256": sha256(path)}
        )

    manifest = {
        "format": "web-attack-detector-model-v4",
        "status": "validated-current",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "objective": "field-level Web attack payload detection",
        "files": files,
        "feature_order": metadata.get("feature_order", []),
        "feature_count": len(metadata.get("feature_order", [])) or 38,
        "thresholds": metadata.get("thresholds", {}),
        "fusion": metadata.get("fusion", {}),
        "training_policy": training.get("data_policy", {}),
        "sampling": training.get("sampling", {}),
        "model_validation": training.get("validation", {}),
        "model_test": training.get("test", {}),
        "pipeline_evaluation": evaluation.get("metrics", {}),
        "pipeline_latency_ms": evaluation.get("latency_ms", {}),
    }
    output = root / args.output_name
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "manifest": str(output),
                "files": len(files),
                "feature_count": manifest["feature_count"],
                "thresholds": manifest["thresholds"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
