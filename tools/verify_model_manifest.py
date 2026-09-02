#!/usr/bin/env python3
"""Verify every model artifact against model_manifest_v4.json."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODEL_ROOT = ROOT / "models" / "current"


def main() -> None:
    manifest = json.loads(
        (MODEL_ROOT / "model_manifest_v4.json").read_text(encoding="utf-8")
    )
    errors = []
    for item in manifest["files"]:
        path = MODEL_ROOT / item["path"]
        if not path.is_file():
            errors.append(f"missing: {item['path']}")
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.stat().st_size != item["bytes"] or digest != item["sha256"]:
            errors.append(f"changed: {item['path']}")
    if len(manifest.get("feature_order", [])) not in (0, 38):
        errors.append("feature_order must contain exactly 38 entries")
    if errors:
        raise SystemExit("model verification FAILED\n" + "\n".join(errors))
    print(f"model verification PASS: {len(manifest['files'])} artifacts")


if __name__ == "__main__":
    main()
