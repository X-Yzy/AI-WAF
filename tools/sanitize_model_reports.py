#!/usr/bin/env python3
"""Remove machine-specific absolute paths from portable model reports."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sanitize(value, report_path: Path):
    if isinstance(value, dict):
        return {
            key: (
                "data/organized"
                if key in {"data_root", "data_source"} and isinstance(item, str)
                else (
                    (
                        "models/current"
                        if "current" in report_path.parts
                        else "models/history/c5"
                    )
                    if key in {"model_dir", "output_dir"} and isinstance(item, str)
                    else sanitize(item, report_path)
                )
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item, report_path) for item in value]
    return value


def main() -> None:
    changed = []
    for path in sorted((ROOT / "models").rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        cleaned = sanitize(data, path)
        encoded = json.dumps(cleaned, ensure_ascii=False, indent=2) + "\n"
        if encoded != path.read_text(encoding="utf-8"):
            path.write_text(encoded, encoding="utf-8")
            changed.append(path.relative_to(ROOT).as_posix())
    print(f"portable model reports: {len(changed)} files normalized")


if __name__ == "__main__":
    main()
