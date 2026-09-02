#!/usr/bin/env python3
"""Prove that result is self-contained and has no Git LFS placeholders."""

from __future__ import annotations

import json
import subprocess
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def is_lfs_pointer(path: Path) -> bool:
    if path.stat().st_size > 300:
        return False
    try:
        with path.open("rb") as handle:
            return handle.readline().strip() == b"version https://git-lfs.github.com/spec/v1"
    except OSError:
        return False


def absolute_path_fields(value, prefix=""):
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            current = f"{prefix}.{key}" if prefix else key
            if (
                key in {"data_root", "data_source", "model_dir", "output_dir"}
                and isinstance(item, str)
                and (":\\" in item or item.startswith("/"))
            ):
                found.append((current, item))
            found.extend(absolute_path_fields(item, current))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(absolute_path_fields(item, f"{prefix}[{index}]"))
    return found


def main() -> None:
    errors = []
    pointers = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file() and is_lfs_pointer(path)
    ]
    if pointers:
        errors.extend(f"Git LFS pointer: {path}" for path in pointers)

    dataset_root = ROOT / "data" / "organized"
    archive = ROOT / "data" / "archives" / "organized_complete.zip"
    if not dataset_root.is_dir():
        errors.append("missing local data/organized")
    if not archive.is_file() or archive.stat().st_size != 205_690_188:
        errors.append("missing or changed organized_complete.zip")

    absolute_fields = []
    for path in (ROOT / "models").rglob("*.json"):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        for key, item in absolute_path_fields(value):
            absolute_fields.append(
                {
                    "report": path.relative_to(ROOT).as_posix(),
                    "field": key,
                    "value": item,
                }
            )
    if absolute_fields:
        errors.extend(
            f"absolute report path: {item['report']}:{item['field']}"
            for item in absolute_fields
        )

    python = shutil.which("python")
    dry_run = None
    if not python:
        errors.append("restartable python launcher not found")
    else:
        dry_run = subprocess.run(
            [
                python,
                str(ROOT / "training" / "train_final.py"),
                "--data-root",
                str(dataset_root),
                "--dry-run",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        if dry_run.returncode:
            errors.append("standalone training dry-run failed")

    report = {
        "status": "FAIL" if errors else "PASS",
        "project_root": ".",
        "local_dataset": {
            "path": "data/organized",
            "archive": "data/archives/organized_complete.zip",
        },
        "lfs_pointer_count": len(pointers),
        "absolute_model_report_path_count": len(absolute_fields),
        "training_dry_run": {
            "returncode": None if dry_run is None else dry_run.returncode,
            "tail": (
                ""
                if dry_run is None
                else "standalone training dry-run PASS on data/organized"
                if dry_run.returncode == 0
                else (dry_run.stdout + dry_run.stderr)[-4000:]
            ),
        },
        "errors": errors,
    }
    output = ROOT / "runtime" / "verification" / "independence.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
