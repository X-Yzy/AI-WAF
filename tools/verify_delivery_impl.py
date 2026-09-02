#!/usr/bin/env python3
"""Verify all ten delivery sections and both integrity manifests."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from tools.verify_model_manifest import main as verify_model


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "complete_dataset": ["data/organized/manifest.json"],
    "payload_generator": ["payload_generator/cli.py", "src/obfuscator.py"],
    "detection_core": [
        "src/parser.py", "src/normalizer.py", "src/extractor.py",
        "src/engine.py", "src/pipeline.py",
    ],
    "training_evaluation": [
        "training/train_final.py", "training/evaluate_candidate_pipeline.py",
        "training/compare_real_waf.py", "training/real_waf.py",
        "training/compare_external_wafs.py", "training/external_waf.py",
    ],
    "model_management": [
        "models/current/lgbm_v4.pkl", "models/current/text_lr_v4.pkl",
        "models/current/lgbm_v4.meta.json",
        "models/current/waf_comparison.last_verified.json",
        "models/current/model_manifest_v4.json",
    ],
    "local_workbench": ["src/local_app.py", "demo/index.html"],
    "server_runtime": [
        "src/runtime_api.py", "src/proxy.py", "src/ops_dashboard.py",
    ],
    "deployment": [
        "Dockerfile", "docker-compose.yml",
        "deployment/server_runtime/manifest.json",
        "deployment/waf_benchmark/compose.yml",
        "docs/deployment/WAF_BENCHMARK.md",
        "deployment/waf_benchmark/proof_backend.py",
        "deployment/waf_benchmark/openappsec/compose.yml",
        "deployment/waf_benchmark/openappsec/local_policy.yaml",
        "deployment/waf_benchmark/openappsec/nginx.conf",
        "deployment/waf_benchmark/openappsec/start.py",
        "deployment/waf_benchmark/safeline/compose.yml",
        "deployment/waf_benchmark/safeline/.env.example",
        "deployment/waf_benchmark/safeline/start.py",
        "deployment/config/server_integration/nginx.conf",
        "deployment/config/server_integration/apache.conf",
        "deployment/config/server_integration/wad-proxy.service.example",
    ],
    "tests": [
        "tests/test_final_delivery.py", "tests/test_integration.py",
        "tests/test_runtime_api.py", "tests/test_proxy.py",
        "tests/test_demo_ui.py", "tests/test_external_waf.py",
        "tests/test_real_waf.py", "tests/test_full_workflow.py",
    ],
    "documents": [
        "README.md", "docs/README.md", "docs/AI-WAF_report.pdf",
        "docs/SYSTEM_DESIGN.md", "docs/data/DATASET_GUIDE.md",
        "docs/MODEL.md", "docs/TEST_REPORT.md",
        "docs/experiments/REAL_WAF_COMPARISON.md",
    ],
}


def tree_fingerprint(root: Path) -> tuple[int, int, str]:
    digest = hashlib.sha256()
    files = sorted(item for item in root.rglob("*") if item.is_file())
    total = 0
    for path in files:
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest.update(relative.encode("utf-8"))
        digest.update(str(size).encode("ascii"))
        total += size
    return len(files), total, digest.hexdigest()


def _is_complete_waf_report(report: object) -> bool:
    """Return whether a report contains the complete four-system test scope."""

    if not isinstance(report, dict):
        return False
    expected_systems = {
        "final_model",
        "modsecurity_crs_4_28_0",
        "safeline_ce",
        "openappsec_ce",
    }
    dataset = report.get("dataset")
    fairness = report.get("fairness")
    systems = report.get("systems")
    return (
        isinstance(dataset, dict)
        and dataset.get("total") == 34_721
        and isinstance(fairness, dict)
        and fairness.get("complete_independent_test_split") is True
        and isinstance(systems, dict)
        and expected_systems.issubset(systems)
    )


def _select_waf_report(current: dict) -> tuple[dict, str]:
    """Prefer the current report, then its preserved complete report."""

    candidates = [
        (current, "models/current/waf_comparison.json"),
        (
            current.get("cached_report"),
            "models/current/waf_comparison.json#cached_report",
        ),
    ]
    preserved_path = (
        ROOT / "models" / "current" / "waf_comparison.last_verified.json"
    )
    if preserved_path.is_file():
        try:
            candidates.append(
                (
                    json.loads(preserved_path.read_text(encoding="utf-8")),
                    "models/current/waf_comparison.last_verified.json",
                )
            )
        except (OSError, ValueError, TypeError):
            pass
    for candidate, source in candidates:
        if _is_complete_waf_report(candidate):
            return candidate, source
    return current, "models/current/waf_comparison.json"


def main() -> None:
    errors = []
    sections = {}
    waf_report_source = None
    runtime_model_sync = {"status": "NOT_CHECKED", "files": []}
    for section, paths in REQUIRED.items():
        missing = [path for path in paths if not (ROOT / path).is_file()]
        sections[section] = {"required": len(paths), "missing": missing}
        errors.extend(f"{section}: missing {path}" for path in missing)

    count, size, fingerprint = tree_fingerprint(ROOT / "data" / "organized")
    if count != 725 or size != 1_308_030_515:
        errors.append(
            f"organized dataset differs: expected 725/1308030515, got {count}/{size}"
        )

    waf_report_path = ROOT / "models" / "current" / "waf_comparison.json"
    if waf_report_path.is_file():
        try:
            current_waf_report = json.loads(
                waf_report_path.read_text(encoding="utf-8")
            )
            waf_report, waf_report_source = _select_waf_report(
                current_waf_report
            )
            expected_systems = {
                "final_model",
                "modsecurity_crs_4_28_0",
                "safeline_ce",
                "openappsec_ce",
            }
            systems = waf_report.get("systems", {})
            candidates = waf_report.get("candidate_products", {})
            identities = waf_report.get("product_identities", {})
            if waf_report.get("dataset", {}).get("total") != 34_721:
                errors.append("WAF report does not cover 34,721 test records")
            if not waf_report.get("fairness", {}).get(
                "complete_independent_test_split"
            ):
                errors.append("WAF report is not a complete independent test run")
            for key in expected_systems:
                metrics = systems.get(key)
                if not isinstance(metrics, dict):
                    errors.append(f"WAF report missing completed system: {key}")
                    continue
                matrix = metrics.get("confusion_matrix")
                if (
                    not isinstance(matrix, list)
                    or sum(sum(int(value) for value in row) for row in matrix)
                    != 34_721
                ):
                    errors.append(f"WAF system has incomplete confusion matrix: {key}")
            for key in ("safeline_ce", "openappsec_ce"):
                candidate = candidates.get(key, {})
                identity = identities.get(key, {})
                if (
                    candidate.get("status") != "evaluated"
                    or candidate.get("included_in_ranking") is not True
                ):
                    errors.append(f"external WAF is not fully evaluated: {key}")
                if (
                    identity.get("is_actual_product_execution") is not True
                    or identity.get("is_simulation") is not False
                    or identity.get("smoke_gate", {}).get("status") != "passed"
                ):
                    errors.append(f"external WAF identity gate failed: {key}")
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"invalid WAF report: {exc}")

    if not errors:
        verify_model()
        python = shutil.which("python")
        if not python:
            errors.append("restartable python launcher not found")
        else:
            check = subprocess.run(
                [
                    python,
                    str(
                        ROOT
                        / "deployment"
                        / "server_runtime"
                        / "verify_manifest.py"
                    ),
                ],
                cwd=ROOT / "deployment" / "server_runtime",
                text=True,
                capture_output=True,
            )
            if check.returncode:
                errors.append(check.stdout + check.stderr)
            else:
                runtime_model_sync = {"status": "PASS", "files": []}
                for name in (
                    "lgbm_v4.pkl",
                    "text_lr_v4.pkl",
                    "lgbm_v4.meta.json",
                    "model_manifest_v4.json",
                ):
                    source = ROOT / "models" / "current" / name
                    bundled = (
                        ROOT
                        / "deployment"
                        / "server_runtime"
                        / "models"
                        / "current"
                        / name
                    )
                    matches = (
                        source.is_file()
                        and bundled.is_file()
                        and source.stat().st_size == bundled.stat().st_size
                        and hashlib.sha256(source.read_bytes()).digest()
                        == hashlib.sha256(bundled.read_bytes()).digest()
                    )
                    runtime_model_sync["files"].append(
                        {"path": name, "matches_current": matches}
                    )
                    if not matches:
                        runtime_model_sync["status"] = "FAIL"
                        errors.append(
                            "server runtime model differs from current: " + name
                        )

    report = {
        "status": "FAIL" if errors else "PASS",
        "sections": sections,
        "organized_dataset": {
            "files": count,
            "bytes": size,
            "tree_fingerprint": fingerprint,
        },
        "waf_comparison_source": waf_report_source,
        "runtime_model_sync": runtime_model_sync,
        "errors": errors,
    }
    output = ROOT / "runtime" / "verification" / "delivery.json"
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
