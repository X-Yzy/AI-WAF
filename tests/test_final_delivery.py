"""Final delivery smoke tests for separated local and server applications."""

import json
from pathlib import Path
import subprocess
import sys

import run
from fastapi.testclient import TestClient


def test_local_workbench_uses_complete_dashboard_and_dataset():
    from src.local_app import app

    client = TestClient(app)
    home = client.get("/")
    assert home.status_code == 200
    assert "WAD Lab" in home.text
    assert 'data-page="batch"' in home.text
    assert "实时防护" not in home.text

    overview = client.get("/dashboard/overview")
    assert overview.status_code == 200
    organized = overview.json()["datasets"]["organized"]
    assert organized["total"] == 639_984
    assert organized["attack_types"] == 65

    normal_samples = client.get("/dashboard/samples?kind=normal&limit=3")
    assert normal_samples.status_code == 200
    assert len(normal_samples.json()["records"]) == 3


def test_local_single_and_batch_detection():
    from src.local_app import app

    client = TestClient(app)
    single = client.post(
        "/detect",
        json={
            "payload": "<svg onload=alert(1)>",
            "param_location": "body",
            "param_name": "content",
        },
    )
    assert single.status_code == 200
    assert single.json()["verdict"] == "attack"

    batch = client.post(
        "/batch-detect",
        json={
            "items": [
                {
                    "payload": "' OR 1=1 --",
                    "param_location": "query",
                    "param_name": "id",
                },
                {
                    "payload": "machine learning tutorial",
                    "param_location": "query",
                    "param_name": "q",
                },
                {
                    "payload": "SELECT 和 JOIN 的区别是什么？  ",
                    "param_location": "query",
                    "param_name": "value",
                },
                {
                    "payload": "<img src=x onerror=alert(1)>",
                    "param_location": "body",
                    "param_name": "content",
                },
            ]
        },
    )
    assert batch.status_code == 200
    body = batch.json()
    assert body["count"] == 4
    assert [item["verdict"] for item in body["results"]] == [
        "attack",
        "benign",
        "benign",
        "attack",
    ]


def test_server_runtime_loads_validated_models_and_keeps_ops_console():
    from src.runtime_api import app

    client = TestClient(app)
    root = client.get("/")
    assert root.status_code == 200
    assert "AI-WAF 运维控制台" in root.text

    health = client.get("/health")
    assert health.status_code == 200
    body = health.json()
    assert body["lgbm_loaded"] is True
    assert body["text_model_loaded"] is True
    assert body["model_errors"] == []


def test_server_bundle_uses_the_current_model_artifacts():
    root = Path(__file__).resolve().parents[1]
    current = root / "models" / "current"
    bundled = root / "deployment" / "server_runtime" / "models" / "current"

    for name in (
        "lgbm_v4.pkl",
        "text_lr_v4.pkl",
        "lgbm_v4.meta.json",
        "model_manifest_v4.json",
    ):
        assert (bundled / name).read_bytes() == (current / name).read_bytes()


def test_windows_one_click_runtime_script_is_self_contained():
    root = Path(__file__).resolve().parents[1]
    source = (root / "deployment" / "start_monitor_proxy.cmd").read_text(
        encoding="utf-8"
    )
    assert "docker build -t ai-waf-runtime:latest ." in source
    assert "server_runtime_wad-runtime:/app/runtime" in source
    assert "WAD_DASHBOARD_PASSWORD" in source
    assert "http://127.0.0.1:8081/_wad/health" in source


def test_new_one_click_scripts_use_non_conflicting_ports():
    root = Path(__file__).resolve().parents[1]
    visual = (root / "start_visual_ui.cmd").read_text(encoding="utf-8")
    runtime = (root / "deployment" / "start_monitor_proxy.cmd").read_text(
        encoding="utf-8"
    )

    assert "python run.py ui --host %UI_HOST% --port %UI_PORT%" in visual
    assert 'set "UI_PORT=8002"' in visual
    assert "docker build -t ai-waf-runtime:latest ." in runtime
    assert "-p 127.0.0.1:8000:8000" in runtime
    assert "-p 8081:8081" in runtime
    assert "server_runtime_wad-runtime:/app/runtime" in runtime


def test_final_data_audit_accepts_organized_snapshot_without_legacy_builders():
    from training.audit_data import audit

    report = audit(deep=False)
    assert report["status"] == "PASS", report["errors"]
    assert report["organized_view"]["declared"] == 639_984
    assert report["delivery_scope"]["authoritative_dataset"] == "data/organized"
    assert report["delivery_scope"]["organized_snapshot_required"] is True


def test_payload_generator_supports_direct_script_execution(tmp_path):
    root = Path(__file__).resolve().parents[1]
    stdout_path = tmp_path / "generator.stdout.json"
    stderr_path = tmp_path / "generator.stderr.log"
    with (
        stdout_path.open("w", encoding="utf-8") as stdout,
        stderr_path.open("w", encoding="utf-8") as stderr,
    ):
        subprocess.run(
            [
                run.current_python(),
                str(root / "payload_generator" / "cli.py"),
                "' OR 1=1 --",
                "--count",
                "3",
                "--seed",
                "20260729",
            ],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            close_fds=True,
            check=True,
        )
    result = json.loads(stdout_path.read_text(encoding="utf-8"))
    assert result["input"] == "' OR 1=1 --"
    assert len(result["variants"]) == 3
