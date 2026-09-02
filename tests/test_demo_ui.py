"""Static regressions for the original-style local experiment dashboard."""

from pathlib import Path

from fastapi.testclient import TestClient

import run

from src import app as local_app
from src import runtime_api


HTML = (Path(__file__).resolve().parents[1] / "demo" / "index.html").read_text(
    encoding="utf-8"
)


def test_local_and_server_dashboards_are_isolated():
    assert local_app.app is not runtime_api.app

    local_response = TestClient(local_app.app).get("/")
    server_response = TestClient(runtime_api.app).get("/")

    assert local_response.status_code == 200
    assert server_response.status_code == 200
    assert "WAD Lab" in local_response.text
    assert "AI-WAF 运维控制台" not in local_response.text
    assert "AI-WAF 运维控制台" in server_response.text



def test_local_dashboard_favicon_does_not_create_console_404():
    response = TestClient(local_app.app).get("/favicon.ico")
    assert response.status_code == 204


def test_local_dashboard_keeps_original_pages_and_visual_identity():
    for page in ("overview", "data", "models", "results", "detect"):
        assert f'data-page="{page}"' in HTML
        assert f'id="page-{page}"' in HTML
    assert "WAD Lab" in HTML
    assert "--normal-end" in HTML
    assert "--original-end" in HTML
    assert "data-browser-layout" in HTML
    assert "sample-table-wrap" in HTML and "max-height:610px" in HTML
    assert '<col style="width:27%"><col style="width:73%">' in HTML
    assert "limit:'14'" in HTML


def test_local_dashboard_excludes_server_only_live_protection():
    assert "data-page='monitor'" not in HTML
    assert 'data-page="monitor"' not in HTML
    assert "page-monitor" not in HTML
    assert "实时防护" not in HTML
    assert "loadProxyActivity" not in HTML
    assert "/dashboard/proxy/activity" not in HTML


def test_batch_detection_page_uses_existing_design_system():
    assert 'data-page="batch"' in HTML
    assert 'id="page-batch"' in HTML
    assert 'class="grid detect-layout"' in HTML
    assert 'id="batchInput"' in HTML
    assert 'id="batchRows"' in HTML
    assert "/batch-detect" in HTML
    assert "单次最多 100 条" in HTML


def test_detect_samples_set_their_http_field_context():
    assert "location:'body',name:'content'" in HTML
    assert "$('detectLocation').value=sample.location" in HTML
    assert "$('detectName').value=sample.name" in HTML


def test_attack_distribution_still_summarizes_long_tail():
    assert "entries.slice(0,20)" in HTML
    assert "其余低频攻击类型摘要" in HTML
    assert "中低频类型" in HTML
    assert "稀少类型" in HTML


def test_attack_type_heat_cells_remain_flat():
    assert ".heat-cell" in HTML and "box-shadow:none" in HTML
    assert "box-shadow:inset 3px 0 rgba(56,217,197" not in HTML


def test_ui_command_is_available_with_safe_local_defaults():
    args = run.build_parser().parse_args(["ui"])
    assert args.command == "ui"
    assert args.host == "127.0.0.1"
    assert args.port == 8000


def test_ui_command_starts_the_local_dashboard(monkeypatch):
    captured = {}
    monkeypatch.setattr(run, "validate_layout", lambda require_models=False: None)

    def fake_run_stage(label, command):
        captured["label"] = label
        captured["command"] = command

    monkeypatch.setattr(run, "run_stage", fake_run_stage)
    args = run.build_parser().parse_args(
        ["ui", "--host", "0.0.0.0", "--port", "9000"]
    )
    run.command_ui(args)

    assert captured["label"] == "启动本地可视化界面"
    assert "src.local_app:app" in captured["command"]
    assert captured["command"][-4:] == ["--host", "0.0.0.0", "--port", "9000"]


def test_cached_mode_hides_unmeasured_candidate_rows():
    assert "const statusRows=" not in HTML
    assert "尚未接入真实产品，本次不参与排名" not in HTML
    assert "尚未接入" not in HTML
    assert "完整 WAF 产品评测正在生成" in HTML


def test_full_workflow_uses_the_delivery_recall_default():
    assert 'id="jobRecall" type="number" min="0.8" max="1" step="0.01" value="0.95"' in HTML
    assert "仅显示具有完整指标的系统" in HTML


def test_full_workflow_progress_does_not_jump_on_manifest_pass():
    from src.dashboard import DashboardService

    progress, stage = DashboardService._progress(
        "all", '  "status": "PASS",', 68
    )
    assert progress == 68
    assert stage == "任务运行中"

    progress, stage = DashboardService._progress(
        "validate-data", '  "status": "PASS",', 50
    )
    assert progress == 96
    assert stage == "数据审计通过"


def test_organized_evaluation_stage_updates_live_progress():
    from src.dashboard import DashboardService

    progress, stage = DashboardService._progress(
        "all", "=== 独立 organized 测试集与性能验证 ===", 78
    )
    assert progress == 82
    assert stage == "运行独立验证与性能评测"


def test_delivery_gates_are_computed_from_report_metrics():
    from src.dashboard import evaluation_gates

    passing = evaluation_gates(
        {
            "metrics": {"fpr": 0.001, "recall": 0.97},
            "external_sources": {"recall": 0.90},
            "latency_ms": {"p99": 10.0},
        }
    )
    failing = evaluation_gates(
        {
            "metrics": {"fpr": 0.002, "recall": 0.96},
            "external_sources": {"recall": 0.89},
            "latency_ms": {"p99": 10.01},
        }
    )

    assert all(passing.values())
    assert not any(failing.values())


def test_root_docker_image_contains_real_dashboard_job_dependencies():
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (root / ".dockerignore").read_text(encoding="utf-8")
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")

    assert "COPY --chown=appuser:appuser . ." in dockerfile
    assert "training/" not in dockerignore
    assert "tests/" not in dockerignore
    assert "data/" not in dockerignore.splitlines()
    assert "data/archives/" in dockerignore
    assert "./models/current:/app/models/current\n" in compose
    assert "./models/current:/app/models/current:ro" in compose
    assert 'user: "${WAD_LAB_USER:-0:0}"' in compose
    assert "${WAD_UI_BIND:-127.0.0.1}" in compose
    assert "${WAD_UI_PUBLISH_PORT:-18089}" in compose
    assert '["uvicorn", "src.runtime_api:app"' in compose
    assert "/var/run/docker.sock" not in compose
    assert "${WAD_PROXY_BIND:-127.0.0.1}" in compose

