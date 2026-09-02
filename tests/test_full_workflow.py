"""Regressions for the self-contained local full workflow."""

import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import run
from src.dashboard import JobRequest
from training.evaluate_candidate_pipeline import is_external_source


ROOT = Path(__file__).resolve().parents[1]


def test_layout_validation_uses_only_organized_and_current_models(capsys):
    run.validate_layout(require_models=True)
    output = capsys.readouterr().out
    summary = json.loads(output)

    assert summary["layout"] == "PASS"
    assert summary["dataset"] == "data/organized"
    assert summary["records"] == 639_984
    assert summary["attack_families"] == 65
    assert summary["artifacts"] == 588

    source = inspect.getsource(run.validate_layout)
    for removed_legacy_directory in (
        "all_original_obfuscated",
        "normal_traffic",
        "external_traffic",
        "external_deserialization",
    ):
        assert removed_legacy_directory not in source


def test_full_workflow_runs_all_stages_in_order(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(run, "docker_engine_status", lambda: (True, "ready"))
    monkeypatch.setattr(run, "command_train", lambda _args: calls.append("train"))
    monkeypatch.setattr(run, "command_test", lambda: calls.append("test"))
    monkeypatch.setattr(run, "command_evaluate", lambda: calls.append("evaluate"))
    monkeypatch.setattr(
        run, "command_compare_waf", lambda: calls.append("compare-waf")
    )
    monkeypatch.setattr(
        run, "sync_server_runtime_bundle", lambda: calls.append("build-runtime")
    )

    run.command_all(SimpleNamespace(min_recall=0.95))

    assert calls == ["train", "test", "evaluate", "compare-waf", "build-runtime"]
    assert "全部阶段通过" in capsys.readouterr().out


def test_full_workflow_checks_docker_before_training(monkeypatch):
    calls = []
    monkeypatch.setattr(
        run,
        "docker_engine_status",
        lambda: (False, "Docker engine is not running"),
    )
    monkeypatch.setattr(run, "command_train", lambda _args: calls.append("train"))

    with pytest.raises(SystemExit) as error:
        run.command_all(SimpleNamespace(min_recall=0.95))

    assert "完整流程要求 Docker" in str(error.value)
    assert "train、test 和 evaluate" in str(error.value)

    assert calls == []


def test_external_source_definition_is_explicit():
    assert is_external_source("external_traffic/payloads")
    assert is_external_source("external_traffic/gap_payloads")
    assert is_external_source("external_deserialization/gadget_fields")
    assert is_external_source("modern_attack_traffic")
    assert not is_external_source("all_original_obfuscated")
    assert not is_external_source("enriched_traffic")
    assert not is_external_source("specialized_traffic/payloads")


def test_external_recall_is_present_in_report_and_dashboard():
    report = json.loads(
        (ROOT / "models" / "current" / "pipeline_evaluation.json").read_text(
            encoding="utf-8"
        )
    )
    external = report["external_sources"]
    assert external["records"] > 0
    assert 0 <= external["detected"] <= external["records"]
    assert 0 <= external["recall"] <= 1
    assert report["source_recall"]

    html = (ROOT / "demo" / "index.html").read_text(encoding="utf-8")
    assert "e.external_sources?.recall" in html


def test_train_command_forwards_text_feature_limit(
    tmp_path, monkeypatch
):
    commands = []
    monkeypatch.setattr(run, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(run, "validate_layout", lambda: None)
    monkeypatch.setattr(run, "refresh_model_manifest", lambda: None)
    monkeypatch.setattr(run, "write_waf_status_report", lambda *_args: tmp_path)

    def fake_run_stage(_label, command):
        commands.append(command)
        (tmp_path / "training_results.json").write_text(
            "{}", encoding="utf-8"
        )

    monkeypatch.setattr(run, "run_stage", fake_run_stage)
    run.command_train(
        SimpleNamespace(min_recall=0.95, max_text_features=60_000)
    )

    command = commands[0]
    index = command.index("--max-text-features")
    assert command[index + 1] == "60000"


def test_dashboard_and_cli_share_the_same_recall_default():
    assert JobRequest(action="all").min_recall == 0.95
    parsed = run.build_parser().parse_args(["all"])
    assert parsed.min_recall == 0.95


def test_test_command_uses_a_fresh_windows_safe_basetemp(monkeypatch):
    commands = []
    monkeypatch.setattr(run, "validate_layout", lambda require_models=False: None)
    monkeypatch.setattr(run, "sync_server_runtime_bundle", lambda: None)
    monkeypatch.setattr(run, "run_stage", lambda _label, command: commands.append(command))
    monkeypatch.setattr(run.os, "getpid", lambda: 1234)
    timestamps = iter((100, 200))
    monkeypatch.setattr(run.time, "time_ns", lambda: next(timestamps))

    run.command_test()
    run.command_test()

    first = commands[0][commands[0].index("--basetemp") + 1]
    second = commands[1][commands[1].index("--basetemp") + 1]
    assert first.endswith("pytest_runs\\run-1234-100")
    assert second.endswith("pytest_runs\\run-1234-200")
    assert first != second
