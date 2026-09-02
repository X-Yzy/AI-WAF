"""Regression tests for the unified project entrypoint."""

from pathlib import Path

import deployment.build_runtime_bundle as runtime_bundle
import run
from run import manifest_record_count


def test_manifest_record_count_supports_all_project_schemas():
    assert manifest_record_count({"total": 9_040}) == 9_040
    assert manifest_record_count({"total_records": 913}) == 913
    assert manifest_record_count({"generated_records": 59_583}) == 59_583
    assert manifest_record_count({"records": 269}) == 269
    assert manifest_record_count({
        "attack_types": {
            "sqli": {"records": 200},
            "xss": {"records": 200},
        }
    }) == 400
    assert manifest_record_count({"counts": {"train": 8, "test": 2}}) == 10
    assert manifest_record_count({"dataset": "missing-count"}) == "未声明"


def test_run_stage_passes_resolved_python_to_nested_process(monkeypatch):
    captured = {}
    monkeypatch.delenv("WAD_PYTHON", raising=False)
    monkeypatch.setattr(
        run.subprocess,
        "run",
        lambda *args, **kwargs: captured.update(kwargs),
    )

    run.run_stage("test", ["resolved-python", "child.py"])

    assert captured["env"]["WAD_PYTHON"] == "resolved-python"


def test_test_command_uses_project_runtime_for_temporary_files(monkeypatch):
    captured = []
    events = []

    def fake_validate(require_models=False):
        events.append(("布局校验", require_models))

    def fake_run_stage(label, command):
        events.append((label, None))
        captured.append((label, command))

    monkeypatch.setattr(run, "validate_layout", fake_validate)
    monkeypatch.setattr(run, "run_stage", fake_run_stage)

    run.command_test()

    assert events == [
        ("布局校验", True),
        ("同步并验证服务器交付运行包", None),
        ("单元测试与集成测试", None),
    ]
    assert [label for label, _command in captured] == [
        "同步并验证服务器交付运行包",
        "单元测试与集成测试",
    ]
    pytest_command = captured[-1][1]
    index = pytest_command.index("--basetemp")
    basetemp = Path(pytest_command[index + 1])
    assert basetemp.parent == run.ROOT / "runtime" / "pytest_runs"
    assert basetemp.name.startswith("run-")
    assert pytest_command[-1] == "tests"


def test_current_python_does_not_silently_switch_to_project_venv(
    tmp_path, monkeypatch
):
    global_python = tmp_path / "global" / "python"
    project_venv = tmp_path / ".venv" / "bin" / "python"
    global_python.parent.mkdir()
    project_venv.parent.mkdir(parents=True)
    global_python.touch()
    project_venv.touch()
    monkeypatch.delenv("WAD_PYTHON", raising=False)
    monkeypatch.setattr(run, "ROOT", tmp_path)
    monkeypatch.setattr(run.sys, "executable", str(global_python))
    monkeypatch.setattr(run.shutil, "which", lambda _name: None)

    assert run.current_python() == str(global_python)


def test_restartable_python_prefers_explicit_launcher(monkeypatch):
    monkeypatch.setenv("WAD_PYTHON", r"C:\Python\bin\python.exe")

    assert runtime_bundle.restartable_python() == r"C:\Python\bin\python.exe"


def test_restartable_python_detects_python_manager_wrapper(tmp_path, monkeypatch):
    internal = tmp_path / "pythoncore-3.14-64" / "python.exe"
    wrapper = tmp_path / "bin" / "python.exe"
    internal.parent.mkdir()
    wrapper.parent.mkdir()
    internal.touch()
    wrapper.touch()
    monkeypatch.delenv("WAD_PYTHON", raising=False)
    monkeypatch.setattr(runtime_bundle.sys, "executable", str(internal))

    assert runtime_bundle.restartable_python() == str(wrapper)


def test_runtime_validation_uses_launcher_and_preserves_system_env(
    tmp_path, monkeypatch
):
    launcher = r"C:\Python\bin\python.exe"
    captured = {}
    monkeypatch.setenv("WAD_PYTHON", launcher)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(
        runtime_bundle.subprocess,
        "run",
        lambda command, **kwargs: captured.update(command=command, **kwargs),
    )

    runtime_bundle._validate(tmp_path)

    assert captured["command"][0] == launcher
    # Windows environment-variable names are case-insensitive and CPython may
    # expose this key as either SystemRoot or SYSTEMROOT after copying it.
    normalized_env = {
        key.casefold(): value for key, value in captured["env"].items()
    }
    assert normalized_env["systemroot"] == r"C:\Windows"
    assert captured["env"]["PYTHONPATH"] == str(tmp_path)
    assert captured["env"]["PYTHONDONTWRITEBYTECODE"] == "1"


def test_runtime_docker_uses_reachable_pinned_sources():
    dockerfile = (
        runtime_bundle.DEPLOYMENT_ROOT / "Dockerfile.runtime"
    ).read_text(encoding="utf-8")
    compose = (
        runtime_bundle.DEPLOYMENT_ROOT / "compose.bundle.yml"
    ).read_text(encoding="utf-8")
    environment = (
        runtime_bundle.DEPLOYMENT_ROOT / "runtime.env.example"
    ).read_text(encoding="utf-8")
    deployment_text = "\n".join((dockerfile, compose, environment))

    assert "python:3.12-slim-bookworm" in deployment_text
    assert "https://mirrors.aliyun.com/debian" in dockerfile
    assert "https://mirrors.aliyun.com/debian-security" in dockerfile
    assert "https://mirrors.aliyun.com/pypi/simple/" in dockerfile
    assert "rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*" in dockerfile
    assert "deb.debian.org" not in deployment_text
    assert "security.debian.org" not in deployment_text
    assert "pypi.org" not in deployment_text
    assert "docker.m.daocloud.io" not in deployment_text
    assert "no-new-privileges:true" in compose
    assert "apparmor=" not in compose
