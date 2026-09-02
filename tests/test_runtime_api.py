"""纯服务器运行时 API 与最小部署包回归测试。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi.testclient import TestClient

from src import runtime_api


class _Request:
    def __init__(self, body: bytes):
        self._body = body

    async def body(self) -> bytes:
        return self._body


def test_runtime_health_and_models_are_ready():
    result = runtime_api.health()
    assert result["status"] == "ok"
    assert result["lgbm_loaded"] is True
    assert result["text_model_loaded"] is True


def test_runtime_detects_benign_and_attack_payloads():
    benign = runtime_api.detect(runtime_api.DetectRequest(
        payload="hello world", param_location="query", param_name="q"
    ))
    attack = runtime_api.detect(runtime_api.DetectRequest(
        payload="' OR 1=1 --", param_location="query", param_name="id"
    ))
    assert benign.verdict == "benign"
    assert attack.verdict == "attack"


def test_runtime_detect_http_blocks_protocol_ambiguity():
    request = _Request(
        b"POST / HTTP/1.1\r\nContent-Length: 3\r\n"
        b"Transfer-Encoding: chunked\r\n\r\nabc"
    )
    response = asyncio.run(runtime_api.detect_http(request))
    assert response.verdict == "attack"
    assert response.params[0]["rule_hits"] == ["CL_TE_ambiguity"]


def test_stats_reset_requires_the_operations_password(monkeypatch):
    client = TestClient(runtime_api.app)
    monkeypatch.delenv("WAD_DASHBOARD_PASSWORD", raising=False)
    assert client.post("/stats/reset").status_code == 403

    monkeypatch.setenv("WAD_DASHBOARD_USERNAME", "operator")
    monkeypatch.setenv("WAD_DASHBOARD_PASSWORD", "strong-password")
    assert client.post(
        "/stats/reset", auth=("operator", "strong-password")
    ).status_code == 200


def test_generated_runtime_bundle_excludes_development_assets():
    root = Path(__file__).resolve().parents[1] / "deployment" / "server_runtime"
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    paths = {item["path"] for item in manifest["files"]}
    forbidden = ("data/", "training/", "tests/", "lab/", "payload_generator/", "demo/")
    assert not any(path.startswith(forbidden) for path in paths)
    assert "src/dashboard.py" not in paths
    assert "src/runtime_api.py" in paths
    assert "src/ops_dashboard.py" in paths
    assert "src/ops_dashboard.html" in paths
    assert "src/proxy.py" in paths
    assert "models/current/lgbm_v4.pkl" in paths
    assert "models/current/text_lr_v4.pkl" in paths


def test_runtime_bundle_defaults_to_aliyun_dependency_mirrors():
    root = Path(__file__).resolve().parents[1] / "deployment"
    dockerfile = (root / "Dockerfile.runtime").read_text(encoding="utf-8")
    compose = (root / "compose.bundle.yml").read_text(encoding="utf-8")
    env_example = (root / "runtime.env.example").read_text(encoding="utf-8")

    for content in (dockerfile, compose, env_example):
        assert "https://mirrors.aliyun.com/pypi/simple/" in content
        assert "https://mirrors.aliyun.com/debian" in content
        assert "https://mirrors.aliyun.com/debian-security" in content
    assert "/etc/apt/sources.list.d/debian.sources" in dockerfile
    assert "deb." + "debian.org" not in dockerfile
    assert "security." + "debian.org" not in dockerfile
