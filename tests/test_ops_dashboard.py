"""Server operations dashboard aggregation and access-control tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPBasicCredentials

from src import ops_dashboard


def test_runtime_monitor_aggregates_proxy_log_and_heartbeat(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    log_path = tmp_path / "proxy_access.jsonl"
    rows = [
        {
            "timestamp": (now - timedelta(minutes=10)).isoformat(),
            "client_ip": "198.51.100.8",
            "method": "GET",
            "path": "/",
            "mode": "monitor",
            "outcome": "forwarded",
            "threat_count": 0,
            "detection_elapsed_ms": 2,
            "elapsed_ms": 4,
        },
        {
            "timestamp": (now - timedelta(minutes=5)).isoformat(),
            "client_ip": "203.0.113.9",
            "method": "POST",
            "path": "/search",
            "mode": "monitor",
            "outcome": "monitored_attack",
            "threat_count": 1,
            "detection_elapsed_ms": 8,
            "elapsed_ms": 12,
            "threats": [{"name": "id", "rule_hits": ["sqli_union"]}],
        },
    ]
    log_path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )
    (tmp_path / "proxy_status.json").write_text(
        json.dumps({
            "timestamp": now.isoformat(),
            "mode": "monitor",
            "backend": "http://127.0.0.1:8080",
        }),
        encoding="utf-8",
    )
    monkeypatch.setenv("WAD_PROXY_LOG_FILE", str(log_path))

    result = ops_dashboard.RuntimeMonitor(tmp_path).overview(hours=1, event_limit=20)

    assert result["status"] == "online"
    assert result["backend"] == "http://127.0.0.1:8080"
    assert result["summary"] == {
        "requests": 2,
        "attacks": 1,
        "blocked": 0,
        "errors": 0,
        "attack_rate": 50.0,
        "avg_detection_latency_ms": 5.0,
        "p95_detection_latency_ms": 8.0,
    }
    assert result["by_threat"] == {"sqli_union": 1}
    assert result["records"][0]["outcome"] == "monitored_attack"
    assert sum(item["requests"] for item in result["timeline"]) == 2


def test_runtime_monitor_excludes_events_outside_window(tmp_path, monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(days=2)
    log_path = tmp_path / "proxy_access.jsonl"
    log_path.write_text(
        json.dumps({
            "timestamp": old.isoformat(), "method": "GET",
            "outcome": "forwarded", "threat_count": 0, "elapsed_ms": 1,
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("WAD_PROXY_LOG_FILE", str(log_path))

    result = ops_dashboard.RuntimeMonitor(tmp_path).overview(hours=1)

    assert result["status"] == "waiting"
    assert result["summary"]["requests"] == 0


def test_dashboard_basic_auth_is_optional_but_enforced_when_configured(monkeypatch):
    monkeypatch.delenv("WAD_DASHBOARD_PASSWORD", raising=False)
    assert ops_dashboard._authorize(None) is None

    monkeypatch.setenv("WAD_DASHBOARD_USERNAME", "operator")
    monkeypatch.setenv("WAD_DASHBOARD_PASSWORD", "strong-password")
    with pytest.raises(HTTPException) as exc_info:
        ops_dashboard._authorize(None)
    assert exc_info.value.status_code == 401

    credentials = HTTPBasicCredentials(
        username="operator", password="strong-password"
    )
    assert ops_dashboard._authorize(credentials) is None

    monkeypatch.delenv("WAD_DASHBOARD_PASSWORD")
    with pytest.raises(HTTPException) as control_exc:
        ops_dashboard._authorize_control(None)
    assert control_exc.value.status_code == 403


def test_runtime_monitor_writes_proxy_control_atomically(tmp_path, monkeypatch):
    log_path = tmp_path / "proxy_access.jsonl"
    monkeypatch.setenv("WAD_PROXY_LOG_FILE", str(log_path))
    monitor = ops_dashboard.RuntimeMonitor(tmp_path)

    value = monitor.write_control("block", "closed")

    stored = json.loads(
        (tmp_path / "proxy_control.json").read_text(encoding="utf-8")
    )
    assert stored == value
    assert stored["mode"] == "block"
    assert stored["fail_policy"] == "closed"


def test_dashboard_asset_is_self_contained_and_has_operations_views():
    html = ops_dashboard._dashboard_asset.read_text(encoding="utf-8")
    assert "AI-WAF 运维控制台" in html
    assert "运行概览" in html
    assert "安全事件" in html
    assert "在线检测" in html
    assert "/ops/api/overview" in html
    assert "https://" not in html
    assert "http://" not in html
