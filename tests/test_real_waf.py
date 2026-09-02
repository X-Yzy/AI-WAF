"""Regression tests for the real ModSecurity + OWASP CRS experiment."""

from __future__ import annotations

import json
from pathlib import Path

from training import real_waf
from training.real_waf import (
    DEFAULT_IMAGE,
    PRODUCT_KEY,
    ModSecurityCRSProduct,
    ProductDecision,
    RealWAFError,
    ResilientModSecurityCRSProduct,
    build_product_request,
)


ROOT = Path(__file__).resolve().parents[1]


def test_official_product_version_is_fixed() -> None:
    assert DEFAULT_IMAGE == "owasp/modsecurity-crs:4.28.0-nginx-202607160307"
    product = ModSecurityCRSProduct(pull="never")
    try:
        identity = product.identity()
    finally:
        product.close()
    assert identity["is_actual_product_execution"] is True
    assert identity["is_simulation"] is False
    assert identity["configuration"]["blocking_paranoia"] == 1
    assert identity["configuration"]["inbound_anomaly_threshold"] == 5


def test_query_payload_is_sent_as_real_http_argument() -> None:
    request = build_product_request(
        {
            "payload": "%2531+union+select",
            "param_location": "query",
            "param_name": "q",
        },
        "token",
    )
    assert request.method == "GET"
    assert request.carrier == "query"
    assert request.target.startswith("/benchmark?q=")
    assert "%252531%2Bunion%2Bselect" in request.target


def test_unsafe_header_has_explicit_body_fallback() -> None:
    request = build_product_request(
        {
            "payload": "safe\r\nX-Injected: yes",
            "param_location": "header",
            "param_name": "X-Test",
        },
        "token",
    )
    assert request.carrier == "body_fallback"
    assert request.fallback_reason
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_filename_uses_multipart_request() -> None:
    request = build_product_request(
        {
            "payload": "shell.php",
            "param_location": "filename",
            "param_name": "file",
        },
        "token",
    )
    assert request.method == "POST"
    assert request.carrier == "filename"
    assert request.headers["Content-Type"].startswith("multipart/form-data;")
    assert b"filename*=UTF-8''shell.php" in (request.body or b"")


def test_active_workflow_uses_real_product_entrypoint() -> None:
    source = (ROOT / "run.py").read_text(encoding="utf-8")
    assert 'training" / "compare_real_waf.py' in source
    assert 'training" / "compare_waf.py' not in source
    assert not (ROOT / "src" / "waf_profiles.py").exists()


def test_current_report_proves_real_product_execution() -> None:
    report = json.loads(
        (ROOT / "models" / "current" / "waf_comparison.json").read_text(
            encoding="utf-8"
        )
    )
    assert report["schema"] in {
        "final_model_vs_real_waf_product_v3",
        "final_model_vs_real_waf_products_v4",
        "final_model_vs_real_waf_products_v5",
    }
    if report.get("systems"):
        assert report["system_order"][:2] == ["final_model", PRODUCT_KEY]
        assert report["baseline_identity"]["is_actual_product_execution"] is True
        assert report["baseline_identity"]["is_simulation"] is False
        assert report["fairness"]["complete_independent_test_split"] is True
        assert report["dataset"]["total"] == 34_721
    else:
        assert report["system_order"] == []
        assert report["benchmark_status"]["completed"] is False
        assert report["candidate_products"][PRODUCT_KEY]["included_in_ranking"] is False


def test_resilient_product_reuses_one_backend_across_container_restart(
    monkeypatch,
) -> None:
    instances = []

    class FakeProduct:
        def __init__(self, *, backend, **_kwargs):
            self.backend = backend
            self.container_name = f"fake-{len(instances) + 1}"
            self.status_counts = {}
            self.closed = False
            instances.append(self)

        def start(self):
            return None

        def inspect(self, _record):
            if self is instances[0]:
                raise RealWAFError("transient transport timeout")
            return ProductDecision(False, True, 204, 1.0)

        def identity(self):
            return {"name": "fake", "is_actual_product_execution": True}

        def close(self):
            self.closed = True

    monkeypatch.setattr(real_waf, "ModSecurityCRSProduct", FakeProduct)
    product = ResilientModSecurityCRSProduct(start_retry_delay=0)
    try:
        product.start()
        decision = product.inspect(
            {
                "id": "record-1",
                "label": 0,
                "payload": "normal",
                "param_location": "query",
            }
        )
        assert decision.reached_backend is True
        assert len(instances) == 2
        assert instances[0].backend is instances[1].backend is product.backend
        assert instances[0].closed is True
        assert product.execution_summary()["audited_restarts"] == 1
    finally:
        product.close()


def test_resilient_product_retries_transient_container_start_failure(
    monkeypatch,
) -> None:
    instances = []

    class FakeProduct:
        def __init__(self, *, backend, **_kwargs):
            self.backend = backend
            self.container_name = f"startup-{len(instances) + 1}"
            self.status_counts = {}
            instances.append(self)

        def start(self):
            if self is instances[0]:
                raise RealWAFError("temporary 502 while Docker networking settles")

        def identity(self):
            return {"name": "fake", "is_actual_product_execution": True}

        def close(self):
            return None

    monkeypatch.setattr(real_waf, "ModSecurityCRSProduct", FakeProduct)
    product = ResilientModSecurityCRSProduct(
        max_start_attempts=2,
        start_retry_delay=0,
    )
    try:
        product.start()
        assert len(instances) == 2
        assert instances[0].backend is instances[1].backend is product.backend
        summary = product.execution_summary()
        assert len(summary["startup_failures"]) == 1
        assert "temporary 502" in summary["startup_failures"][0]["error"]
    finally:
        product.close()
