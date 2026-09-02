"""Regression tests for SafeLine/open-appsec real endpoint integration."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
from subprocess import CompletedProcess
import threading
from contextlib import nullcontext

import pytest

import run
from deployment.waf_benchmark.openappsec import start as openappsec_start

from training.external_waf import (
    ExternalProductSpec,
    ExternalReverseProxyWAF,
    OPENAPPSEC_KEY,
    SAFELINE_KEY,
    candidate_statuses,
)


ROOT = Path(__file__).resolve().parents[1]


def test_openappsec_start_recovers_a_stale_nginx_pid(monkeypatch):
    calls: list[list[str]] = []
    return_codes = iter((1, 0, 0))

    def fake_run(arguments: list[str], *, check: bool = True):
        calls.append(arguments)
        return CompletedProcess(
            arguments,
            next(return_codes),
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(openappsec_start, "run", fake_run)
    openappsec_start.wait_nginx_ready(0.1)

    recovery = calls[1]
    assert recovery[-2:] == [
        "-c",
        openappsec_start.NGINX_RECOVERY_COMMAND,
    ]


def _complete_report(total: int = 34721) -> dict:
    systems = {
        "final_model": {"f1": 0.98, "recall": 0.97},
        "modsecurity_crs_4_28_0": {"f1": 0.45, "recall": 0.52},
        SAFELINE_KEY: {"f1": 0.70, "recall": 0.57},
        OPENAPPSEC_KEY: {"f1": 0.43, "recall": 0.77},
    }
    return {
        "schema": "test_complete",
        "generated_at": "2026-07-29T10:29:12+00:00",
        "dataset": {"split": "test", "total": total},
        "system_order": list(systems),
        "systems": systems,
        "fairness": {"complete_independent_test_split": True},
        "candidate_products": {
            key: {
                "status": "evaluated",
                "configured": True,
                "included_in_ranking": True,
            }
            for key in (SAFELINE_KEY, OPENAPPSEC_KEY)
        },
        "product_identities": {
            key: {
                "is_actual_product_execution": True,
                "is_simulation": False,
            }
            for key in (SAFELINE_KEY, OPENAPPSEC_KEY)
        },
    }


class _FakeWAFHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if "UNION" in self.path.upper():
            self.send_response(403)
            self.send_header("Content-Length", "0")
        else:
            self.send_response(204)
            self.send_header("X-WAD-Benchmark-Backend", "reached")
            self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *args) -> None:
        return


def _spec(endpoint: str) -> ExternalProductSpec:
    return ExternalProductSpec(
        key=SAFELINE_KEY,
        name="SafeLine 社区版 test",
        endpoint=endpoint,
        version="test",
        project_url="https://github.com/chaitin/SafeLine",
        deployment_note="test",
    )


def test_unconfigured_products_never_receive_fake_metrics() -> None:
    statuses = candidate_statuses({})
    assert set(statuses) == {SAFELINE_KEY, OPENAPPSEC_KEY}
    assert all(item["status"] == "not_configured" for item in statuses.values())
    assert all(item["included_in_ranking"] is False for item in statuses.values())
    assert all("reason" in item for item in statuses.values())


def test_external_product_requires_real_allow_and_block_proofs() -> None:
    server = HTTPServer(("127.0.0.1", 0), _FakeWAFHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with ExternalReverseProxyWAF(_spec(endpoint)) as product:
            allowed = product.inspect(
                {
                    "payload": "ordinary product search",
                    "param_location": "query",
                    "param_name": "q",
                }
            )
            blocked = product.inspect(
                {
                    "payload": "' UNION SELECT secret FROM users--",
                    "param_location": "query",
                    "param_name": "q",
                }
            )
            assert allowed.reached_backend is True
            assert allowed.blocked is False
            assert blocked.reached_backend is False
            assert blocked.blocked is True
            assert product.identity()["is_simulation"] is False
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_workflow_and_ui_expose_external_products_honestly() -> None:
    run_source = (ROOT / "run.py").read_text(encoding="utf-8")
    compare_source = (
        ROOT / "training" / "compare_external_wafs.py"
    ).read_text(encoding="utf-8")
    html = (ROOT / "demo" / "index.html").read_text(encoding="utf-8")

    assert "compare-external-waf" in run_source
    assert 'str(ROOT / "training" / "compare_external_wafs.py")' in run_source
    assert '"performance_based_exclusion": False' in compare_source
    assert "products_outperforming_final" in compare_source
    assert "SafeLine 社区版" in html
    assert "open-appsec 社区版" in html
    assert "不能因为优于当前模型而删除" in html
    assert "缓存" not in html
    assert "Docker服务未启动，本次真实产品实验未运行" not in html
    assert "不代表当前重新训练模型" not in html
    assert "cached_report" in html
    assert "usingCache" in html

def test_missing_docker_fails_the_complete_workflow_without_publishing_report(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(run, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(run, "validate_layout", lambda require_models=False: None)
    monkeypatch.setattr(
        run,
        "docker_engine_status",
        lambda: (False, "Docker Desktop engine is not running"),
    )
    with pytest.raises(SystemExit, match="完整流程要求 Docker"):
        run.command_compare_waf()

    assert not (tmp_path / run.WAF_REPORT_NAME).exists()


def test_complete_report_is_preserved_and_attached_as_cache(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(run, "MODEL_DIR", tmp_path)
    complete = _complete_report()
    (tmp_path / run.WAF_REPORT_NAME).write_text(
        json.dumps(complete, ensure_ascii=False),
        encoding="utf-8",
    )

    cache_path = run.cache_verified_waf_report()
    assert cache_path == tmp_path / run.WAF_CACHE_NAME
    cached = json.loads(cache_path.read_text(encoding="utf-8"))
    assert cached["systems"] == complete["systems"]
    assert cached["cache_metadata"]["status"] == "last_verified"
    assert "不代表当前模型结果" in cached["cache_metadata"]["warning"]

    run.write_waf_status_report("docker_unavailable", "daemon offline")
    current = json.loads(
        (tmp_path / run.WAF_REPORT_NAME).read_text(encoding="utf-8")
    )
    assert current["benchmark_status"]["status"] == "docker_unavailable"
    assert current["systems"] == {}
    assert current["cached_report"]["dataset"]["total"] == 34721
    assert "final_model" in current["cached_report"]["systems"]


def test_partial_report_never_overwrites_verified_cache(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(run, "MODEL_DIR", tmp_path)
    valid_cache = _complete_report(total=10)
    cache_path = tmp_path / run.WAF_CACHE_NAME
    cache_path.write_text(json.dumps(valid_cache), encoding="utf-8")
    partial = {
        "dataset": {"total": 10},
        "systems": {"safeline_ce": {"f1": 0.7}},
    }
    reduced_complete = {
        "dataset": {"total": 10},
        "systems": {
            "final_model": {"f1": 0.9},
            "modsecurity_crs_4_28_0": {"f1": 0.4},
        },
    }

    assert run.cache_verified_waf_report(partial) is None
    assert run.cache_verified_waf_report(reduced_complete) is None
    assert json.loads(cache_path.read_text(encoding="utf-8")) == valid_cache


def test_compare_waf_starts_both_products_and_publishes_only_complete_report(
    tmp_path, monkeypatch
) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    calls: list[list[str]] = []
    monkeypatch.setattr(run, "ROOT", tmp_path)
    monkeypatch.setattr(run, "MODEL_DIR", model_dir)
    monkeypatch.setattr(run, "validate_layout", lambda require_models=False: None)
    monkeypatch.setattr(run, "docker_engine_status", lambda: (True, "ready"))
    monkeypatch.setattr(run, "benchmark_proof_backend", lambda: nullcontext())
    monkeypatch.setattr(run, "refresh_model_manifest", lambda: None)
    monkeypatch.setattr(run, "cache_verified_waf_report", lambda report=None: None)

    def fake_run_stage(_label: str, command: list[str]) -> None:
        calls.append(command)
        if "compare_external_wafs.py" in command[1]:
            report_path = Path(command[command.index("--report") + 1])
            report_path.write_text(
                json.dumps(_complete_report(), ensure_ascii=False),
                encoding="utf-8",
            )

    monkeypatch.setattr(run, "run_stage", fake_run_stage)
    run.command_compare_waf()

    external = next(command for command in calls if "compare_external_wafs.py" in command[1])
    modsecurity = next(command for command in calls if "compare_real_waf.py" in command[1])
    assert "--safeline-url" in external
    assert "--openappsec-url" in external
    assert "--no-resume" not in external
    assert "--no-resume" not in modsecurity
    assert any("safeline" in command[1] and "start.py" in command[1] for command in calls)
    assert any("openappsec" in command[1] and "start.py" in command[1] for command in calls)
    assert run._is_complete_waf_report(
        json.loads((model_dir / run.WAF_REPORT_NAME).read_text(encoding="utf-8"))
    )
    assert not (tmp_path / "runtime" / "waf_comparison.building.json").exists()


def test_verified_product_results_are_rebased_to_current_model_metrics() -> None:
    verified = json.loads(
        (ROOT / "models" / "current" / run.WAF_CACHE_NAME).read_text(
            encoding="utf-8"
        )
    )
    evaluation = json.loads(
        (ROOT / "models" / "current" / "pipeline_evaluation.json").read_text(
            encoding="utf-8"
        )
    )

    report = run.compose_current_model_waf_report(
        verified,
        evaluation,
        generated_at="2026-07-31T00:00:00+00:00",
    )

    assert report["schema"] == "final_model_vs_real_waf_products_v5"
    assert report["systems"]["final_model"]["f1"] == evaluation["metrics"]["f1"]
    assert report["systems"]["final_model"]["confusion_matrix"] == evaluation[
        "metrics"
    ]["confusion_matrix"]
    assert report["attack_form_recall"]["original"]["final_model"] == evaluation[
        "representation_recall"
    ]["original"]
    assert report["attack_type_recall"]["sqli"]["final_model"] == evaluation[
        "type_recall"
    ]["sqli"]
    assert report["systems"]["safeline_ce"] == verified["systems"]["safeline_ce"]
    assert report["report_provenance"]["same_organized_test_split_verified"] is True
    assert "cache_metadata" not in report


def test_external_product_allows_bounded_cold_start_warmup() -> None:
    class _AdaptiveHandler(BaseHTTPRequestHandler):
        attacks = 0

        def do_GET(self) -> None:
            if "UNION" in self.path.upper():
                type(self).attacks += 1
                if type(self).attacks >= 3:
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                else:
                    self.send_response(204)
                    self.send_header("X-WAD-Benchmark-Backend", "reached")
                    self.send_header("Content-Length", "0")
            else:
                self.send_response(204)
                self.send_header("X-WAD-Benchmark-Backend", "reached")
                self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *args) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _AdaptiveHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with ExternalReverseProxyWAF(
            _spec(endpoint),
            smoke_max_attempts=5,
            smoke_retry_delay=0,
        ) as product:
            gate = product.identity()["smoke_gate"]
            assert gate["status"] == "passed"
            assert gate["attack_attempts"] == 3
            assert gate["bounded_warmup"] is True
            assert gate["evaluation_records_used_for_warmup"] == 0
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_external_product_retries_transient_5xx_without_counting_it_as_block() -> None:
    class _TransientHandler(BaseHTTPRequestHandler):
        calls = 0

        def do_GET(self) -> None:
            type(self).calls += 1
            if type(self).calls == 1:
                self.send_response(502)
            else:
                self.send_response(204)
                self.send_header("X-WAD-Benchmark-Backend", "reached")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *args) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _TransientHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    product = ExternalReverseProxyWAF(
        _spec(endpoint),
        smoke_retry_delay=0,
        transient_retry_delay=0,
    )
    product.started = True
    try:
        decision = product.inspect(
            {
                "payload": "ordinary retry probe",
                "param_location": "query",
                "param_name": "q",
            }
        )
        assert decision.blocked is False
        assert decision.reached_backend is True
        assert _TransientHandler.calls == 2
    finally:
        product.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

def test_external_product_rejects_persistent_5xx_after_bounded_retries() -> None:
    class _BrokenHandler(BaseHTTPRequestHandler):
        calls = 0

        def do_GET(self) -> None:
            type(self).calls += 1
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *args) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _BrokenHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    product = ExternalReverseProxyWAF(
        _spec(endpoint),
        transient_max_attempts=4,
        transient_retry_delay=0,
    )
    product.started = True
    try:
        try:
            product.inspect(
                {
                    "payload": "ordinary persistent failure probe",
                    "param_location": "query",
                    "param_name": "q",
                }
            )
        except Exception as exc:
            assert "returned 502" in str(exc)
        else:
            raise AssertionError("persistent 502 must never count as a WAF block")
        assert _BrokenHandler.calls == 4
        assert product.execution_summary()["status_codes"]["502"] == 4
    finally:
        product.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_completed_external_product_survives_single_product_followup() -> None:
    from training.compare_external_wafs import merged_candidate_statuses

    previous = {
        "systems": {
            OPENAPPSEC_KEY: {
                "recall": 0.8,
                "precision": 0.7,
                "f1": 0.75,
            }
        },
        "product_identities": {
            OPENAPPSEC_KEY: {
                "version": "1.1.35-open-source",
                "is_actual_product_execution": True,
            }
        },
        "candidate_products": {
            OPENAPPSEC_KEY: {
                "display_name": "open-appsec 社区版",
                "configured": True,
                "status": "evaluated",
                "included_in_ranking": True,
                "reason": "completed",
            }
        },
    }
    safeline = _spec("http://127.0.0.1:18082")
    statuses = merged_candidate_statuses(previous, {SAFELINE_KEY: safeline})

    cached = statuses[OPENAPPSEC_KEY]
    assert cached["status"] == "evaluated"
    assert cached["included_in_ranking"] is True
    assert cached["configured"] is False
    assert cached["result_origin"] == "last_completed_full_run"
    assert statuses[SAFELINE_KEY]["configured"] is True


def test_external_product_retries_incomplete_http_response() -> None:
    class _ProtocolFlapHandler(BaseHTTPRequestHandler):
        calls = 0

        def do_GET(self) -> None:
            type(self).calls += 1
            if type(self).calls == 1:
                self.send_response(200)
                self.send_header("X-WAD-Benchmark-Backend", "reached")
                self.send_header("Content-Length", "20")
                self.end_headers()
                self.wfile.write(b"short")
                self.close_connection = True
            else:
                self.send_response(204)
                self.send_header("X-WAD-Benchmark-Backend", "reached")
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, _format: str, *args) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _ProtocolFlapHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    product = ExternalReverseProxyWAF(
        _spec(endpoint),
        transient_max_attempts=3,
        transient_retry_delay=0,
    )
    product.started = True
    try:
        decision = product.inspect(
            {
                "payload": "ordinary protocol retry probe",
                "param_location": "query",
                "param_name": "q",
            }
        )
        assert decision.blocked is False
        assert decision.reached_backend is True
        assert _ProtocolFlapHandler.calls == 2
    finally:
        product.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_external_product_accepts_block_status_without_readable_block_page() -> None:
    class _TruncatedBlockHandler(BaseHTTPRequestHandler):
        calls = 0

        def do_GET(self) -> None:
            type(self).calls += 1
            self.send_response(403)
            self.send_header("Content-Length", "20")
            self.end_headers()
            self.wfile.write(b"short")
            self.close_connection = True

        def log_message(self, _format: str, *args) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), _TruncatedBlockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}"
    product = ExternalReverseProxyWAF(
        _spec(endpoint),
        transient_max_attempts=3,
        transient_retry_delay=0,
    )
    product.started = True
    try:
        decision = product.inspect(
            {
                "payload": "' UNION SELECT password FROM users--",
                "param_location": "query",
                "param_name": "q",
            }
        )
        assert decision.blocked is True
        assert decision.reached_backend is False
        assert decision.status_code == 403
        assert _TruncatedBlockHandler.calls == 1
    finally:
        product.close()
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()

