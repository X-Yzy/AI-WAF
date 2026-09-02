"""Coverage claims must distinguish data, runtime controls and true gaps."""

import json
from pathlib import Path


MATRIX = Path(__file__).resolve().parents[1] / "data" / "coverage" / "coverage_matrix.json"


def test_coverage_matrix_is_unique_and_has_explicit_gaps():
    document = json.loads(MATRIX.read_text(encoding="utf-8"))
    entries = document["entries"]
    families = [item["family"] for item in entries]
    assert len(entries) == 61
    assert len(families) == len(set(families))
    assert document["summary"]["by_data_status"].get("gap", 0) == 0


def test_protocol_and_llm_data_do_not_overclaim_runtime_enforcement():
    entries = {item["family"]: item for item in json.loads(MATRIX.read_text())['entries']}
    assert entries["HTTP/2 request smuggling / pseudo-header ambiguity"]["data_status"] == "covered_sequence"
    assert entries["HTTP/2 request smuggling / pseudo-header ambiguity"]["runtime_status"] == "gateway_required"
    assert entries["WebSocket frame attacks"]["data_status"] == "covered_sequence"
    assert entries["WebSocket frame attacks"]["runtime_status"] == "not_enforced"
    for family in ("LLM prompt/tool injection", "LLM sensitive-information disclosure"):
        assert entries[family]["data_status"] == "covered_context"
        assert entries[family]["runtime_status"] == "not_enforced"


def test_context_vulnerabilities_are_not_claimed_as_payload_enforcement():
    entries = {item["family"]: item for item in json.loads(MATRIX.read_text())["entries"]}
    for family in (
        "BOLA / IDOR", "Broken function-level authorization",
        "Mass assignment / property and JSON Patch authorization", "CORS misconfiguration",
        "Cache poisoning / Host-forwarding trust", "Race conditions / replay",
    ):
        assert entries[family]["data_status"] == "covered_context"
        assert entries[family]["runtime_status"] == "not_enforced"


def test_non_request_controls_remain_outside_waf_claim():
    entries = {item["family"]: item for item in json.loads(MATRIX.read_text())["entries"]}
    for family in (
        "TLS/cryptographic failures", "Missing security headers / clickjacking",
        "Sensitive data exposure in responses", "Malware in uploaded binaries",
    ):
        assert entries[family]["data_status"] == "outside_request_waf"
