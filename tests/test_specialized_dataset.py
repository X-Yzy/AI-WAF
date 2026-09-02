"""Quality boundaries for deserialization/API/scanner specialized data."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "data" / "specialized_traffic" / "generated"


def _records(kind: str):
    result = []
    for path in (GENERATED / kind).glob("*.json"):
        result.extend(json.loads(path.read_text(encoding="utf-8")))
    return result


def test_specialized_manifest_and_artifact_counts():
    manifest = json.loads((GENERATED / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["total_records"] == 1523
    assert manifest["counts"] == {
        "payloads": 456, "scanner_sequences": 180, "api_context_sequences": 137,
        "protocol_sequences": 62, "high_value_context_sequences": 648,
        "llm_context_sequences": 40,
    }
    assert len(manifest["artifacts"]) == 18


def test_deserialization_formats_and_hard_negatives_are_present():
    records = _records("payloads")
    attacks = [item for item in records if item["label"] == 1]
    normals = [item for item in records if item["label"] == 0]
    decoded = "\n".join(item["decoded_payload"] for item in attacks)
    for marker in (
        "rO0AB", "XMLDecoder", "!!python/object", "JdbcRowSetImpl",
        "ObjectDataProvider", "gASV", "GuzzleHttp", "_$$ND_FUNC$$_", "HESSIAN:",
    ):
        assert marker in decoded
    assert len(normals) == 84
    assert all(item.get("hard_negative") is True for item in normals)


def test_context_api_data_is_never_payload_training_data():
    values = _records("api_context_sequences")
    assert {item["attack_subtype"] for item in values if item["label"] == 1} >= {
        "context_api_bola", "context_api_mass_assignment",
        "context_graphql_complexity", "context_api_resource_consumption",
        "context_api_viewstate_integrity",
    }
    assert all(item["exclude_from_payload_model"] is True for item in values)
    by_family = {}
    for item in values:
        by_family.setdefault(item["attack_subtype"], set()).add(item["label"])
    assert all(labels == {0, 1} for labels in by_family.values())


def test_scanner_sequences_include_tools_and_legitimate_automation():
    values = _records("scanner_sequences")
    tools = {item["tool"] for item in values if item["label"] == 1}
    assert tools == {"nuclei", "sqlmap", "nikto", "ffuf", "gobuster", "dirsearch", "zap", "wapiti"}
    assert sum(item["label"] == 0 for item in values) == 60
    groups = {}
    for item in values:
        previous = groups.setdefault(item["group_id"], item["split"])
        assert previous == item["split"]
    for split in ("train", "validation", "test"):
        assert {item["label"] for item in values if item["split"] == split} == {0, 1}


def test_protocol_sequences_cover_h2_and_websocket_with_paired_controls():
    values = _records("protocol_sequences")
    assert {item["attack_subtype"] for item in values if item["label"] == 1} == {
        "protocol_http2_pseudo_header_ambiguity",
        "protocol_http2_rapid_reset",
        "protocol_websocket_frame_validation",
    }
    assert all(item["exclude_from_payload_model"] is True for item in values)
    by_family = {}
    for item in values:
        by_family.setdefault(item["attack_subtype"], set()).add(item["label"])
    assert all(labels == {0, 1} for labels in by_family.values())


def test_llm_context_has_direct_indirect_tool_and_output_pairs():
    values = _records("llm_context_sequences")
    attacks = {item["attack_subtype"] for item in values if item["label"] == 1}
    assert attacks == {
        "context_llm_direct_prompt_injection",
        "context_llm_indirect_rag_injection",
        "context_llm_tool_argument_injection",
        "context_llm_prompt_exfiltration",
        "context_llm_sensitive_output_disclosure",
    }
    assert all(item["exclude_from_payload_model"] is True for item in values)
    groups = {}
    for item in values:
        groups.setdefault(item["group_id"], set()).add(item["label"])
    assert all(labels == {0, 1} for labels in groups.values())

