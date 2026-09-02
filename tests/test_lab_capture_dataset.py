"""Integrity and leakage boundaries for live loopback lab captures."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "data" / "lab_captures" / "generated"


def records() -> list[dict]:
    result = []
    for path in sorted(GENERATED.glob("dataset_lab_capture_*.json")):
        result.extend(json.loads(path.read_text(encoding="utf-8")))
    return result


def test_lab_capture_manifest_and_labels():
    manifest = json.loads((GENERATED / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["total_records"] == 1_427
    assert manifest["label_counts"] == {"0": 548, "1": 879}
    assert manifest["campaigns"] == 388
    assert manifest["skipped"] == {"duplicate": 6, "unlabelled": 1}
    assert len(manifest["attack_type_counts"]) == 21


def test_lab_campaigns_do_not_cross_splits_and_are_not_field_labels():
    groups = {}
    for item in records():
        groups.setdefault(item["group_id"], {"splits": set(), "labels": set()})
        groups[item["group_id"]]["splits"].add(item["split"])
        groups[item["group_id"]]["labels"].add(item["label"])
        assert item["exclude_from_payload_model"] is True
        assert item["authorization"] == "explicitly labelled isolated lab traffic"
        assert item["lab_target"] in {
            "127.0.0.1:19082", "juice-shop:3000", "vampi:5000", "webgoat:8080"
        }
    assert len(groups) == 388
    assert all(len(value["splits"]) == 1 for value in groups.values())


def test_capture_redaction_and_family_metadata():
    values = records()
    raw = "\n".join(item["raw_request"] for item in values)
    assert "synthetic-password" not in raw
    assert "<redacted:" in raw
    attacks = {item["attack_type"] for item in values if item["label"] == 1}
    assert {"sqli", "xss", "deser", "xxe", "ssrf", "scanner_probe"} <= attacks
    assert {item["lab_target"] for item in values} == {
        "127.0.0.1:19082", "juice-shop:3000", "vampi:5000", "webgoat:8080"
    }
