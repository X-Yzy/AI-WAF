"""The generated organized view must preserve labels, provenance and data levels."""

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ORGANIZED = ROOT / "data" / "organized"


def test_organized_manifest_covers_all_labelled_sources():
    manifest = json.loads((ORGANIZED / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["total_records"] == 639_984
    assert manifest["label_counts"] == {"normal": 509_811, "attack": 130_173}
    assert manifest["attack_families"] == 65
    assert len(manifest["artifacts"]) == 588
    assert manifest["attack_representation_counts"] == {
        "obfuscated": 70_590, "original": 59_583,
    }
    assert sum(manifest["source_dataset_counts"].values()) == manifest["total_records"]
    assert manifest["content_audit"]["cross_label_content_conflicts"] == 0


def test_attack_directories_match_taxonomy_and_per_family_manifests():
    manifest = json.loads((ORGANIZED / "manifest.json").read_text(encoding="utf-8"))
    taxonomy = json.loads((ORGANIZED / "taxonomy.json").read_text(encoding="utf-8"))
    representations = {path.name for path in (ORGANIZED / "attack").iterdir() if path.is_dir()}
    assert representations == {"original", "obfuscated"}
    folders = set()
    for representation in representations:
        root = ORGANIZED / "attack" / representation
        representation_manifest = json.loads((root / "manifest.json").read_text())
        assert representation_manifest["records"] == manifest["attack_representation_counts"][representation]
        for path in root.iterdir():
            if not path.is_dir():
                continue
            family = path.name
            folders.add(family)
            family_manifest = json.loads((path / "manifest.json").read_text())
            assert family_manifest["attack_type"] == family
            assert family_manifest["representation"] == representation
            assert family_manifest["records"] == manifest["attack_representation_type_counts"][representation][family]
    assert folders == set(manifest["attack_type_counts"]) == set(taxonomy)
    assert all(item["standard"] != "unmapped" for item in taxonomy.values())


def test_context_and_protocol_records_are_not_field_model_eligible():
    paths = [
        ORGANIZED / "attack" / "original" / "api_bola" / "context" / "train.jsonl",
        ORGANIZED / "attack" / "original" / "http2_rapid_reset" / "protocol" / "validation.jsonl",
        ORGANIZED / "attack" / "original" / "llm_direct_prompt_injection" / "llm_context" / "train.jsonl",
    ]
    for path in paths:
        first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        assert first["label"] == 1
        assert first["_organized"]["payload_model_eligible"] is False


def test_normal_and_attack_root_manifests_are_consistent():
    normal = json.loads((ORGANIZED / "normal" / "manifest.json").read_text())
    attack = json.loads((ORGANIZED / "attack" / "manifest.json").read_text())
    assert normal["label"] == 0 and normal["records"] == 509_811
    assert attack["label"] == 1 and attack["records"] == 130_173
    assert attack["families"] == 65
    assert attack["by_representation"] == {"obfuscated": 70_590, "original": 59_583}


def test_obfuscation_partition_uses_explicit_provenance_and_preserves_canonical_transports():
    manifest = json.loads((ORGANIZED / "manifest.json").read_text())
    assert manifest["attack_classification_basis_counts"] == {
        "all_original_generated_variant": 59_583,
        "contrastive_non_raw_variant": 1_354,
        "dedicated_obfuscated_attack_dataset": 9_040,
        "no_explicit_obfuscation_derivation": 59_583,
        "specialized_non_raw_encoding": 310,
        "validation_obfuscation_id": 303,
    }
    obfuscated = ORGANIZED / "attack" / "obfuscated"
    parsed = 0
    for path in obfuscated.glob("*/*/*.jsonl"):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                item = json.loads(line)
                parsed += 1
                assert item["_organized"]["attack_representation"] == "obfuscated"
                assert item["_organized"]["attack_representation_basis"] != "no_explicit_obfuscation_derivation"
    assert parsed == 70_590
    deser_path = ORGANIZED / "attack" / "original" / "deser" / "field" / "train.jsonl"
    deser = [json.loads(line) for line in deser_path.read_text(encoding="utf-8").splitlines()]
    canonical_binary = [item for item in deser if item.get("encoding") == "base64_transport"]
    assert canonical_binary
    assert all(item["_organized"]["attack_representation"] == "original" for item in canonical_binary)
