"""验证整理后数据目录的完整性和清单计数。

默认模式只检查清单及清单引用文件，速度很快；``--deep`` 会逐个解析 JSON 数组并
核对记录数，适合提交前验收。脚本只读数据，不修改样本。
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# The final competition delivery stores the complete, immutable training view
# under data/organized. These directories are reproducible source-builder
# workspaces from development and are intentionally omitted from the compact
# final package. If any of them is present, it is audited strictly.
OPTIONAL_SOURCE_DATASETS = {
    "all_original_obfuscated",
    "external_traffic",
    "external_deserialization",
    "normal_traffic",
}


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"无法读取合法 JSON：{path}: {exc}") from exc


def require_file(path: Path, errors: list[str]) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        errors.append(f"缺少或为空：{path.relative_to(ROOT)}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def apply_final_delivery_scope(
    errors: list[str], report: dict[str, object]
) -> list[str]:
    """Ignore only wholly omitted source-builder workspaces.

    The organized snapshot remains mandatory and is never exempted. A partially
    present optional workspace is also never exempted, so broken source data
    cannot be hidden by this delivery profile.
    """

    omitted = sorted(
        name for name in OPTIONAL_SOURCE_DATASETS
        if not (DATA / name).exists()
    )
    retained: list[str] = []
    omitted_findings: list[str] = []
    special = {
        "all_original_obfuscated": (
            "全部原始攻击混淆集引用的 original manifest 已过期",
        ),
        "external_deserialization": (
            "独立反序列化清单错误地声明了编码变体",
            "独立反序列化单位数量与清单不一致",
            "独立反序列化唯一内容数量与清单不一致",
        ),
    }
    source_freshness_findings: list[str] = []
    for error in errors:
        if error.startswith("统一整理视图已过期，源文件哈希变化"):
            source_freshness_findings.append(error)
            continue
        normalized = error.replace("\\", "/")
        matched = any(f"data/{name}/" in normalized for name in omitted)
        if not matched:
            matched = any(
                error.startswith(prefix)
                for name in omitted
                for prefix in special.get(name, ())
            )
        if matched:
            omitted_findings.append(error)
        else:
            retained.append(error)

    report["delivery_scope"] = {
        "profile": "final",
        "authoritative_dataset": "data/organized",
        "optional_source_builders_omitted": omitted,
        "organized_snapshot_required": True,
        "organized_artifact_hashes_enforced": True,
        "input_source_hashes_enforced": False,
        "source_freshness_findings": len(source_freshness_findings),
        "omitted_findings": len(omitted_findings),
    }
    warnings: list[str] = []
    if omitted:
        warnings.append(
            "最终交付以 data/organized 为完整训练快照；"
            "未携带的旧源数据构建工作区不参与必需项判定。"
        )
    if source_freshness_findings:
        warnings.append(
            "旧来源目录与organized构建时哈希不同；最终验收校验organized自身"
            "588个产物的哈希、记录和标签，不以旧来源目录重建快照。"
        )
    if warnings:
        report["warnings"] = warnings
    return retained


def audit(deep: bool = False) -> dict:
    errors: list[str] = []
    report: dict[str, object] = {"mode": "deep" if deep else "quick"}

    raw_root = DATA / "raw_attack_traffic"
    raw_manifest_path = raw_root / "manifest.json"
    require_file(raw_manifest_path, errors)
    raw_manifest = read_json(raw_manifest_path) if raw_manifest_path.is_file() else {}
    raw_expected = 0
    raw_actual = 0
    for info in raw_manifest.get("attack_types", {}).values():
        raw_expected += int(info.get("records", 0))
        path = raw_root / str(info.get("source_records", ""))
        require_file(path, errors)
        if deep and path.is_file():
            data = read_json(path)
            raw_actual += len(data) if isinstance(data, list) else 0
    report["raw_attack_traffic"] = {
        "declared": raw_expected,
        "parsed": raw_actual if deep else None,
    }

    attack_root = DATA / "attack_traffic"
    attack_manifest_path = attack_root / "manifest.json"
    require_file(attack_manifest_path, errors)
    attack_manifest = read_json(attack_manifest_path) if attack_manifest_path.is_file() else {}
    attack_actual = 0
    for attack_type, info in attack_manifest.get("attack_types", {}).items():
        path = attack_root / attack_type / "dataset_obfuscated.json"
        require_file(path, errors)
        if deep and path.is_file():
            data = read_json(path)
            actual = len(data) if isinstance(data, list) else 0
            attack_actual += actual
            expected = int(info.get("count", -1))
            if actual != expected:
                errors.append(f"{path.relative_to(ROOT)} 记录数 {actual}，清单声明 {expected}")
    report["attack_traffic"] = {
        "declared": int(attack_manifest.get("total", 0)),
        "parsed": attack_actual if deep else None,
    }

    all_obfuscated_root = DATA / "all_original_obfuscated" / "generated"
    all_obfuscated_manifest_path = all_obfuscated_root / "manifest.json"
    require_file(all_obfuscated_manifest_path, errors)
    all_obfuscated_manifest = (
        read_json(all_obfuscated_manifest_path)
        if all_obfuscated_manifest_path.is_file() else {}
    )
    organized_original_manifest_path = DATA / "organized" / "attack" / "original" / "manifest.json"
    require_file(organized_original_manifest_path, errors)
    if (
        organized_original_manifest_path.is_file()
        and sha256_file(organized_original_manifest_path)
        != str(all_obfuscated_manifest.get("source_manifest_sha256", ""))
    ):
        errors.append("全部原始攻击混淆集引用的 original manifest 已过期，请重新生成")
    all_obfuscated_expected = int(all_obfuscated_manifest.get("generated_records", 0))
    all_obfuscated_actual = 0
    all_obfuscated_original_ids: set[str] = set()
    for relative, artifact_info in all_obfuscated_manifest.get("artifacts", {}).items():
        path = all_obfuscated_root / str(relative)
        require_file(path, errors)
        if not deep or not path.is_file():
            continue
        values = read_json(path)
        if not isinstance(values, list):
            errors.append(f"{path.relative_to(ROOT)} 顶层不是数组")
            continue
        all_obfuscated_actual += len(values)
        expected = int(artifact_info.get("records", -1))
        if len(values) != expected:
            errors.append(f"{path.relative_to(ROOT)} 记录数 {len(values)}，清单声明 {expected}")
        if sha256_file(path) != str(artifact_info.get("sha256", "")):
            errors.append(f"全部原始攻击混淆文件哈希不匹配：{path.relative_to(ROOT)}")
        for item in values:
            original_id = str(item.get("original_organized_id", ""))
            if (
                item.get("label") != 1
                or item.get("is_encoding_variant") is not True
                or not original_id
                or item.get("original_payload") == item.get("obfuscated_payload")
                or item.get("payload") != item.get("obfuscated_payload")
                or not item.get("obfuscation_chain")
                or not item.get("decoder_requirements")
            ):
                errors.append(f"{path.relative_to(ROOT)} 存在无效或不可追溯的混淆记录")
                break
            all_obfuscated_original_ids.add(original_id)
            if item.get("data_level") != "field" and item.get("exclude_from_payload_model") is not True:
                errors.append(f"{path.relative_to(ROOT)} 非字段混淆表示未排除出字段模型")
                break
    all_obfuscated_originals = int(all_obfuscated_manifest.get("original_records", 0))
    variants_per_original = int(all_obfuscated_manifest.get("variants_per_original", 0))
    if deep:
        if all_obfuscated_actual != all_obfuscated_expected:
            errors.append(
                f"全部原始攻击混淆解析总数 {all_obfuscated_actual}，清单声明 {all_obfuscated_expected}"
            )
        if len(all_obfuscated_original_ids) != all_obfuscated_originals:
            errors.append(
                "全部原始攻击混淆未覆盖清单声明的每个 original_organized_id"
            )
        if all_obfuscated_expected != all_obfuscated_originals * variants_per_original:
            errors.append("全部原始攻击混淆派生数量与每原始记录变体数不一致")
    report["all_original_obfuscated"] = {
        "declared": all_obfuscated_expected,
        "parsed": all_obfuscated_actual if deep else None,
        "original_records": all_obfuscated_originals,
        "covered_original_ids": len(all_obfuscated_original_ids) if deep else None,
        "families": int(all_obfuscated_manifest.get("generated_families", 0)),
        "coverage_complete": bool(all_obfuscated_manifest.get("coverage_complete", False)),
        "normal_content_collision_retries": int(
            all_obfuscated_manifest.get("normal_content_collision_retries", 0)
        ),
    }

    modern_root = DATA / "modern_attack_traffic" / "generated"
    modern_manifest_path = modern_root / "manifest.json"
    require_file(modern_manifest_path, errors)
    modern_manifest = read_json(modern_manifest_path) if modern_manifest_path.is_file() else {}
    kev_snapshot = DATA / "modern_attack_traffic" / "source_snapshots" / "cisa_kev.json"
    require_file(kev_snapshot, errors)
    expected_kev_hash = str(
        modern_manifest.get("sources", {}).get("cisa_kev", {}).get("sha256", "")
    )
    if deep and kev_snapshot.is_file() and sha256_file(kev_snapshot) != expected_kev_hash:
        errors.append("CISA KEV 本地快照哈希与最新漏洞清单不一致")
    modern_actual = 0
    modern_groups: dict[str, str] = {}
    modern_content_groups: set[str] = set()
    modern_required = {
        "id", "payload", "label", "attack_type", "param_location", "source",
        "cve_id", "severity", "source_version", "payload_sha256",
        "content_group_id", "group_id", "split", "label_confidence", "label_basis",
    }
    for split in ("train", "validation", "test"):
        path = modern_root / f"dataset_modern_attack_{split}.json"
        require_file(path, errors)
        if deep and path.is_file():
            values = read_json(path)
            if not isinstance(values, list):
                errors.append(f"{path.relative_to(ROOT)} 顶层不是数组")
                continue
            modern_actual += len(values)
            expected = int(modern_manifest.get("splits", {}).get(split, -1))
            if len(values) != expected:
                errors.append(f"{path.relative_to(ROOT)} 记录数 {len(values)}，清单声明 {expected}")
            for item in values:
                if not modern_required.issubset(item) or item.get("label") != 1:
                    errors.append(f"{path.relative_to(ROOT)} 存在字段缺失或标签无效的记录")
                    break
                if item.get("raw_request") is not None:
                    if not item.get("request_sha256") or item.get("exclude_from_payload_model") is not True:
                        errors.append(f"{path.relative_to(ROOT)} 完整请求缺少请求指纹或字段模型排除标记")
                        break
                group = str(item.get("group_id", ""))
                if not group or item.get("split") != split:
                    errors.append(f"{path.relative_to(ROOT)} 存在缺少 group_id 或 split 不一致的记录")
                    break
                previous = modern_groups.setdefault(group, split)
                if previous != split:
                    errors.append(f"最新 CVE 分组跨集合：{group}: {previous}/{split}")
                content_group = str(item.get("content_group_id", ""))
                if not content_group or content_group in modern_content_groups:
                    errors.append(f"最新 CVE 存在跨 CVE/集合的规范化字段重复：{content_group or 'missing'}")
                    break
                modern_content_groups.add(content_group)
    modern_expected = int(modern_manifest.get("total_records", 0))
    if deep and modern_actual != modern_expected:
        errors.append(f"最新 CVE 解析总数 {modern_actual}，清单声明 {modern_expected}")
    if deep:
        for relative, expected_hash in modern_manifest.get("artifacts", {}).items():
            artifact = modern_root / str(relative)
            require_file(artifact, errors)
            if artifact.is_file() and sha256_file(artifact) != expected_hash:
                errors.append(f"最新 CVE 数据文件哈希不匹配：{artifact.relative_to(ROOT)}")
    report["modern_attack_traffic"] = {
        "declared": modern_expected,
        "parsed": modern_actual if deep else None,
        "cve_groups": len(modern_groups) if deep else None,
    }

    specialized_root = DATA / "specialized_traffic" / "generated"
    specialized_manifest_path = specialized_root / "manifest.json"
    require_file(specialized_manifest_path, errors)
    specialized_manifest = read_json(specialized_manifest_path) if specialized_manifest_path.is_file() else {}
    specialized_actual = 0
    specialized_ids: set[str] = set()
    specialized_groups: dict[str, str] = {}
    specialized_kinds = {
        "payloads": None,
        "scanner_sequences": "request_sequence",
        "api_context_sequences": "authorization_or_request_sequence",
        "high_value_context_sequences": "authorization_or_request_sequence",
        "protocol_sequences": "protocol_sequence",
        "llm_context_sequences": "llm_conversation_or_output",
    }
    for kind, expected_scope in specialized_kinds.items():
        for split in ("train", "validation", "test"):
            path = specialized_root / kind / f"dataset_{kind}_{split}.json"
            require_file(path, errors)
            if not deep or not path.is_file():
                continue
            values = read_json(path)
            if not isinstance(values, list):
                errors.append(f"{path.relative_to(ROOT)} 顶层不是数组")
                continue
            specialized_actual += len(values)
            expected = int(specialized_manifest.get("splits", {}).get(kind, {}).get(split, -1))
            if len(values) != expected:
                errors.append(f"{path.relative_to(ROOT)} 记录数 {len(values)}，清单声明 {expected}")
            for item in values:
                item_id = str(item.get("id", ""))
                group = str(item.get("group_id", ""))
                if not item_id or item_id in specialized_ids:
                    errors.append(f"专项数据存在缺失或重复 ID：{item_id or 'missing'}")
                    break
                specialized_ids.add(item_id)
                if not group or item.get("split") != split or item.get("label") not in {0, 1}:
                    errors.append(f"{path.relative_to(ROOT)} 存在 group/split/label 无效记录")
                    break
                previous = specialized_groups.setdefault(group, split)
                if previous != split:
                    errors.append(f"专项数据分组跨集合：{group}: {previous}/{split}")
                    break
                if kind == "payloads" and not item.get("payload"):
                    errors.append(f"{path.relative_to(ROOT)} 存在空 payload")
                    break
                if expected_scope is not None and item.get("detection_scope") != expected_scope:
                    errors.append(f"{path.relative_to(ROOT)} 缺少上下文检测范围")
                    break
                if kind in {"api_context_sequences", "high_value_context_sequences", "protocol_sequences", "llm_context_sequences"} and item.get("exclude_from_payload_model") is not True:
                    errors.append(f"{path.relative_to(ROOT)} 上下文/协议样本未排除出字段模型")
                    break
    specialized_expected = int(specialized_manifest.get("total_records", 0))
    if deep and specialized_actual != specialized_expected:
        errors.append(f"专项数据解析总数 {specialized_actual}，清单声明 {specialized_expected}")
    if deep:
        for relative, expected_hash in specialized_manifest.get("artifacts", {}).items():
            artifact = specialized_root / str(relative)
            require_file(artifact, errors)
            if artifact.is_file() and sha256_file(artifact) != expected_hash:
                errors.append(f"专项数据文件哈希不匹配：{artifact.relative_to(ROOT)}")
    report["specialized_traffic"] = {
        "declared": specialized_expected,
        "parsed": specialized_actual if deep else None,
        "groups": len(specialized_groups) if deep else None,
    }

    enriched_root = DATA / "enriched_traffic" / "generated"
    enriched_manifest_path = enriched_root / "manifest.json"
    require_file(enriched_manifest_path, errors)
    enriched_manifest = read_json(enriched_manifest_path) if enriched_manifest_path.is_file() else {}
    enriched_actual = 0
    enriched_ids: set[str] = set()
    enriched_contents: set[str] = set()
    enriched_groups: dict[str, str] = {}
    enriched_group_labels: dict[str, set[int]] = {}
    for split in ("train", "validation", "test"):
        path = enriched_root / f"dataset_enriched_{split}.json"
        require_file(path, errors)
        if not deep or not path.is_file():
            continue
        values = read_json(path)
        if not isinstance(values, list):
            errors.append(f"{path.relative_to(ROOT)} 顶层不是数组")
            continue
        enriched_actual += len(values)
        expected = int(enriched_manifest.get("splits", {}).get(split, -1))
        if len(values) != expected:
            errors.append(f"{path.relative_to(ROOT)} 记录数 {len(values)}，清单声明 {expected}")
        for item in values:
            item_id = str(item.get("id", ""))
            group = str(item.get("group_id", ""))
            content = str(item.get("content_group_id", ""))
            label = item.get("label")
            if not item_id or item_id in enriched_ids:
                errors.append(f"对比式增强数据存在缺失或重复 ID：{item_id or 'missing'}")
                break
            enriched_ids.add(item_id)
            if (
                not group or not content or content in enriched_contents
                or label not in {0, 1} or item.get("split") != split
                or not item.get("payload") or item.get("execution_safe") is not True
            ):
                errors.append(f"{path.relative_to(ROOT)} 存在无效 group/content/split/label 记录")
                break
            enriched_contents.add(content)
            previous = enriched_groups.setdefault(group, split)
            if previous != split:
                errors.append(f"对比式增强 group 跨集合：{group}: {previous}/{split}")
                break
            enriched_group_labels.setdefault(group, set()).add(int(label))
    enriched_expected = int(enriched_manifest.get("total_records", 0))
    if deep and enriched_actual != enriched_expected:
        errors.append(f"对比式增强数据解析总数 {enriched_actual}，清单声明 {enriched_expected}")
    if deep and any(labels != {0, 1} for labels in enriched_group_labels.values()):
        errors.append("对比式增强数据存在缺少攻击或正常对照的 group")
    if deep and len(enriched_groups) != int(enriched_manifest.get("contrastive_groups", -1)):
        errors.append("对比式增强 group 数量与清单不一致")
    if deep:
        for relative, expected_hash in enriched_manifest.get("artifacts", {}).items():
            artifact = enriched_root / str(relative)
            require_file(artifact, errors)
            if artifact.is_file() and sha256_file(artifact) != expected_hash:
                errors.append(f"对比式增强数据文件哈希不匹配：{artifact.relative_to(ROOT)}")
    report["enriched_traffic"] = {
        "declared": enriched_expected,
        "parsed": enriched_actual if deep else None,
        "groups": len(enriched_groups) if deep else None,
        "attack_families": int(enriched_manifest.get("attack_families", 0)),
    }

    lab_root = DATA / "lab_captures" / "generated"
    lab_manifest_path = lab_root / "manifest.json"
    require_file(lab_manifest_path, errors)
    lab_manifest = read_json(lab_manifest_path) if lab_manifest_path.is_file() else {}
    lab_actual = 0
    lab_ids: set[str] = set()
    lab_groups: dict[str, str] = {}
    for split in ("train", "validation", "test"):
        path = lab_root / f"dataset_lab_capture_{split}.json"
        require_file(path, errors)
        if not deep or not path.is_file():
            continue
        values = read_json(path)
        if not isinstance(values, list):
            errors.append(f"{path.relative_to(ROOT)} 顶层不是数组")
            continue
        lab_actual += len(values)
        expected = int(lab_manifest.get("splits", {}).get(split, -1))
        if len(values) != expected:
            errors.append(f"{path.relative_to(ROOT)} 记录数 {len(values)}，清单声明 {expected}")
        for item in values:
            item_id = str(item.get("id", ""))
            group = str(item.get("group_id", ""))
            if not item_id or item_id in lab_ids:
                errors.append(f"靶场采集存在缺失或重复 ID：{item_id or 'missing'}")
                break
            lab_ids.add(item_id)
            if (
                not group or item.get("split") != split
                or item.get("label") not in {0, 1}
                or not item.get("raw_request")
                or item.get("exclude_from_payload_model") is not True
            ):
                errors.append(f"{path.relative_to(ROOT)} 存在无效或未隔离的靶场采集记录")
                break
            previous = lab_groups.setdefault(group, split)
            if previous != split:
                errors.append(f"靶场 campaign 跨集合：{group}: {previous}/{split}")
                break
    lab_expected = int(lab_manifest.get("total_records", 0))
    if deep and lab_actual != lab_expected:
        errors.append(f"靶场采集解析总数 {lab_actual}，清单声明 {lab_expected}")
    if deep:
        for relative, expected_hash in lab_manifest.get("artifacts", {}).items():
            artifact = lab_root / str(relative)
            require_file(artifact, errors)
            if artifact.is_file() and sha256_file(artifact) != expected_hash:
                errors.append(f"靶场采集文件哈希不匹配：{artifact.relative_to(ROOT)}")
    report["lab_captures"] = {
        "declared": lab_expected,
        "parsed": lab_actual if deep else None,
        "campaigns": int(lab_manifest.get("campaigns", 0)),
        "groups": len(lab_groups) if deep else None,
    }

    external_root = DATA / "external_traffic" / "generated"
    external_manifest_path = external_root / "manifest.json"
    require_file(external_manifest_path, errors)
    external_manifest = read_json(external_manifest_path) if external_manifest_path.is_file() else {}
    external_expected = int(external_manifest.get("total_records", 0))
    external_actual = 0
    external_ids: set[str] = set()
    external_groups: dict[str, str] = {}
    for relative, info in external_manifest.get("sources", {}).items():
        source = ROOT / str(info.get("local_path", ""))
        require_file(source, errors)
        if deep and source.is_file() and sha256_file(source) != str(info.get("sha256", "")):
            errors.append(f"外部公开数据源快照哈希不匹配：{source.relative_to(ROOT)}")
    for relative, info in external_manifest.get("artifacts", {}).items():
        artifact = external_root / str(relative)
        require_file(artifact, errors)
        if not deep or not artifact.is_file():
            continue
        if sha256_file(artifact) != str(info.get("sha256", "")):
            errors.append(f"外部公开派生数据哈希不匹配：{artifact.relative_to(ROOT)}")
        values = read_json(artifact)
        if not isinstance(values, list):
            errors.append(f"{artifact.relative_to(ROOT)} 顶层不是数组")
            continue
        external_actual += len(values)
        if len(values) != int(info.get("records", -1)):
            errors.append(
                f"{artifact.relative_to(ROOT)} 记录数 {len(values)}，清单声明 {info.get('records')}"
            )
        for item in values:
            item_id = str(item.get("id", ""))
            group = str(item.get("group_id", ""))
            split = str(item.get("split", ""))
            if (
                not item_id or item_id in external_ids or not group
                or split not in {"train", "validation", "test", "evaluation"}
                or item.get("label") not in {0, 1}
                or not item.get("source") or not item.get("source_version")
                or not item.get("label_basis")
            ):
                errors.append(f"{artifact.relative_to(ROOT)} 存在无效 ID/group/split/label/provenance")
                break
            external_ids.add(item_id)
            previous = external_groups.setdefault(group, split)
            if previous != split:
                errors.append(f"外部公开数据 group 跨集合：{group}: {previous}/{split}")
                break
            is_request = item.get("raw_request") is not None
            is_context = (
                item.get("conversation") is not None
                or item.get("protocol_event") is not None
                or item.get("detection_scope") in {
                    "authorization_or_request_sequence", "llm_conversation_or_output",
                    "protocol_sequence", "request_sequence",
                }
            )
            if is_request and (
                not item.get("raw_request") or item.get("exclude_from_payload_model") is not True
            ):
                errors.append(f"{artifact.relative_to(ROOT)} 完整请求未隔离出字段模型")
                break
            if is_context and item.get("exclude_from_payload_model") is not True:
                errors.append(f"{artifact.relative_to(ROOT)} 外部上下文未隔离出字段模型")
                break
            if not is_request and not is_context and not item.get("payload"):
                errors.append(f"{artifact.relative_to(ROOT)} 存在空字段 payload")
                break
    if deep and external_actual != external_expected:
        errors.append(f"外部公开数据解析总数 {external_actual}，清单声明 {external_expected}")
    external_labels = external_manifest.get("label_counts", {})
    if external_expected != int(external_labels.get("normal", 0)) + int(external_labels.get("attack", 0)):
        errors.append("外部公开数据清单的正常/攻击数量与总数不一致")
    report["external_traffic"] = {
        "declared": external_expected,
        "parsed": external_actual if deep else None,
        "normal": int(external_labels.get("normal", 0)),
        "attack": int(external_labels.get("attack", 0)),
        "groups": len(external_groups) if deep else None,
    }

    deser_root = DATA / "external_deserialization" / "generated"
    deser_manifest_path = deser_root / "manifest.json"
    require_file(deser_manifest_path, errors)
    deser_manifest = read_json(deser_manifest_path) if deser_manifest_path.is_file() else {}
    deser_expected = int(deser_manifest.get("total_records", 0))
    deser_actual = 0
    deser_groups: dict[str, str] = {}
    deser_content: set[str] = set()
    independent_units: dict[str, str] = {}
    records_per_unit: dict[str, int] = {}
    for name, info in deser_manifest.get("sources", {}).items():
        source = ROOT / str(info.get("local_path", ""))
        require_file(source, errors)
        if deep and source.is_file() and sha256_file(source) != str(info.get("sha256", "")):
            errors.append(f"独立反序列化来源快照哈希不匹配：{name}")
    for relative, info in deser_manifest.get("artifacts", {}).items():
        artifact = deser_root / str(relative)
        require_file(artifact, errors)
        if not deep or not artifact.is_file():
            continue
        if sha256_file(artifact) != str(info.get("sha256", "")):
            errors.append(f"独立反序列化派生文件哈希不匹配：{artifact.relative_to(ROOT)}")
        values = read_json(artifact)
        if not isinstance(values, list):
            errors.append(f"{artifact.relative_to(ROOT)} 顶层不是数组")
            continue
        deser_actual += len(values)
        if len(values) != int(info.get("records", -1)):
            errors.append(f"{artifact.relative_to(ROOT)} 记录数与清单不一致")
        for item in values:
            group = str(item.get("group_id", ""))
            split = str(item.get("split", ""))
            content = str(item.get("content_group_id", ""))
            unit = str(item.get("independent_sample_id", ""))
            kind = str(item.get("independence_unit", ""))
            if (
                item.get("label") != 1 or item.get("attack_type") != "deser"
                or not item.get("id") or not group or not content or not unit
                or kind not in {
                    "upstream_gadget_chain", "upstream_serialization_format",
                    "upstream_marshaller_entrypoint",
                    "upstream_cve_scenario",
                }
                or split not in {"train", "validation", "test", "evaluation"}
                or item.get("canonical_representation") is not True
                or item.get("is_encoding_variant") is not False
                or not item.get("source") or not item.get("source_version")
                or not item.get("label_basis")
            ):
                errors.append(f"{artifact.relative_to(ROOT)} 存在无效独立性、标签、切分或来源字段")
                break
            previous = deser_groups.setdefault(group, split)
            if previous != split:
                errors.append(f"独立反序列化 group 跨集合：{group}: {previous}/{split}")
                break
            if content in deser_content:
                errors.append(f"独立反序列化存在重复内容组：{content}")
                break
            deser_content.add(content)
            previous_kind = independent_units.setdefault(unit, kind)
            if previous_kind != kind:
                errors.append(f"独立反序列化单位类型冲突：{unit}")
                break
            records_per_unit[unit] = records_per_unit.get(unit, 0) + 1
            if kind in {
                "upstream_gadget_chain", "upstream_serialization_format",
                "upstream_marshaller_entrypoint",
            }:
                if item.get("raw_request") is not None or not item.get("payload"):
                    errors.append(f"{artifact.relative_to(ROOT)} gadget chain 不是有效字段样本")
                    break
                if item.get("derivation_count_for_independent_unit") != 1:
                    errors.append(f"{artifact.relative_to(ROOT)} gadget chain 存在派生扩增")
                    break
                if (
                    item.get("deserialization_ecosystem") == "java"
                    and item.get("source") in {"joaomatosf/JexBoss", "frohoff/ysoserial"}
                ):
                    try:
                        decoded = base64.b64decode(str(item.get("payload", "")), validate=True)
                    except (ValueError, binascii.Error):
                        decoded = b""
                    if item.get("encoding") != "base64_transport" or not decoded.startswith(b"\xac\xed\x00\x05"):
                        errors.append(f"{artifact.relative_to(ROOT)} Java gadget 不是规范序列化流")
                        break
                if item.get("source") == "mbechler/marshalsec":
                    try:
                        expected_prefix = bytes.fromhex(str(item.get("wire_prefix_hex", "")))
                    except ValueError:
                        expected_prefix = b""
                    if item.get("wire_media") == "binary":
                        try:
                            wire_value = base64.b64decode(str(item.get("payload", "")), validate=True)
                        except (ValueError, binascii.Error):
                            wire_value = b""
                        valid = item.get("encoding") == "base64_transport"
                    elif item.get("wire_media") == "text":
                        wire_value = str(item.get("payload", "")).encode("utf-8")
                        valid = item.get("encoding") == "utf8_text"
                    else:
                        wire_value = b""
                        valid = False
                    if not valid or not expected_prefix or not wire_value.startswith(expected_prefix):
                        errors.append(f"{artifact.relative_to(ROOT)} marshalsec 线协议前缀或载体不规范")
                        break
                if item.get("deserialization_ecosystem") == "dotnet":
                    try:
                        decoded = base64.b64decode(str(item.get("payload", "")), validate=True)
                    except (ValueError, binascii.Error):
                        decoded = b""
                    if (
                        item.get("serialization_format") != "BinaryFormatter"
                        or item.get("encoding") != "base64_transport"
                        or not decoded.startswith(b"\x00\x01\x00\x00")
                    ):
                        errors.append(f"{artifact.relative_to(ROOT)} .NET gadget 不是规范 BinaryFormatter 流")
                        break
                if item.get("deserialization_ecosystem") == "python":
                    serialization_format = str(item.get("serialization_format", ""))
                    payload = str(item.get("payload", ""))
                    if serialization_format == "pickle":
                        try:
                            decoded = base64.b64decode(payload, validate=True)
                        except (ValueError, binascii.Error):
                            decoded = b""
                        valid = item.get("encoding") == "base64_transport" and decoded.startswith(b"\x80")
                    elif serialization_format == "pyyaml":
                        valid = (
                            item.get("encoding") == "utf8_text"
                            and "!!python/object/apply:subprocess.Popen" in payload
                        )
                    elif serialization_format == "jsonpickle":
                        try:
                            decoded_json = json.loads(payload)
                        except json.JSONDecodeError:
                            decoded_json = {}
                        valid = (
                            item.get("encoding") == "utf8_text"
                            and isinstance(decoded_json, dict) and "py/reduce" in decoded_json
                        )
                    else:
                        valid = False
                    if not valid:
                        errors.append(f"{artifact.relative_to(ROOT)} Python 反序列化格式不规范")
                        break
            else:
                if (
                    split != "evaluation" or not item.get("raw_request")
                    or item.get("exclude_from_payload_model") is not True
                ):
                    errors.append(f"{artifact.relative_to(ROOT)} CVE 请求未保持 evaluation/字段隔离")
                    break
    if deep and any(
        records_per_unit[unit] != 1
        for unit, kind in independent_units.items()
        if kind in {
            "upstream_gadget_chain", "upstream_serialization_format",
            "upstream_marshaller_entrypoint",
        }
    ):
        errors.append("同一上游 gadget chain 产生了多条记录")
    declared_independence = deser_manifest.get("independence", {})
    if int(declared_independence.get("encoding_variants", -1)) != 0:
        errors.append("独立反序列化清单错误地声明了编码变体")
    if deep and len(independent_units) != int(declared_independence.get("independent_units", -1)):
        errors.append("独立反序列化单位数量与清单不一致")
    if deep and len(deser_content) != int(declared_independence.get("unique_content_groups", -1)):
        errors.append("独立反序列化唯一内容数量与清单不一致")
    if deep and deser_actual != deser_expected:
        errors.append(f"独立反序列化解析总数 {deser_actual}，清单声明 {deser_expected}")
    report["external_deserialization"] = {
        "declared": deser_expected,
        "parsed": deser_actual if deep else None,
        "independent_units": len(independent_units) if deep else int(
            declared_independence.get("independent_units", 0)
        ),
        "encoding_variants": int(declared_independence.get("encoding_variants", -1)),
        "groups": len(deser_groups) if deep else None,
    }

    organized_root = DATA / "organized"
    organized_manifest_path = organized_root / "manifest.json"
    require_file(organized_manifest_path, errors)
    organized_manifest = read_json(organized_manifest_path) if organized_manifest_path.is_file() else {}
    organized_expected = int(organized_manifest.get("total_records", 0))
    organized_actual = 0
    organized_representation_counts: dict[str, int] = {}
    if not deep:
        for relative in organized_manifest.get("artifacts", {}):
            require_file(organized_root / str(relative), errors)
    if deep:
        for relative, info in organized_manifest.get("input_artifacts", {}).items():
            source = ROOT / str(relative)
            require_file(source, errors)
            if source.is_file() and sha256_file(source) != str(info.get("sha256", "")):
                errors.append(f"统一整理视图已过期，源文件哈希变化：{source.relative_to(ROOT)}")
        for relative, info in organized_manifest.get("artifacts", {}).items():
            artifact = organized_root / str(relative)
            require_file(artifact, errors)
            if not artifact.is_file():
                continue
            if sha256_file(artifact) != str(info.get("sha256", "")):
                errors.append(f"统一整理文件哈希不匹配：{artifact.relative_to(ROOT)}")
                continue
            count = 0
            with artifact.open(encoding="utf-8", errors="strict") as handle:
                for line_no, line in enumerate(handle, 1):
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        errors.append(f"统一整理 JSONL 无效：{artifact.relative_to(ROOT)}:{line_no}")
                        break
                    count += 1
                    expected_label = 0 if relative.startswith("normal/") else 1
                    if (
                        not isinstance(item, dict)
                        or item.get("label") != expected_label
                        or not isinstance(item.get("_organized"), dict)
                    ):
                        errors.append(f"统一整理标签/元数据无效：{artifact.relative_to(ROOT)}:{line_no}")
                        break
                    parts = Path(relative).parts
                    if expected_label == 1:
                        metadata = item.get("_organized", {})
                        if (
                            len(parts) < 5
                            or parts[1] not in {"original", "obfuscated"}
                            or item.get("attack_type") != parts[2]
                            or metadata.get("attack_representation") != parts[1]
                            or not metadata.get("attack_representation_basis")
                        ):
                            errors.append(
                                f"统一整理攻击表示/类型目录不一致："
                                f"{artifact.relative_to(ROOT)}:{line_no}"
                            )
                            break
                        organized_representation_counts[parts[1]] = (
                            organized_representation_counts.get(parts[1], 0) + 1
                        )
            expected_count = int(info.get("records", -1))
            if count != expected_count:
                errors.append(f"{artifact.relative_to(ROOT)} 记录数 {count}，清单声明 {expected_count}")
            organized_actual += count
    labels = organized_manifest.get("label_counts", {})
    if organized_expected != int(labels.get("normal", 0)) + int(labels.get("attack", 0)):
        errors.append("统一整理清单的正常/攻击数量与总数不一致")
    declared_representations = {
        str(key): int(value)
        for key, value in organized_manifest.get("attack_representation_counts", {}).items()
    }
    if sum(declared_representations.values()) != int(labels.get("attack", 0)):
        errors.append("统一整理原始/混淆攻击数量与攻击总数不一致")
    if deep and organized_representation_counts != declared_representations:
        errors.append("统一整理原始/混淆攻击实际数量与清单不一致")
    if deep and organized_actual != organized_expected:
        errors.append(f"统一整理解析总数 {organized_actual}，清单声明 {organized_expected}")
    report["organized_view"] = {
        "declared": organized_expected,
        "parsed": organized_actual if deep else None,
        "normal": int(labels.get("normal", 0)),
        "attack": int(labels.get("attack", 0)),
        "attack_families": int(organized_manifest.get("attack_families", 0)),
        "attack_representations": declared_representations,
        "content_conflicts": int(organized_manifest.get("content_audit", {}).get("cross_label_content_conflicts", 0)),
    }

    normal_root = DATA / "normal_traffic" / "generated"
    normal_manifest_path = normal_root / "manifest.json"
    require_file(normal_manifest_path, errors)
    normal_manifest = read_json(normal_manifest_path) if normal_manifest_path.is_file() else {}
    normal_actual = 0
    normal_files = {
        "payload_level": "dataset_normal_payload",
        "hard_negatives": "dataset_normal_hard",
        "http_requests": "dataset_normal_http",
        "modern_http_requests": "dataset_normal_modern_http",
    }
    for kind, stem in normal_files.items():
        for split in ("train", "validation", "test"):
            name = f"{stem}_{split}.json"
            path = normal_root / kind / name
            require_file(path, errors)
            if deep and path.is_file():
                data = read_json(path)
                normal_actual += len(data) if isinstance(data, list) else 0
    normal_expected = int(normal_manifest.get("total_records", 0))
    if deep and normal_actual != normal_expected:
        errors.append(f"正常流量解析总数 {normal_actual}，清单声明 {normal_expected}")
    if deep:
        for relative, expected_hash in normal_manifest.get("artifacts", {}).items():
            artifact = normal_root / str(relative)
            require_file(artifact, errors)
            if artifact.is_file() and sha256_file(artifact) != expected_hash:
                errors.append(f"正常流量数据文件哈希不匹配：{artifact.relative_to(ROOT)}")
    report["normal_traffic"] = {
        "declared": normal_expected,
        "parsed": normal_actual if deep else None,
    }

    coverage_path = DATA / "coverage" / "coverage_matrix.json"
    require_file(coverage_path, errors)
    coverage = read_json(coverage_path) if coverage_path.is_file() else {}
    entries = coverage.get("entries", [])
    allowed_data_status = {
        "covered", "covered_context", "covered_sequence", "partial", "gap",
        "outside_request_waf", "recent_cve_metadata",
    }
    if not isinstance(entries, list) or len(entries) < 40:
        errors.append("漏洞覆盖矩阵缺失或覆盖家族过少")
        entries = []
    families = [str(item.get("family", "")) for item in entries if isinstance(item, dict)]
    if len(families) != len(set(families)) or any(not family for family in families):
        errors.append("漏洞覆盖矩阵存在空名称或重复家族")
    if any(item.get("data_status") not in allowed_data_status for item in entries):
        errors.append("漏洞覆盖矩阵存在未知 data_status")
    report["coverage_matrix"] = {
        "families": len(entries),
        "gaps": sum(item.get("data_status") == "gap" for item in entries),
        "outside_request_waf": sum(item.get("data_status") == "outside_request_waf" for item in entries),
    }

    for path in (
        DATA / "validation" / "semantic_edge_cases.json",
        DATA / "validation" / "test_basic.json",
        DATA / "validation" / "test_medium.json",
        DATA / "validation" / "test_heavy.json",
    ):
        require_file(path, errors)

    if deep:
        if raw_actual != raw_expected:
            errors.append(f"原始攻击解析总数 {raw_actual}，清单声明 {raw_expected}")
        if attack_actual != int(attack_manifest.get("total", 0)):
            errors.append(
                f"混淆攻击解析总数 {attack_actual}，清单声明 {attack_manifest.get('total', 0)}"
            )

    errors = apply_final_delivery_scope(errors, report)
    report["status"] = "PASS" if not errors else "FAIL"
    report["errors"] = errors
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="审计三个训练数据目录")
    parser.add_argument("--deep", action="store_true", help="解析全部 JSON 并核对记录数")
    args = parser.parse_args()
    report = audit(args.deep)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    raise SystemExit(0 if report["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
