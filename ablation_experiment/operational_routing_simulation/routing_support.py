"""Routing and sampling helpers used only by the retained 95% experiment."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import re

import numpy as np


SAFE_NORMAL_RULES = (
    (
        "normalized_uuid",
        re.compile(r"(?i)^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$"),
        None,
    ),
    (
        "normalized_email",
        re.compile(r"(?i)^[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$"),
        None,
    ),
    (
        "normalized_iso_datetime",
        re.compile(
            r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}"
            r"(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
        ),
        None,
    ),
    (
        "normalized_safe_static_filename",
        re.compile(
            r"(?i)^[a-z0-9][a-z0-9_-]{0,63}\."
            r"(?:jpe?g|png|gif|webp|pdf|txt|csv)$"
        ),
        None,
    ),
    (
        "normalized_session_preference_cookie",
        re.compile(
            r"(?i)^session=[a-z0-9]{16,64};\s*"
            r"theme=(?:light|dark|system);\s*"
            r"locale=[a-z]{2}(?:-[a-z]{2})?$"
        ),
        {"cookie"},
    ),
    (
        "normalized_pagination_query",
        re.compile(
            r"(?i)^(?:(?:page|limit|offset|sort|order|cursor|batch|start|end|timezone)="
            r"[a-z0-9_.:+-]+)(?:&(?:page|limit|offset|sort|order|cursor|batch|start|end|timezone)="
            r"[a-z0-9_.:+-]+){1,10}$"
        ),
        {"query"},
    ),
)


def safe_normal_rule(restored: str, location: str) -> str | None:
    """Return the matching validated benign rule, if any."""
    value = restored.strip()
    if not value or len(value) > 512 or any(ord(char) < 32 for char in value):
        return None
    for rule_id, pattern, allowed_locations in SAFE_NORMAL_RULES:
        if allowed_locations is not None and location not in allowed_locations:
            continue
        if pattern.fullmatch(value):
            return rule_id
    return None


def build_operational_test_set(
    records: list[dict],
    record_routes: list[str],
    *,
    target_records: int,
    normal_share: float,
    model_share: float,
    seed: int,
) -> tuple[list[dict], dict]:
    """Build a unique deterministic workload subset from the held-out test set."""
    if len(records) != len(record_routes):
        raise ValueError("records and record_routes must have equal length")
    if target_records <= 0 or target_records > len(records):
        raise ValueError("target_records must fit inside the independent test set")
    if not 0.0 < normal_share < 1.0:
        raise ValueError("normal_share must be between 0 and 1")
    if not 0.0 < model_share < 1.0:
        raise ValueError("model_share must be between 0 and 1")

    buckets: dict[tuple[str, int], list[int]] = defaultdict(list)
    for index, (record, route) in enumerate(zip(records, record_routes)):
        buckets[(route, int(record.get("label", 0)))].append(index)

    normal_target = int(round(target_records * normal_share))
    attack_target = target_records - normal_target
    model_target = int(round(target_records * model_share))
    source_attack_total = sum(
        len(buckets[(route, 1)])
        for route in (
            "existing_rules_normalization_context",
            "normalized_routine_benign",
            "lightgbm_and_character_model",
        )
    )
    source_model_attack = len(
        buckets[("lightgbm_and_character_model", 1)]
    )
    model_attack_target = min(
        int(
            round(
                attack_target
                * source_model_attack
                / max(source_attack_total, 1)
            )
        ),
        model_target,
        len(buckets[("lightgbm_and_character_model", 1)]),
    )
    model_normal_target = model_target - model_attack_target
    direct_attack_target = attack_target - model_attack_target
    direct_normal_target = normal_target - model_normal_target

    existing_normal_available = len(
        buckets[("existing_rules_normalization_context", 0)]
    )
    routine_normal_available = len(
        buckets[("normalized_routine_benign", 0)]
    )
    direct_normal_available = existing_normal_available + routine_normal_available
    existing_normal_target = int(
        round(
            direct_normal_target
            * existing_normal_available
            / max(direct_normal_available, 1)
        )
    )
    routine_normal_target = direct_normal_target - existing_normal_target

    requested = {
        ("existing_rules_normalization_context", 0): existing_normal_target,
        ("existing_rules_normalization_context", 1): direct_attack_target,
        ("normalized_routine_benign", 0): routine_normal_target,
        ("normalized_routine_benign", 1): 0,
        ("lightgbm_and_character_model", 0): model_normal_target,
        ("lightgbm_and_character_model", 1): model_attack_target,
    }
    for key, count in requested.items():
        if count < 0 or count > len(buckets[key]):
            raise RuntimeError(
                f"95% test allocation cannot be satisfied for {key}: "
                f"requested={count}, available={len(buckets[key])}"
            )

    rng = np.random.default_rng(seed)
    selected_indices: list[int] = []
    allocation: dict[str, dict[str, int]] = {}
    for (route, label), count in requested.items():
        candidates = np.asarray(buckets[(route, label)], dtype=np.int64)
        chosen = (
            rng.choice(candidates, size=count, replace=False).tolist()
            if count
            else []
        )
        selected_indices.extend(int(index) for index in chosen)
        allocation.setdefault(route, {"normal": 0, "attack": 0})[
            "attack" if label else "normal"
        ] = count

    selected_indices.sort()
    if len(selected_indices) != target_records:
        raise RuntimeError("95% test allocation produced wrong record count")
    if len(set(selected_indices)) != target_records:
        raise RuntimeError("95% test allocation unexpectedly duplicated records")

    selected_records = [records[index] for index in selected_indices]
    identity = hashlib.sha256(
        "\n".join(
            f"{index}:{records[index].get('id', '')}"
            for index in selected_indices
        ).encode("utf-8")
    ).hexdigest()
    return selected_records, {
        "kind": (
            "deterministic stratified subset of the untouched independent "
            "test set; sampled without replacement"
        ),
        "purpose": "retained 95% direct-route ablation only",
        "source_records": len(records),
        "records": target_records,
        "normal_records": normal_target,
        "attack_records": attack_target,
        "normal_share": round(normal_target / target_records, 6),
        "attack_share": round(attack_target / target_records, 6),
        "target_model_share": model_share,
        "seed": seed,
        "replacement": False,
        "selected_index_sha256": identity,
        "allocation": allocation,
        "note": (
            "This test set is never used for model or threshold tuning."
        ),
    }
