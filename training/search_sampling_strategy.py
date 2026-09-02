#!/usr/bin/env python3
"""Compare group-aware per-attack-type sampling strategies.

All strategies keep every attack record for types at or below ``rare_limit``.
Only abundant types are reduced, and reduction happens by stable original
groups so related raw/obfuscated variants are not split arbitrarily.

Model/threshold selection uses validation only.  The test split is evaluated
once, after the best validation strategy has been chosen.
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import json
import math
import pickle
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, roc_auc_score
from sklearn.pipeline import Pipeline as SkPipeline


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from training import train_organized_full as core  # noqa: E402


SEED = 20260728
# Compatibility name retained for machine-readable reports and older imports.
KNOWN_TRAIN_TEST_DUPLICATE = core.KNOWN_CROSS_SPLIT_DUPLICATE_ID


def emit(message: str, **values) -> None:
    print(
        json.dumps({"message": message, **values}, ensure_ascii=False),
        flush=True,
    )


def attack_group(record: dict) -> str:
    metadata = record.get("_organized") or {}
    attack_type = str(record.get("attack_type", "unknown"))
    if record.get("original_organized_id"):
        identity = f"organized:{record['original_organized_id']}"
    elif record.get("group_id"):
        identity = f"group:{record['group_id']}"
    elif record.get("original_id"):
        identity = f"original:{record['original_id']}"
    else:
        identity = f"content:{metadata.get('content_sha256') or record.get('id')}"
    return f"{attack_type}|{identity}"


def stable_group_order(group: str) -> str:
    return hashlib.sha256(f"{SEED}|{group}".encode("utf-8")).hexdigest()


def cap_for(policy: str, count: int, rare_limit: int) -> int:
    if count <= rare_limit or policy == "all":
        return count
    if policy.startswith("cap_"):
        return max(rare_limit, int(policy.split("_", 1)[1]))
    if policy == "sqrt":
        return max(rare_limit, int(round(math.sqrt(count * rare_limit))))
    if policy == "log":
        return max(
            rare_limit,
            int(round(rare_limit * (1.0 + math.log2(count / rare_limit)))),
        )
    raise ValueError(f"Unknown policy: {policy}")


def select_attack_indices(
    records: list[dict],
    policy: str,
    rare_limit: int,
) -> tuple[np.ndarray, dict]:
    by_type: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        if int(record.get("label", 0)) == 1:
            by_type[str(record.get("attack_type", "unknown"))].append(index)

    selected: list[int] = []
    audit = {}
    for attack_type, indices in sorted(by_type.items()):
        target = cap_for(policy, len(indices), rare_limit)
        if target >= len(indices):
            chosen = indices
        else:
            groups: dict[str, list[int]] = defaultdict(list)
            for index in indices:
                groups[attack_group(records[index])].append(index)
            chosen = []
            for group in sorted(groups, key=stable_group_order):
                group_indices = groups[group]
                if chosen and len(chosen) + len(group_indices) > target:
                    continue
                chosen.extend(group_indices)
                if len(chosen) >= target:
                    break
        selected.extend(chosen)
        representations = Counter(
            str((records[index].get("_organized") or {}).get(
                "attack_representation", "unknown"
            ))
            for index in chosen
        )
        audit[attack_type] = {
            "available": len(indices),
            "selected": len(chosen),
            "all_retained": len(chosen) == len(indices),
            "representations": dict(sorted(representations.items())),
        }
    return np.asarray(sorted(selected), dtype=np.int64), audit


def binary_metrics(
    y: np.ndarray,
    probability: np.ndarray,
    threshold: float,
    attack_types: np.ndarray,
    representations: np.ndarray,
) -> dict:
    prediction = probability >= threshold
    cm = confusion_matrix(y, prediction, labels=[0, 1])
    tp = int(cm[1, 1])
    fp = int(cm[0, 1])
    fn = int(cm[1, 0])
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-15)
    type_recall = {}
    for attack_type in sorted(set(attack_types[y == 1].tolist())):
        mask = (y == 1) & (attack_types == attack_type)
        type_recall[attack_type] = {
            "records": int(mask.sum()),
            "recall": round(float(prediction[mask].mean()), 6),
        }
    representation_recall = {}
    for representation in sorted(set(representations[y == 1].tolist())):
        mask = (y == 1) & (representations == representation)
        representation_recall[representation] = {
            "records": int(mask.sum()),
            "recall": round(float(prediction[mask].mean()), 6),
        }
    macro_recall = float(
        np.mean([item["recall"] for item in type_recall.values()])
    )
    return {
        "auc": round(float(roc_auc_score(y, probability)), 6),
        "f1": round(f1, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "macro_type_recall": round(macro_recall, 6),
        "minimum_type_recall": round(
            min(item["recall"] for item in type_recall.values()), 6
        ),
        "fpr": round(float(cm[0, 1] / max(cm[0].sum(), 1)), 6),
        "confusion_matrix": cm.tolist(),
        "representation_recall": representation_recall,
        "type_recall": type_recall,
    }


def operating_point(
    y: np.ndarray,
    feature_probability: np.ndarray,
    text_probability: np.ndarray,
    attack_types: np.ndarray,
    representations: np.ndarray,
    *,
    min_recall: float,
    max_fpr: float,
) -> dict:
    """Efficiently maximize F1 + macro/type robustness under hard constraints."""
    best = None
    attack_mask = y == 1
    normal_total = int((y == 0).sum())
    attack_total = int(attack_mask.sum())
    type_names = sorted(set(attack_types[attack_mask].tolist()))
    type_totals = {
        name: int(np.sum(attack_mask & (attack_types == name)))
        for name in type_names
    }
    obfuscated_mask = attack_mask & (representations == "obfuscated")
    obfuscated_total = int(obfuscated_mask.sum())

    for text_weight in np.linspace(0.50, 0.90, 17):
        combined = (
            (1.0 - text_weight) * feature_probability
            + text_weight * text_probability
        )
        order = np.argsort(-combined, kind="mergesort")
        sorted_score = combined[order]
        sorted_y = y[order]
        tp = np.cumsum(sorted_y == 1)
        fp = np.cumsum(sorted_y == 0)
        boundary = np.r_[sorted_score[:-1] > sorted_score[1:], True]
        indices = np.flatnonzero(boundary)

        tp_i = tp[indices]
        fp_i = fp[indices]
        recall = tp_i / max(attack_total, 1)
        precision = tp_i / np.maximum(tp_i + fp_i, 1)
        f1 = 2 * precision * recall / np.maximum(precision + recall, 1e-15)
        fpr = fp_i / max(normal_total, 1)
        feasible = (recall >= min_recall) & (fpr <= max_fpr)
        if not feasible.any():
            continue

        macro_parts = []
        for name in type_names:
            sorted_type = (
                (sorted_y == 1) & (attack_types[order] == name)
            )
            type_tp = np.cumsum(sorted_type)[indices]
            macro_parts.append(type_tp / max(type_totals[name], 1))
        macro_recall = np.mean(np.vstack(macro_parts), axis=0)
        if obfuscated_total:
            obfuscated_recall = (
                np.cumsum(obfuscated_mask[order])[indices] / obfuscated_total
            )
        else:
            obfuscated_recall = recall

        composite = (
            0.45 * f1
            + 0.35 * macro_recall
            + 0.20 * obfuscated_recall
        )
        candidate_indices = np.flatnonzero(feasible)
        local = candidate_indices[np.argmax(composite[candidate_indices])]
        candidate = {
            "composite": float(composite[local]),
            "threshold": float(sorted_score[indices[local]]),
            "feature_weight": float(1.0 - text_weight),
            "text_weight": float(text_weight),
            "f1": float(f1[local]),
            "precision": float(precision[local]),
            "recall": float(recall[local]),
            "macro_type_recall": float(macro_recall[local]),
            "obfuscated_recall": float(obfuscated_recall[local]),
            "fpr": float(fpr[local]),
        }
        rank = (
            candidate["composite"],
            candidate["macro_type_recall"],
            candidate["obfuscated_recall"],
            candidate["f1"],
            -candidate["fpr"],
            candidate["threshold"],
        )
        if best is None or rank > best[0]:
            best = (rank, candidate)

    if best is None:
        raise RuntimeError(
            f"No operating point satisfies recall>={min_recall} and fpr<={max_fpr}"
        )
    return best[1]


def feature_model(positive_weight: float):
    return lgb.LGBMClassifier(
        objective="binary",
        metric="auc",
        n_estimators=1400,
        learning_rate=0.02,
        num_leaves=47,
        max_depth=-1,
        min_child_samples=30,
        subsample=0.9,
        subsample_freq=1,
        colsample_bytree=0.9,
        reg_alpha=0.1,
        reg_lambda=2.0,
        scale_pos_weight=positive_weight,
        random_state=SEED,
        n_jobs=-1,
        verbosity=-1,
        deterministic=True,
        force_col_wise=True,
    )


def metadata_arrays(records: list[dict]):
    y = np.asarray([int(item["label"]) for item in records], dtype=np.int32)
    attack_types = np.asarray(
        [str(item.get("attack_type", "normal")) for item in records]
    )
    representations = np.asarray(
        [
            str((item.get("_organized") or {}).get(
                "attack_representation", "normal"
            ))
            for item in records
        ]
    )
    return y, attack_types, representations


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-model-dir",
        type=Path,
        default=ROOT / "models" / "organized_full_candidate",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "models" / "sampling_search_candidate",
    )
    parser.add_argument("--rare-limit", type=int, default=2000)
    parser.add_argument(
        "--policies",
        nargs="+",
        default=["all", "cap_8000", "cap_6000", "cap_5000", "cap_4000", "cap_3000", "sqrt", "log"],
    )
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.001)
    args = parser.parse_args()
    started = time.perf_counter()

    data_root = core.resolve_data_root(None)
    datasets, data_audit = core.load_organized_fields(
        data_root, include_unspecified_in_train=True
    )
    y = {}
    attack_types = {}
    representations = {}
    for split in ("train", "validation", "test"):
        y[split], attack_types[split], representations[split] = metadata_arrays(
            datasets[split]
        )
    normal_indices = np.flatnonzero(y["train"] == 0)
    emit("data_loaded", counts=core.counts_for(datasets))

    with (args.base_model_dir / "text_lr_v4.pkl").open("rb") as handle:
        base_text_pipeline = pickle.load(handle)
    vectorizer = base_text_pipeline.named_steps["tfidf"]

    emit("extracting_features")
    x = {split: core.featurize(datasets[split]) for split in ("train", "validation", "test")}
    emit("transforming_text")
    text_matrix = {
        split: vectorizer.transform(
            [core.text_value(item) for item in datasets[split]]
        )
        for split in ("train", "validation", "test")
    }

    experiments = []
    best = None
    for policy in args.policies:
        attack_indices, sampling_audit = select_attack_indices(
            datasets["train"], policy, args.rare_limit
        )
        train_indices = np.sort(np.r_[normal_indices, attack_indices])
        train_y = y["train"][train_indices]
        imbalance = float(
            np.sum(train_y == 0) / max(np.sum(train_y == 1), 1)
        )
        emit(
            "policy_started",
            policy=policy,
            train_total=int(len(train_indices)),
            attack=int(np.sum(train_y == 1)),
            normal=int(np.sum(train_y == 0)),
            imbalance=imbalance,
        )

        classifier = LogisticRegression(
            C=2.0,
            max_iter=1000,
            solver="liblinear",
            random_state=SEED,
        )
        classifier.fit(text_matrix["train"][train_indices], train_y)
        text_probability_validation = classifier.predict_proba(
            text_matrix["validation"]
        )[:, 1]

        for weight_mode, positive_weight in (
            ("ratio", imbalance),
            ("sqrt_ratio", math.sqrt(imbalance)),
        ):
            model = feature_model(positive_weight)
            model.fit(
                x["train"][train_indices],
                train_y,
                eval_set=[(x["validation"], y["validation"])],
                eval_metric="auc",
                callbacks=[lgb.early_stopping(100, verbose=False)],
            )
            feature_probability_validation = model.predict_proba(
                x["validation"]
            )[:, 1]
            point = operating_point(
                y["validation"],
                feature_probability_validation,
                text_probability_validation,
                attack_types["validation"],
                representations["validation"],
                min_recall=args.min_recall,
                max_fpr=args.max_fpr,
            )
            fused_validation = (
                point["feature_weight"] * feature_probability_validation
                + point["text_weight"] * text_probability_validation
            )
            validation = binary_metrics(
                y["validation"],
                fused_validation,
                point["threshold"],
                attack_types["validation"],
                representations["validation"],
            )
            result = {
                "policy": policy,
                "weight_mode": weight_mode,
                "positive_weight": positive_weight,
                "train": {
                    "attack": int(np.sum(train_y == 1)),
                    "normal": int(np.sum(train_y == 0)),
                    "total": int(len(train_y)),
                },
                "operating_point": point,
                "validation": validation,
                "lightgbm_best_iteration": int(model.best_iteration_ or 0),
                "sampling": sampling_audit,
            }
            experiments.append(result)
            rank = (
                point["composite"],
                validation["macro_type_recall"],
                validation["representation_recall"]
                .get("obfuscated", {})
                .get("recall", 0.0),
                validation["f1"],
                -validation["fpr"],
            )
            emit(
                "candidate_completed",
                policy=policy,
                weight_mode=weight_mode,
                validation={
                    key: validation[key]
                    for key in (
                        "f1",
                        "precision",
                        "recall",
                        "macro_type_recall",
                        "minimum_type_recall",
                        "fpr",
                    )
                },
                operating_point=point,
            )
            if best is None or rank > best["rank"]:
                best = {
                    "rank": rank,
                    "result": result,
                    "feature_model": model,
                    "text_classifier": classifier,
                }
            elif model is not best.get("feature_model"):
                del model
        if classifier is not best.get("text_classifier"):
            del classifier
        gc.collect()

    if best is None:
        raise RuntimeError("No valid experiment completed")

    # The test split is touched exactly once, after validation-only selection.
    chosen = best["result"]
    chosen_model = best["feature_model"]
    chosen_classifier = best["text_classifier"]
    point = chosen["operating_point"]
    test_feature_probability = chosen_model.predict_proba(x["test"])[:, 1]
    test_text_probability = chosen_classifier.predict_proba(
        text_matrix["test"]
    )[:, 1]
    test_probability = (
        point["feature_weight"] * test_feature_probability
        + point["text_weight"] * test_text_probability
    )
    test = binary_metrics(
        y["test"],
        test_probability,
        point["threshold"],
        attack_types["test"],
        representations["test"],
    )

    final_text_pipeline = SkPipeline(
        [("tfidf", vectorizer), ("classifier", chosen_classifier)]
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "lgbm_v4.pkl").open("wb") as handle:
        pickle.dump(chosen_model, handle)
    with (args.output_dir / "text_lr_v4.pkl").open("wb") as handle:
        pickle.dump(final_text_pipeline, handle)

    report = {
        "version": "sampling-search-v1",
        "selection_rule": (
            "validation only: recall>=min_recall and fpr<=max_fpr; maximize "
            "0.45*F1 + 0.35*macro_type_recall + 0.20*obfuscated_recall"
        ),
        "test_usage": "evaluated once after final validation selection",
        "rare_limit": args.rare_limit,
        "policies": args.policies,
        "data_root": str(data_root),
        "data_audit": data_audit,
        "experiments": experiments,
        "selected": chosen,
        "threshold": round(point["threshold"], 8),
        "thresholds": {"high": round(point["threshold"], 8), "low": 0.05},
        "fusion": {
            "feature_weight": round(point["feature_weight"], 8),
            "text_weight": round(point["text_weight"], 8),
        },
        "validation": chosen["validation"],
        "test": test,
        "models": {
            "lightgbm_best_iteration": int(chosen_model.best_iteration_ or 0),
            "lightgbm_params": chosen_model.get_params(),
            "text_max_features": int(vectorizer.max_features),
            "text_ngram_range": list(vectorizer.ngram_range),
            "text_C": 2.0,
        },
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "environment": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "scikit_learn": __import__("sklearn").__version__,
            "lightgbm": lgb.__version__,
        },
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    (args.output_dir / "lgbm_v4.meta.json").write_text(encoded, encoding="utf-8")
    (args.output_dir / "sampling_search_results.json").write_text(
        encoded, encoding="utf-8"
    )
    emit(
        "search_completed",
        selected={
            "policy": chosen["policy"],
            "weight_mode": chosen["weight_mode"],
            "validation": chosen["validation"],
            "test": test,
        },
        output_dir=str(args.output_dir),
        elapsed_seconds=report["elapsed_seconds"],
    )


if __name__ == "__main__":
    main()
