#!/usr/bin/env python3
"""Train the deployable field-payload detector from the organized JSONL view.

This trainer deliberately uses only records marked ``payload_model_eligible``.
Request/context/protocol/LLM records remain available for their own evaluators;
turning every parameter of a labelled request into a field label would create
label noise and inflate the apparent training size.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickle
import random
import sys
import time
from collections import Counter
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline as SkPipeline


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.extractor import FEATURE_NAMES, extract  # noqa: E402
from src.normalizer import normalize  # noqa: E402


SEED = 20260728
SPLITS = ("train", "validation", "test")
# The organized snapshot intentionally preserves this cross-source duplicate.
# Excluding its training copy in the shared eligibility policy keeps every
# training/evaluation entry point leakage-safe without per-script monkeypatches.
KNOWN_CROSS_SPLIT_DUPLICATE_ID = "mlwaf_c31520dda92f1db0ff6a73cc"


def _is_lfs_pointer(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.readline().strip() == b"version https://git-lfs.github.com/spec/v1"
    except OSError:
        return False


def _usable_organized_root(path: Path) -> bool:
    manifest = path / "manifest.json"
    if not manifest.is_file():
        return False
    candidates = list((path / "normal" / "field").glob("*.jsonl"))
    return bool(candidates) and not all(_is_lfs_pointer(item) for item in candidates)


def resolve_data_root(explicit: Path | None) -> Path:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    if value := os.environ.get("WAD_ORGANIZED_ROOT"):
        candidates.append(Path(value))
    candidates.extend((ROOT / "data" / "organized", ROOT.parent / "organized"))

    checked: list[str] = []
    for candidate in candidates:
        resolved = candidate.expanduser().resolve()
        if str(resolved) in checked:
            continue
        checked.append(str(resolved))
        if _usable_organized_root(resolved):
            return resolved
    raise FileNotFoundError(
        "No usable organized dataset was found. Checked: "
        + ", ".join(checked)
        + ". The project data/organized files may be Git LFS pointers; "
          "pass --data-root or set WAD_ORGANIZED_ROOT to the real dataset."
    )


def iter_jsonl(path: Path):
    if _is_lfs_pointer(path):
        raise RuntimeError(f"Git LFS pointer found instead of JSONL data: {path}")
    with path.open(encoding="utf-8-sig") as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at {path}:{line_number}: {exc}") from exc


def _payload(record: dict) -> str:
    return str(record.get("obfuscated_payload") or record.get("payload") or "")


def is_model_eligible(record: dict) -> bool:
    """Return whether a record may enter the field-level model dataset."""
    metadata = record.get("_organized")
    return (
        str(record.get("id", "")) != KNOWN_CROSS_SPLIT_DUPLICATE_ID
        and isinstance(metadata, dict)
        and metadata.get("payload_model_eligible") is True
        and str(metadata.get("data_level", "")) == "field"
        and bool(_payload(record))
        and len(_payload(record)) <= 8192
    )


def _record_key(record: dict) -> tuple:
    """Remove exact duplicate field examples without collapsing real variants."""
    payload = _payload(record)
    return (
        int(record.get("label", 0)),
        str(record.get("param_location", "query")),
        hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest(),
    )


def _append_unique(target: list[dict], seen: set[tuple], record: dict) -> bool:
    key = _record_key(record)
    if key in seen:
        return False
    seen.add(key)
    target.append(record)
    return True


def load_organized_fields(
    data_root: Path,
    *,
    include_unspecified_in_train: bool,
) -> tuple[dict[str, list[dict]], dict]:
    datasets = {split: [] for split in SPLITS}
    seen = {split: set() for split in SPLITS}
    audit = {
        "data_root": str(data_root),
        "loaded": {split: Counter() for split in SPLITS},
        "skipped_ineligible": Counter(),
        "skipped_duplicates": Counter(),
        "unspecified_policy": (
            "train_only" if include_unspecified_in_train else "excluded"
        ),
    }

    paths: list[tuple[Path, int, str]] = []
    normal_field = data_root / "normal" / "field"
    for split in (*SPLITS, "unspecified"):
        path = normal_field / f"{split}.jsonl"
        if path.is_file():
            paths.append((path, 0, "normal"))

    attack_root = data_root / "attack"
    for representation in ("original", "obfuscated"):
        representation_root = attack_root / representation
        if not representation_root.is_dir():
            continue
        for attack_type_root in sorted(representation_root.iterdir()):
            field_root = attack_type_root / "field"
            if not field_root.is_dir():
                continue
            for split in (*SPLITS, "unspecified"):
                path = field_root / f"{split}.jsonl"
                if path.is_file():
                    paths.append((path, 1, representation))

    for path, expected_label, representation in paths:
        source_split = path.stem
        target_split = (
            "train"
            if source_split == "unspecified" and include_unspecified_in_train
            else source_split
        )
        for record in iter_jsonl(path):
            if int(record.get("label", -1)) != expected_label:
                raise ValueError(f"Unexpected label in {path}: {record.get('id')}")
            if not is_model_eligible(record):
                audit["skipped_ineligible"][source_split] += 1
                continue
            if target_split not in datasets:
                audit["skipped_ineligible"][source_split] += 1
                continue
            if _append_unique(datasets[target_split], seen[target_split], record):
                audit["loaded"][target_split][
                    "normal" if expected_label == 0 else representation
                ] += 1
                if source_split == "unspecified":
                    audit["loaded"][target_split]["from_unspecified"] += 1
            else:
                audit["skipped_duplicates"][target_split] += 1

    # Exact content must never cross the formal split boundary.
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        overlap = seen[left] & seen[right]
        if overlap:
            raise RuntimeError(
                f"Exact payload leakage between {left} and {right}: {len(overlap)} records"
            )

    for split in SPLITS:
        random.Random(SEED + SPLITS.index(split)).shuffle(datasets[split])
        audit["loaded"][split] = dict(sorted(audit["loaded"][split].items()))
    audit["skipped_ineligible"] = dict(sorted(audit["skipped_ineligible"].items()))
    audit["skipped_duplicates"] = dict(sorted(audit["skipped_duplicates"].items()))
    return datasets, audit


def text_value(record: dict) -> str:
    """Exactly match ``DetectionPipeline.detect`` text-model input."""
    payload = _payload(record)
    location = str(record.get("param_location", "query"))
    restored, _ = normalize(payload, param_location=location)
    return f"{payload} __normalized__ {restored}"


def featurize(records: list[dict]) -> np.ndarray:
    matrix = np.zeros((len(records), len(FEATURE_NAMES)), dtype=np.float32)
    for index, record in enumerate(records):
        payload = _payload(record)
        location = str(record.get("param_location", "query"))
        restored, metadata = normalize(payload, param_location=location)
        matrix[index] = extract(payload, restored, metadata)
    return matrix


def metrics(y: np.ndarray, probability: np.ndarray, threshold: float) -> dict:
    prediction = probability >= threshold
    cm = confusion_matrix(y, prediction, labels=[0, 1])
    return {
        "auc": round(float(roc_auc_score(y, probability)), 6),
        "f1": round(float(f1_score(y, prediction, zero_division=0)), 6),
        "precision": round(float(precision_score(y, prediction, zero_division=0)), 6),
        "recall": round(float(recall_score(y, prediction, zero_division=0)), 6),
        "fpr": round(float(cm[0, 1] / max(cm[0].sum(), 1)), 6),
        "confusion_matrix": cm.tolist(),
    }


def select_operating_point(
    y: np.ndarray,
    feature_probability: np.ndarray,
    text_probability: np.ndarray,
    *,
    min_recall: float,
    max_fpr: float,
) -> dict:
    """Select on validation only; prefer feasible F1, then recall, then FPR."""
    candidates: list[tuple] = []
    fallback: list[tuple] = []
    negatives = y == 0
    for text_weight in np.linspace(0.60, 1.00, 17):
        combined = (
            (1.0 - text_weight) * feature_probability
            + text_weight * text_probability
        )
        # A fine deterministic grid is adequate for a calibrated linear fusion
        # and avoids selecting a threshold on the test split.
        for threshold in np.linspace(0.01, 0.99, 981):
            prediction = combined >= threshold
            recall = float(recall_score(y, prediction, zero_division=0))
            precision = float(precision_score(y, prediction, zero_division=0))
            f1 = float(f1_score(y, prediction, zero_division=0))
            fpr = float(np.mean(prediction[negatives])) if negatives.any() else 0.0
            item = (
                -f1,
                -recall,
                fpr,
                -precision,
                -threshold,
                float(text_weight),
                float(threshold),
            )
            fallback.append((max(0.0, min_recall - recall) + max(0.0, fpr - max_fpr), *item))
            if recall >= min_recall and fpr <= max_fpr:
                candidates.append(item)

    constraint_satisfied = bool(candidates)
    if candidates:
        chosen = min(candidates)
    else:
        _, *chosen_values = min(fallback)
        chosen = tuple(chosen_values)
    _, _, _, _, _, text_weight, threshold = chosen
    combined = (1.0 - text_weight) * feature_probability + text_weight * text_probability
    return {
        "threshold": threshold,
        "text_weight": text_weight,
        "feature_weight": 1.0 - text_weight,
        "constraints": {
            "min_recall": min_recall,
            "max_fpr": max_fpr,
            "satisfied": constraint_satisfied,
        },
        "validation": metrics(y, combined, threshold),
    }


def counts_for(datasets: dict[str, list[dict]]) -> dict:
    result = {}
    for split, records in datasets.items():
        labels = np.asarray([int(item["label"]) for item in records], dtype=np.int8)
        result[split] = {
            "attack": int(labels.sum()),
            "normal": int((labels == 0).sum()),
            "total": len(records),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train from all eligible organized field records"
    )
    parser.add_argument("--data-root", type=Path)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "models" / "current"
    )
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.001)
    parser.add_argument("--max-text-features", type=int, default=140_000)
    parser.add_argument(
        "--exclude-unspecified",
        action="store_true",
        help="Do not add the group-isolated unspecified field records to train",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the dataset and print exact counts without fitting models",
    )
    args = parser.parse_args()

    started = time.perf_counter()
    data_root = resolve_data_root(args.data_root)
    datasets, data_audit = load_organized_fields(
        data_root,
        include_unspecified_in_train=not args.exclude_unspecified,
    )
    counts = counts_for(datasets)
    print(json.dumps({"data_root": str(data_root), "counts": counts}, ensure_ascii=False, indent=2))
    if args.dry_run:
        print(json.dumps({"data_audit": data_audit}, ensure_ascii=False, indent=2))
        return

    y = {
        split: np.asarray([int(item["label"]) for item in records], dtype=np.int32)
        for split, records in datasets.items()
    }
    x = {}
    text = {}
    for split in SPLITS:
        print(f"Featurizing {split}: {len(datasets[split]):,}")
        x[split] = featurize(datasets[split])
        text[split] = [text_value(item) for item in datasets[split]]

    imbalance = float((y["train"] == 0).sum() / max((y["train"] == 1).sum(), 1))
    feature_model = lgb.LGBMClassifier(
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
        scale_pos_weight=imbalance,
        random_state=SEED,
        n_jobs=-1,
        verbosity=-1,
        deterministic=True,
        force_col_wise=True,
    )
    feature_model.fit(
        x["train"],
        y["train"],
        eval_set=[(x["validation"], y["validation"])],
        eval_metric="auc",
        callbacks=[lgb.early_stopping(100, verbose=False)],
    )

    text_model = SkPipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(2, 5),
                    min_df=2,
                    max_features=args.max_text_features,
                    sublinear_tf=True,
                    lowercase=True,
                    dtype=np.float32,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    C=2.0,
                    max_iter=1000,
                    solver="liblinear",
                    random_state=SEED,
                ),
            ),
        ]
    )
    text_model.fit(text["train"], y["train"])

    feature_probability = {
        split: np.asarray(feature_model.predict_proba(x[split])[:, 1], dtype=np.float64)
        for split in SPLITS
    }
    text_probability = {
        split: np.asarray(text_model.predict_proba(text[split])[:, 1], dtype=np.float64)
        for split in SPLITS
    }
    operating_point = select_operating_point(
        y["validation"],
        feature_probability["validation"],
        text_probability["validation"],
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
    )
    feature_weight = operating_point["feature_weight"]
    text_weight = operating_point["text_weight"]
    threshold = operating_point["threshold"]
    fused = {
        split: (
            feature_weight * feature_probability[split]
            + text_weight * text_probability[split]
        )
        for split in SPLITS
    }

    report = {
        "version": "organized-full-v1",
        "objective": "binary field-payload attack detection",
        "seed": SEED,
        "data_source": str(data_root),
        "data_policy": {
            "payload_model_eligible_only": True,
            "request_context_protocol_llm_excluded": True,
            "unspecified": data_audit["unspecified_policy"],
            "exact_duplicate_policy": "deduplicate within split; fail on cross-split overlap",
        },
        "counts": counts,
        "feature_count": len(FEATURE_NAMES),
        "text_format": "payload __normalized__ restored (matches runtime)",
        "threshold": round(threshold, 6),
        "thresholds": {"high": round(threshold, 6), "low": 0.05},
        "fusion": {
            "feature_weight": round(feature_weight, 6),
            "text_weight": round(text_weight, 6),
        },
        "threshold_selection": operating_point["constraints"],
        "validation": operating_point["validation"],
        "test": metrics(y["test"], fused["test"], threshold),
        "models": {
            "lightgbm_best_iteration": int(feature_model.best_iteration_ or 0),
            "lightgbm_params": feature_model.get_params(),
            "text_max_features": args.max_text_features,
            "text_ngram_range": [2, 5],
        },
        "data_audit": data_audit,
        "elapsed_seconds": round(time.perf_counter() - started, 2),
        "environment": {
            "python": sys.version.split()[0],
            "numpy": np.__version__,
            "scikit_learn": __import__("sklearn").__version__,
            "lightgbm": lgb.__version__,
        },
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "lgbm_v4.pkl").open("wb") as handle:
        pickle.dump(feature_model, handle)
    with (args.output_dir / "text_lr_v4.pkl").open("wb") as handle:
        pickle.dump(text_model, handle)
    metadata = {
        "format": "ai-waf-runtime-metadata-v4",
        "feature_order": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "threshold": report["threshold"],
        "thresholds": report["thresholds"],
        "fusion": report["fusion"],
        "models": report["models"],
        "training_results": "training_results.json",
        "deployment_status": "candidate",
    }
    (args.output_dir / "lgbm_v4.meta.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (args.output_dir / "training_results.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "saved_to": str(args.output_dir),
        "validation": report["validation"],
        "test": report["test"],
        "thresholds": report["thresholds"],
        "fusion": report["fusion"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
