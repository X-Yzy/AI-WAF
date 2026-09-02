#!/usr/bin/env python3
"""Train the validated final field detector from the complete organized dataset.

Policy:
* use only field records explicitly marked payload_model_eligible;
* keep every attack type with at most 2,000 eligible training records;
* reduce only over-represented types, by stable original groups;
* keep every eligible normal training record;
* choose fusion weights and threshold on validation only;
* evaluate the selected operating point once on the untouched test split.
"""

from __future__ import annotations

import argparse
import json
import pickle
import sys
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline as SkPipeline


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.extractor import FEATURE_NAMES  # noqa: E402
from training import search_sampling_strategy as search  # noqa: E402
from training import train_organized_full as core  # noqa: E402


def emit(message: str, **values) -> None:
    print(json.dumps({"message": message, **values}, ensure_ascii=False), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", type=Path, default=ROOT / "data" / "organized")
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "models" / "candidate"
    )
    parser.add_argument("--rare-limit", type=int, default=2000)
    parser.add_argument("--abundant-cap", type=int, default=8000)
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.001)
    parser.add_argument("--max-text-features", type=int, default=140_000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    started = time.perf_counter()

    data_root = core.resolve_data_root(args.data_root)
    datasets, data_audit = core.load_organized_fields(
        data_root, include_unspecified_in_train=True
    )
    labels = {}
    attack_types = {}
    representations = {}
    for split in ("train", "validation", "test"):
        labels[split], attack_types[split], representations[split] = (
            search.metadata_arrays(datasets[split])
        )

    attack_indices, sampling_audit = search.select_attack_indices(
        datasets["train"], f"cap_{args.abundant_cap}", args.rare_limit
    )
    normal_indices = np.flatnonzero(labels["train"] == 0)
    train_indices = np.sort(np.r_[normal_indices, attack_indices])
    train_records = [datasets["train"][index] for index in train_indices]
    train_y = labels["train"][train_indices]

    audit_summary = {
        "data_root": str(data_root),
        "train_records": len(train_records),
        "train_normal": int(np.sum(train_y == 0)),
        "train_attack": int(np.sum(train_y == 1)),
        "validation_records": len(datasets["validation"]),
        "test_records": len(datasets["test"]),
        "attack_types": len(sampling_audit),
        "types_fully_retained": sum(
            int(item["all_retained"]) for item in sampling_audit.values()
        ),
        "sampling_by_type": sampling_audit,
    }
    emit("data_audit_completed", summary=audit_summary)
    if args.dry_run:
        return

    emit("building_38d_features")
    train_x = core.featurize(train_records)
    validation_x = core.featurize(datasets["validation"])
    test_x = core.featurize(datasets["test"])

    imbalance = float(np.sum(train_y == 0) / max(np.sum(train_y == 1), 1))
    feature_model = search.feature_model(imbalance)
    feature_model.fit(
        train_x,
        train_y,
        eval_set=[(validation_x, labels["validation"])],
        eval_metric="auc",
        callbacks=[lgb.early_stopping(100, verbose=False)],
    )
    emit("lightgbm_completed", best_iteration=int(feature_model.best_iteration_ or 0))

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
                    C=6.0,
                    max_iter=1600,
                    solver="liblinear",
                    random_state=search.SEED,
                ),
            ),
        ]
    )
    emit("training_text_model")
    text_model.fit([core.text_value(item) for item in train_records], train_y)

    feature_probability = {
        "validation": feature_model.predict_proba(validation_x)[:, 1],
        "test": feature_model.predict_proba(test_x)[:, 1],
    }
    text_probability = {
        "validation": text_model.predict_proba(
            [core.text_value(item) for item in datasets["validation"]]
        )[:, 1],
        "test": text_model.predict_proba(
            [core.text_value(item) for item in datasets["test"]]
        )[:, 1],
    }
    point = search.operating_point(
        labels["validation"],
        feature_probability["validation"],
        text_probability["validation"],
        attack_types["validation"],
        representations["validation"],
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
    )
    fused_validation = (
        point["feature_weight"] * feature_probability["validation"]
        + point["text_weight"] * text_probability["validation"]
    )
    fused_test = (
        point["feature_weight"] * feature_probability["test"]
        + point["text_weight"] * text_probability["test"]
    )
    validation = search.binary_metrics(
        labels["validation"],
        fused_validation,
        point["threshold"],
        attack_types["validation"],
        representations["validation"],
    )
    test = search.binary_metrics(
        labels["test"],
        fused_test,
        point["threshold"],
        attack_types["test"],
        representations["test"],
    )

    report = {
        "version": "final-c6-organized-v1",
        "objective": "binary field-payload attack detection",
        "seed": search.SEED,
        "selection_rule": (
            f"validation only: recall>={args.min_recall:g} and "
            f"fpr<={args.max_fpr:g}; maximize "
            "0.45*F1 + 0.35*macro_type_recall + 0.20*obfuscated_recall"
        ),
        "selection_constraints": {
            "minimum_validation_recall": args.min_recall,
            "maximum_validation_fpr": args.max_fpr,
        },
        "data_policy": {
            "payload_model_eligible_only": True,
            "request_context_protocol_llm_excluded_from_field_model": True,
            "unspecified_records": "train_only",
            "exact_duplicates": "deduplicate within split and reject cross-split",
            "rare_limit": args.rare_limit,
            "abundant_cap": args.abundant_cap,
            "group_aware_sampling": True,
        },
        "data_audit": data_audit,
        "sampling": audit_summary,
        "feature_order": list(FEATURE_NAMES),
        "threshold": round(point["threshold"], 8),
        "thresholds": {"high": round(point["threshold"], 8), "low": 0.05},
        "fusion": {
            "feature_weight": round(point["feature_weight"], 8),
            "text_weight": round(point["text_weight"], 8),
        },
        "validation": validation,
        "test": test,
        "models": {
            "lightgbm_best_iteration": int(feature_model.best_iteration_ or 0),
            "lightgbm_params": feature_model.get_params(),
            "text_analyzer": "char",
            "text_ngram_range": [2, 5],
            "text_max_features": args.max_text_features,
            "text_vocabulary_size": len(
                text_model.named_steps["tfidf"].vocabulary_
            ),
            "text_C": 6.0,
        },
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
        "feature_order": report["feature_order"],
        "feature_count": len(report["feature_order"]),
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
    emit(
        "training_completed",
        output_dir=str(args.output_dir),
        validation=validation,
        test=test,
        thresholds=report["thresholds"],
        fusion=report["fusion"],
        elapsed_seconds=report["elapsed_seconds"],
    )


if __name__ == "__main__":
    main()
