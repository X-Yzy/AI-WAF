#!/usr/bin/env python3
"""Replay bundled scanner/benign sessions through the behaviour detector."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.scanner_detector import ScannerBehaviorDetector


def request_parts(raw: str) -> tuple[str, str]:
    lines = raw.replace("\r\n", "\n").splitlines()
    target = "/"
    if lines:
        match = re.match(r"^[A-Z]+\s+(\S+)", lines[0], re.I)
        if match:
            target = match.group(1)
    user_agent = ""
    for line in lines[1:]:
        if line.lower().startswith("user-agent:"):
            user_agent = line.split(":", 1)[1].strip()
            break
    return target, user_agent


def metrics(labels: list[int], predictions: list[int]) -> dict:
    tp = sum(y == 1 and p == 1 for y, p in zip(labels, predictions))
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predictions))
    return {
        "records": len(labels), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "recall": round(tp / max(tp + fn, 1), 6),
        "fpr": round(fp / max(fp + tn, 1), 6),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dataset", type=Path,
        default=ROOT / "data" / "specialized_traffic" / "generated" / "scanner_sequences",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    records = []
    for path in sorted(args.dataset.glob("dataset_scanner_sequences_*.json")):
        records.extend(json.loads(path.read_text(encoding="utf-8")))
    sessions = defaultdict(list)
    for item in records:
        sessions[str(item["session_id"])].append(item)
    request_labels, request_predictions = [], []
    session_labels, session_predictions = [], []
    first_detection = {}
    for session, values in sorted(sessions.items()):
        detector = ScannerBehaviorDetector()
        values.sort(key=lambda item: int(item["sequence_index"]))
        predictions = []
        for item in values:
            target, agent = request_parts(str(item["raw_request"]))
            decision = detector.observe(session, target, agent, now=float(item["sequence_index"]) / 10)
            prediction = int(decision.verdict)
            predictions.append(prediction)
            request_labels.append(int(item["label"]))
            request_predictions.append(prediction)
            if prediction and session not in first_detection:
                first_detection[session] = int(item["sequence_index"])
        session_labels.append(int(values[0]["label"]))
        session_predictions.append(int(any(predictions)))
    report = {
        "dataset_records": len(records), "sessions": len(sessions),
        "request_level": metrics(request_labels, request_predictions),
        "session_level": metrics(session_labels, session_predictions),
        "first_detection_index": first_detection,
        "policy": "User-Agent alone is insufficient; verdict requires combined sequence evidence",
    }
    output = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
