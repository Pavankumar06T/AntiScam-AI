"""Run the Detection Agent against the synthetic test set and report metrics.

Computes precision, recall, F1, and — called out specifically because it is the
metric that matters most for a tool that warns real citizens — the false positive
rate on the legitimate subset. A scam detector that cries wolf gets muted, and then
it is useless on the call that counts.

Also reports:
- Per-scam-type recall (does it catch loan fraud as well as digital arrest?).
- Hard-negative false positive rate separately (the honest number: FPR on calls
  built to look scam-like, not on easy negatives).
- Average detection lead time: how early in the conversation risk first crosses the
  warn threshold, measured as a fraction of the way through the call. Earlier is
  better — it is the difference between a warning and a post-mortem.

A "positive" prediction is scam_probability >= WARN_THRESHOLD.

Cost warning: this makes one LLM call per sample per evaluated turn. On the full
60-sample set that is well beyond the Groq free-tier daily budget — see the README.
Use --limit to cap samples, or run on Dev Tier.

Usage:
    python scripts/evaluate.py                 # full set, final-transcript scoring
    python scripts/evaluate.py --limit 10      # cheap smoke run
    python scripts/evaluate.py --lead-time     # also compute lead time (costlier)
    python scripts/evaluate.py --out metrics.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# Windows consoles default to cp1252, which chokes on ₹ / Devanagari / box marks.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.agents.scam_detector import classify  # noqa: E402
from app.config import DATA_DIR, get_settings  # noqa: E402
from app.models.schemas import ClassifyRequest, Turn  # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(levelname)-7s | %(message)s")
logging.getLogger("app").setLevel(logging.ERROR)
logger = logging.getLogger("evaluate")

DATASET_PATH = DATA_DIR / "synthetic_transcripts.json"
WARN_THRESHOLD = None  # resolved from settings at runtime


def _turns_from_record(record: dict) -> list[Turn]:
    return [
        Turn(
            speaker=t.get("speaker", "unknown"),
            text=t["text"],
            timestamp=t.get("timestamp"),
            turn_index=i,
        )
        for i, t in enumerate(record["turns"])
    ]


def _score_full(record: dict) -> dict:
    turns = _turns_from_record(record)
    request = ClassifyRequest(
        conversation_id=record["id"], turns=turns, is_full_conversation=True
    )
    result = classify(request, allow_backoff=True)
    return {
        "id": record["id"],
        "true_label": record["label"],
        "true_scam_type": record.get("scam_type", "none"),
        "is_hard_negative": record.get("is_hard_negative", False),
        "score": result.scam_probability,
        "pred_scam_type": result.scam_type.value,
        "degraded": result.degraded,
        "latency_ms": result.latency_ms,
    }


def _lead_time(record: dict, threshold: int) -> float | None:
    """Fraction through the call where risk first crosses the warn threshold.

    0.0 = crossed on the very first turn, 1.0 = only at the end, None = never.
    Only meaningful for actual scams. Costs one call per turn, so it is opt-in.
    """
    turns = _turns_from_record(record)
    n = len(turns)
    for i in range(1, n + 1):
        request = ClassifyRequest(
            conversation_id=f"{record['id']}_lt{i}",
            turns=turns[:i],
            is_full_conversation=(i == n),
        )
        result = classify(request, allow_backoff=True)
        if result.scam_probability >= threshold:
            return round((i - 1) / max(1, n - 1), 3) if n > 1 else 0.0
    return None


def _metrics(results: list[dict], threshold: int) -> dict:
    tp = fp = tn = fn = 0
    for r in results:
        predicted_scam = r["score"] >= threshold
        actual_scam = r["true_label"] == "scam"
        if predicted_scam and actual_scam:
            tp += 1
        elif predicted_scam and not actual_scam:
            fp += 1
        elif not predicted_scam and not actual_scam:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy = (tp + tn) / len(results) if results else 0.0

    # Per-scam-type recall.
    by_type: dict[str, dict[str, int]] = {}
    for r in results:
        if r["true_label"] != "scam":
            continue
        t = r["true_scam_type"]
        by_type.setdefault(t, {"caught": 0, "total": 0})
        by_type[t]["total"] += 1
        if r["score"] >= threshold:
            by_type[t]["caught"] += 1
    type_recall = {
        t: round(v["caught"] / v["total"], 3) for t, v in sorted(by_type.items())
    }

    # Hard-negative FPR — the honest false-positive number.
    hard = [r for r in results if r["is_hard_negative"]]
    hard_fp = sum(1 for r in hard if r["score"] >= threshold)
    hard_fpr = hard_fp / len(hard) if hard else None

    scores_scam = [r["score"] for r in results if r["true_label"] == "scam"]
    scores_legit = [r["score"] for r in results if r["true_label"] == "legitimate"]

    return {
        "threshold": threshold,
        "counts": {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "total": len(results)},
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(fpr, 3),
        "accuracy": round(accuracy, 3),
        "recall_by_scam_type": type_recall,
        "hard_negative_fpr": round(hard_fpr, 3) if hard_fpr is not None else None,
        "hard_negative_count": len(hard),
        "mean_score_scam": round(sum(scores_scam) / len(scores_scam), 1) if scores_scam else None,
        "mean_score_legit": round(sum(scores_legit) / len(scores_legit), 1) if scores_legit else None,
        "degraded_samples": sum(1 for r in results if r["degraded"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the Detection Agent.")
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--limit", type=int, default=None, help="Cap samples (cheap runs).")
    parser.add_argument("--lead-time", action="store_true", help="Also compute lead time (costlier).")
    parser.add_argument("--out", type=Path, default=DATA_DIR / "metrics_report.json")
    args = parser.parse_args()

    settings = get_settings()
    threshold = settings.warn_threshold

    if not args.dataset.exists():
        logger.error(
            "Dataset not found at %s. Run scripts/generate_dataset.py first.", args.dataset
        )
        return 1
    if not settings.groq_configured:
        logger.warning(
            "GROQ_API_KEY not set — evaluation will run in DEGRADED (rule-only) mode. "
            "Metrics will reflect the rule layer alone, not the full detector."
        )

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    records = dataset["records"]
    if args.limit:
        # Keep the scam/legit balance when sampling.
        scam = [r for r in records if r["label"] == "scam"][: args.limit // 2]
        legit = [r for r in records if r["label"] == "legitimate"][: args.limit // 2]
        records = scam + legit

    logger.warning("Evaluating %d samples (threshold=%d)…", len(records), threshold)

    results = []
    started = time.time()
    for i, record in enumerate(records, 1):
        try:
            row = _score_full(record)
        except Exception as exc:
            logger.error("  %s failed: %s", record["id"], exc)
            continue
        results.append(row)
        correct = (row["score"] >= threshold) == (row["true_label"] == "scam")
        mark = "OK  " if correct else "MISS"
        print(
            f"  [{i:2}/{len(records)}] {mark} {record['id']:28} "
            f"score={row['score']:3} true={row['true_label']:11} "
            f"{'(degraded)' if row['degraded'] else ''}"
        )

    metrics = _metrics(results, threshold)

    if args.lead_time:
        logger.warning("Computing lead time on scam samples…")
        lead_times = []
        for record in records:
            if record["label"] != "scam":
                continue
            lt = _lead_time(record, threshold)
            if lt is not None:
                lead_times.append(lt)
        metrics["mean_lead_time_fraction"] = (
            round(sum(lead_times) / len(lead_times), 3) if lead_times else None
        )
        metrics["lead_time_note"] = (
            "0.0 = risk crossed threshold on the first turn; 1.0 = only at the end. "
            "Lower is earlier warning."
        )

    metrics["evaluated_at_unix"] = int(time.time())
    metrics["wall_seconds"] = round(time.time() - started, 1)
    metrics["model"] = dataset.get("meta", {}).get("generated_by_model", "unknown")
    metrics["degraded_mode"] = not settings.groq_configured

    report = {"metrics": metrics, "per_sample": results}
    args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print()
    print("=" * 60)
    print(" METRICS")
    print("=" * 60)
    print(f"  Precision            : {metrics['precision']}")
    print(f"  Recall               : {metrics['recall']}")
    print(f"  F1                   : {metrics['f1']}")
    print(f"  False positive rate  : {metrics['false_positive_rate']}")
    print(f"  Accuracy             : {metrics['accuracy']}")
    if metrics["hard_negative_fpr"] is not None:
        print(f"  Hard-negative FPR    : {metrics['hard_negative_fpr']}  ({metrics['hard_negative_count']} samples)")
    if metrics.get("mean_lead_time_fraction") is not None:
        print(f"  Mean lead time       : {metrics['mean_lead_time_fraction']} (0=earliest, 1=latest)")
    print(f"  Mean score  scam/legit: {metrics['mean_score_scam']} / {metrics['mean_score_legit']}")
    print(f"  Recall by type       : {metrics['recall_by_scam_type']}")
    if metrics["degraded_samples"]:
        print(f"  ⚠ degraded samples   : {metrics['degraded_samples']} (rule-only, LLM unavailable)")
    print("=" * 60)
    print(f"  Report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
