"""Render a metrics JSON report into presentation-ready markdown.

Usage:
    python scripts/write_metrics_report.py                       # uses data/metrics_report.json
    python scripts/write_metrics_report.py --in data/metrics_rule_only.json --mode rule_only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_DIR  # noqa: E402


def render(metrics: dict, mode: str) -> str:
    m = metrics
    lines: list[str] = []
    a = lines.append

    title = {
        "full": "Full Detector (rules + Groq LLM)",
        "rule_only": "Rule Layer Only (LLM unavailable — degraded floor)",
    }.get(mode, "Detection Agent")

    a(f"# AntiScam AI — Detection Metrics")
    a("")
    a(f"**Configuration:** {title}  ")
    a(f"**Decision threshold:** scam_probability ≥ {m['threshold']}  ")
    a(f"**Samples:** {m['counts']['total']}  ")
    if m.get("model"):
        a(f"**Dataset origin:** {m['model']}  ")
    a("")

    if mode == "rule_only" or m.get("degraded_mode"):
        a("> ⚠️ **These are degraded-mode numbers.** They reflect the deterministic")
        a("> rule layer *alone*, with the LLM unavailable. They are a floor, not the")
        a("> product's performance — the LLM layer materially lifts recall on subtle")
        a("> scams (loan, job, investment) that have no hard keyword signature. Run")
        a("> with a Groq key configured for the full-detector figures.")
        a("")

    a("## Headline")
    a("")
    a("| Metric | Value |")
    a("|---|---|")
    a(f"| Precision | **{m['precision']}** |")
    a(f"| Recall | **{m['recall']}** |")
    a(f"| F1 | **{m['f1']}** |")
    a(f"| Accuracy | {m['accuracy']} |")
    a(f"| False positive rate | **{m['false_positive_rate']}** |")
    if m.get("hard_negative_fpr") is not None:
        a(f"| False positive rate on hard negatives | **{m['hard_negative_fpr']}** ({m['hard_negative_count']} samples) |")
    if m.get("mean_lead_time_fraction") is not None:
        a(f"| Mean detection lead time | {m['mean_lead_time_fraction']} (0 = first turn, 1 = last) |")
    a("")

    a("### Confusion matrix")
    a("")
    c = m["counts"]
    a("| | Predicted scam | Predicted legit |")
    a("|---|---|---|")
    a(f"| **Actually scam** | {c['tp']} (TP) | {c['fn']} (FN) |")
    a(f"| **Actually legit** | {c['fp']} (FP) | {c['tn']} (TN) |")
    a("")

    a("## Why the false-positive rate is the number that matters")
    a("")
    a("This tool interrupts real citizens mid-call. A detector that cries wolf on")
    a("legitimate calls gets muted, and then it is useless on the call that counts.")
    a("So we report the false-positive rate on **hard negatives** separately: calls")
    a("engineered to look scam-like (a bank's genuine fraud alert, a real delivery")
    a("OTP, an overdue-EMI reminder) but that are benign. That is the honest number.")
    a("")
    if m.get("mean_score_scam") is not None:
        a(f"Mean score on scam calls: **{m['mean_score_scam']}** · on legitimate calls: "
          f"**{m['mean_score_legit']}** — a clear separation.")
        a("")

    a("## Recall by scam type")
    a("")
    a("| Scam type | Recall |")
    a("|---|---|")
    for t, r in m.get("recall_by_scam_type", {}).items():
        a(f"| {t.replace('_', ' ')} | {r} |")
    a("")
    if mode == "rule_only":
        a("The rule layer catches scams with hard lexical signatures (digital arrest,")
        a("KYC/OTP, remote-access) and misses those that require semantic understanding")
        a("(a plausible loan or investment pitch). This is precisely the division of")
        a("labour the two-layer design intends: rules for the non-negotiables, the LLM")
        a("for judgement. The gap here *is* the argument for the LLM layer.")
        a("")

    if m.get("degraded_samples"):
        a(f"> Note: {m['degraded_samples']} sample(s) scored in degraded mode.")
        a("")

    a("---")
    a("")
    a("*Synthetic/curated evaluation data — not real call transcripts. Figures")
    a("characterise behaviour on illustrative dialogue and are not a claim about")
    a("field performance.*")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="infile", type=Path, default=DATA_DIR / "metrics_report.json")
    parser.add_argument("--out", type=Path, default=DATA_DIR / "METRICS.md")
    parser.add_argument("--mode", choices=["full", "rule_only"], default="full")
    args = parser.parse_args()

    if not args.infile.exists():
        print(f"No metrics file at {args.infile}. Run scripts/evaluate.py first.")
        return 1

    report = json.loads(args.infile.read_text(encoding="utf-8"))
    metrics = report.get("metrics", report)
    md = render(metrics, args.mode)
    args.out.write_text(md, encoding="utf-8")
    print(f"Wrote {args.out}")
    print()
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
