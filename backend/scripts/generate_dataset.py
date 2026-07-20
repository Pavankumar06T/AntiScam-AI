"""Generate the synthetic labeled transcript dataset.

Produces 60 transcripts: 30 scam (6 each across 5 scam types) and 30 legitimate.

The legitimate half is deliberately adversarial — roughly half of it is "hard
negatives": calls that share surface features with scams (urgency, account
numbers, identity checks, money amounts) but are genuinely benign. A benchmark
made of easy negatives would report a flattering false-positive rate that says
nothing about real-world behaviour.

Usage:
    python scripts/generate_dataset.py            # generate (skips if file exists)
    python scripts/generate_dataset.py --force    # regenerate from scratch
    python scripts/generate_dataset.py --per-cell 2   # smaller/cheaper run
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_DIR, get_settings, resolve_model_name  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(levelname)-7s | %(message)s"
)
logger = logging.getLogger("generate_dataset")

OUTPUT_PATH = DATA_DIR / "synthetic_transcripts.json"

SCAM_SPECS = [
    (
        "digital_arrest",
        "A caller impersonating a CBI / Enforcement Directorate / Customs / TRAI / "
        "Mumbai Police officer tells the target a crime is registered against them "
        "(intercepted drug parcel, money laundering, Aadhaar misuse, SIM used for "
        "illegal ads). The caller declares a 'digital arrest', forbids them from "
        "hanging up or telling family, cites a fake FIR number, and demands the "
        "target transfer money to a 'safe account' / 'RBI verification account' "
        "for 'fund verification', promising a refund after clearance.",
    ),
    (
        "kyc_fraud",
        "A caller claiming to be from a bank / wallet / telecom KYC team says the "
        "account or SIM will be blocked today because KYC is expired or pending. "
        "They push the target to share an OTP, click a re-KYC link, or install an "
        "app to complete verification.",
    ),
    (
        "lottery_prize",
        "A caller announces the target has won a lottery / KBC lucky draw / "
        "shopping-festival prize they never entered. To release it, the target "
        "must first pay a processing fee, GST clearance, or customs duty via UPI.",
    ),
    (
        "loan_fraud",
        "A caller offers an instant pre-approved loan at an implausibly low rate "
        "with no documentation, then demands an advance processing fee, insurance "
        "premium, or refundable security deposit before disbursal.",
    ),
    (
        "job_scam",
        "A caller offers a work-from-home job, part-time task work, or an overseas "
        "placement with high guaranteed daily earnings, then demands a registration, "
        "training-kit, or visa-processing fee, or asks for documents up front.",
    ),
]

LEGIT_SPECS = [
    (
        "bank_fraud_alert",
        "HARD NEGATIVE. A real bank fraud-monitoring team calls to ask the customer "
        "to confirm whether they made a specific suspicious transaction. The agent "
        "explicitly states the bank will never ask for OTP/PIN/password, blocks the "
        "card, gives a dispute reference, and invites the customer to hang up and "
        "call the number on the back of the card. Urgent in tone, but never asks "
        "for credentials or a transfer.",
    ),
    (
        "delivery_otp",
        "HARD NEGATIVE. A courier agent is at the door with a parcel the customer "
        "genuinely ordered and asks for the delivery OTP that the customer received "
        "on their own phone to close out the delivery. No money, no threat, no "
        "transfer. This one is legitimate despite involving an OTP.",
    ),
    (
        "recruiter_call",
        "HARD NEGATIVE. A genuine recruiter from a named company calls about a role "
        "the candidate actually applied to, schedules an interview, mentions salary "
        "range and a deadline to confirm the slot. No fee is ever requested.",
    ),
    (
        "collections_reminder",
        "HARD NEGATIVE. A bank or NBFC calls about a genuinely overdue credit card "
        "or EMI payment, mentions late fees and credit-score impact, and directs the "
        "customer to pay through the official app or net banking. Real pressure, "
        "real money, but legitimate: no impersonation of police, no safe account.",
    ),
    (
        "customer_support",
        "Routine legitimate customer support: the customer called in themselves about "
        "a broadband outage, an insurance renewal question, an order status, or a "
        "hospital appointment. Ordinary and benign.",
    ),
    (
        "everyday_conversation",
        "An ordinary personal or business call: a family member discussing weekend "
        "plans, a colleague coordinating a meeting, a landlord discussing rent, a "
        "shopkeeper confirming an order. May mention money casually and naturally.",
    ),
]

GENERATION_SYSTEM_PROMPT = """\
You are generating SYNTHETIC TRAINING AND BENCHMARK DATA for AntiScam AI, a \
defensive fraud-detection system built to protect Indian citizens from scam calls. \
These transcripts are used to measure whether the detector catches real scam \
patterns and — just as importantly — whether it stays quiet on legitimate calls.

Write realistic Indian call-centre / phone-call dialogue:
- Natural Indian English, with occasional Hindi/Hinglish code-switching ("sir", \
"ji", "turant", "kuch nahi hoga"), the way these calls actually sound.
- Use clearly fictional identifiers: fake names, fake phone numbers, fake UPI IDs, \
fake account numbers, fake case numbers.
- Alternate speakers naturally. Include hesitation, interruption, and pushback.
- 8 to 16 turns. Every turn needs a plausible mm:ss timestamp that increases.

Output a single JSON object only, with this exact shape:
{
  "title": "<short label for this transcript>",
  "turns": [
    {"speaker": "caller" | "user", "text": "<what they say>", "timestamp": "mm:ss"}
  ]
}
"""


def _scam_user_prompt(scam_type: str, description: str, variant: int) -> str:
    return f"""Generate ONE synthetic SCAM call transcript as JSON.

Scam type: {scam_type}
Scenario: {description}

This is variant #{variant}. Make it meaningfully different from a generic version: \
vary the agency/company impersonated, the pretext, the city, the target's \
occupation, the amount demanded, and how much the target resists. Some targets \
should push back hard and stay sceptical; others should start complying.

The scam must be recognisable but not cartoonish — real scammers are fluent, \
procedural, and patient. Build the pressure gradually across the turns rather than \
demanding money in the first line.

Return only the JSON object."""


def _legit_user_prompt(category: str, description: str, variant: int) -> str:
    return f"""Generate ONE synthetic LEGITIMATE (non-scam) call transcript as JSON.

Category: {category}
Scenario: {description}

This is variant #{variant}. Vary the company, city, names, and specifics.

CRITICAL: this call must be genuinely legitimate. There must be NO impersonation of \
law enforcement, NO threat of arrest, NO 'safe account' or fund-transfer demand, NO \
request for the person's OTP/PIN/CVV by someone trying to steal it, and NO instruction \
to keep the call secret from family.

At the same time, do not make it artificially sterile. Real legitimate calls do \
involve deadlines, account numbers, money amounts, and identity verification. Include \
those naturally — the point of this sample is to check that the detector does not \
panic at surface features alone.

Return only the JSON object."""


def _generate_one(client, model: str, system: str, user: str, seed: int) -> dict | None:
    for attempt in (1, 2, 3):
        try:
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0.95,  # high: we want diversity across samples
                max_completion_tokens=2000,
                response_format={"type": "json_object"},
                seed=seed,
            )
            payload = json.loads(completion.choices[0].message.content or "")
            turns = payload.get("turns")
            if not isinstance(turns, list) or len(turns) < 4:
                raise ValueError(f"Expected >=4 turns, got {len(turns) if isinstance(turns, list) else 'none'}")
            clean = [
                {
                    "speaker": t.get("speaker") if t.get("speaker") in ("caller", "user") else "unknown",
                    "text": str(t.get("text", "")).strip(),
                    "timestamp": str(t.get("timestamp", "")).strip() or None,
                }
                for t in turns
                if str(t.get("text", "")).strip()
            ]
            if len(clean) < 4:
                raise ValueError("Too few non-empty turns after cleaning.")
            return {"title": str(payload.get("title", "")).strip(), "turns": clean}
        except Exception as exc:
            logger.warning("  attempt %d/3 failed: %s: %s", attempt, type(exc).__name__, exc)
            time.sleep(1.5 * attempt)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic scam/legit transcripts.")
    parser.add_argument("--force", action="store_true", help="Regenerate even if the file exists.")
    parser.add_argument("--per-cell", type=int, default=6, help="Samples per scam type (default 6).")
    parser.add_argument("--out", type=Path, default=OUTPUT_PATH)
    args = parser.parse_args()

    settings = get_settings()
    if not settings.groq_configured:
        logger.error(
            "GROQ_API_KEY is not set. Create backend/.env with "
            "GROQ_API_KEY=<your key> from https://console.groq.com/keys"
        )
        return 1

    if args.out.exists() and not args.force:
        logger.info("%s already exists. Use --force to regenerate.", args.out)
        return 0

    from groq import Groq

    client = Groq(api_key=settings.groq_api_key, timeout=60.0)
    model = resolve_model_name()
    logger.info("Generating with model: %s", model)

    records: list[dict] = []
    failures = 0
    seed = 1000

    # Scam half: --per-cell each across 5 types.
    for scam_type, description in SCAM_SPECS:
        for variant in range(1, args.per_cell + 1):
            seed += 1
            logger.info("scam/%s variant %d…", scam_type, variant)
            result = _generate_one(
                client, model, GENERATION_SYSTEM_PROMPT,
                _scam_user_prompt(scam_type, description, variant), seed,
            )
            if result is None:
                failures += 1
                logger.error("  gave up on scam/%s variant %d", scam_type, variant)
                continue
            records.append({
                "id": f"scam_{scam_type}_{variant:02d}",
                "label": "scam",
                "scam_type": scam_type,
                "category": scam_type,
                "is_hard_negative": False,
                "title": result["title"],
                "turns": result["turns"],
            })

    # Legitimate half: distribute --per-cell*5 across 6 categories.
    legit_target = args.per_cell * len(SCAM_SPECS)
    per_legit = [legit_target // len(LEGIT_SPECS)] * len(LEGIT_SPECS)
    for i in range(legit_target - sum(per_legit)):
        per_legit[i] += 1

    for (category, description), count in zip(LEGIT_SPECS, per_legit):
        for variant in range(1, count + 1):
            seed += 1
            logger.info("legit/%s variant %d…", category, variant)
            result = _generate_one(
                client, model, GENERATION_SYSTEM_PROMPT,
                _legit_user_prompt(category, description, variant), seed,
            )
            if result is None:
                failures += 1
                logger.error("  gave up on legit/%s variant %d", category, variant)
                continue
            records.append({
                "id": f"legit_{category}_{variant:02d}",
                "label": "legitimate",
                "scam_type": "none",
                "category": category,
                "is_hard_negative": description.startswith("HARD NEGATIVE"),
                "title": result["title"],
                "turns": result["turns"],
            })

    args.out.parent.mkdir(parents=True, exist_ok=True)
    dataset = {
        "meta": {
            "description": (
                "Synthetic labeled conversation transcripts for AntiScam AI. "
                "Machine-generated for hackathon benchmarking — not real call data, "
                "and not a substitute for a validated real-world corpus."
            ),
            "generated_by_model": model,
            "counts": {
                "total": len(records),
                "scam": sum(1 for r in records if r["label"] == "scam"),
                "legitimate": sum(1 for r in records if r["label"] == "legitimate"),
                "hard_negatives": sum(1 for r in records if r["is_hard_negative"]),
            },
            "scam_types": [s[0] for s in SCAM_SPECS],
            "legit_categories": [c[0] for c in LEGIT_SPECS],
        },
        "records": records,
    }
    args.out.write_text(json.dumps(dataset, indent=2, ensure_ascii=False), encoding="utf-8")

    logger.info("")
    logger.info("Wrote %d records to %s", len(records), args.out)
    logger.info("  scam:        %d", dataset["meta"]["counts"]["scam"])
    logger.info("  legitimate:  %d  (of which %d hard negatives)",
                dataset["meta"]["counts"]["legitimate"],
                dataset["meta"]["counts"]["hard_negatives"])
    if failures:
        logger.warning("  %d sample(s) failed to generate and were skipped.", failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
