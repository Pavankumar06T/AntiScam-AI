"""Build a hand-curated labeled evaluation set — no API, no tokens.

Why hand-authored rather than only LLM-generated:

The build plan called for a Groq-generated synthetic set, and the generator exists
(scripts/generate_dataset.py). But a benchmark's whole value is trustworthy labels,
and for a *benchmark* hand-authored transcripts are arguably stronger: a human wrote
each one to embody a specific pattern, so the label is ground truth by construction
rather than by a second model's say-so. It is also fully reproducible by anyone with
no API key and no token budget — which, given the free-tier ceiling, matters.

The set is deliberately balanced and adversarial:
- Every scam type is represented.
- Half the legitimate half are HARD NEGATIVES: calls engineered to trip a naive
  detector (urgency, account numbers, a real delivery OTP, identity checks) while
  being genuinely benign. The false-positive rate on these is the number that
  actually predicts real-world trust.

This produces data/curated_transcripts.json in the same schema the generator emits,
so scripts/evaluate.py consumes either interchangeably.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_DIR  # noqa: E402

OUTPUT_PATH = DATA_DIR / "curated_transcripts.json"


def T(speaker, text, ts):
    return {"speaker": speaker, "text": text, "timestamp": ts}


# --- SCAM transcripts (one+ per type) ---------------------------------------

SCAM = [
    {
        "id": "scam_digital_arrest_01",
        "scam_type": "digital_arrest",
        "title": "CBI parcel / NDPS digital arrest",
        "turns": [
            T("caller", "Am I speaking with Rajesh Kumar? This is Inspector Vikram Rathore from CBI Mumbai, badge 4471.", "00:04"),
            T("user", "Yes. What is this about?", "00:10"),
            T("caller", "A parcel in your name to Taiwan was seized. It contained 400 grams of MDMA and fake passports. FIR MUM/CBI/2024/8871 is registered against you under the NDPS Act.", "00:26"),
            T("user", "I never sent any parcel!", "00:33"),
            T("caller", "Your Aadhaar was used, this is money laundering. You are under digital arrest. Do not disconnect this video call and do not inform your family.", "00:49"),
            T("caller", "To prove your funds are clean, transfer your balance to RBI verification account 50100294471882. It refunds in two hours, or a non-bailable warrant issues tonight.", "01:12"),
        ],
    },
    {
        "id": "scam_digital_arrest_02",
        "scam_type": "digital_arrest",
        "title": "TRAI-to-cybercrime SIM misuse",
        "turns": [
            T("caller", "This is the Telecom Regulatory Authority. Your number will be deactivated in two hours for illegal activity.", "00:03"),
            T("user", "Why? I paid my bill.", "00:09"),
            T("caller", "Nine complaints of illegal advertising are registered against your SIM in Andheri. I am transferring you to the cyber crime department now.", "00:21"),
            T("caller", "Officer speaking. A money laundering case is open against your Aadhaar. Do not tell anyone. Stay on this call.", "00:38"),
            T("caller", "You must move your savings to a government safe account for verification, account number 39100288812major, immediately.", "00:55"),
        ],
    },
    {
        "id": "scam_kyc_fraud_01",
        "scam_type": "kyc_fraud",
        "title": "KYC-expiry OTP + AnyDesk",
        "turns": [
            T("caller", "Calling from your bank. Your KYC has expired and the account will be blocked within two hours.", "00:05"),
            T("user", "Oh no, what do I do?", "00:11"),
            T("caller", "Just a quick verification. I am sending an OTP now — please read it out to complete the update.", "00:22"),
            T("user", "It says 4412...", "00:29"),
            T("caller", "Good. Now install AnyDesk from the Play Store so I can complete the re-KYC on your screen.", "00:41"),
        ],
    },
    {
        "id": "scam_lottery_prize_01",
        "scam_type": "lottery_prize",
        "title": "KBC lucky draw / GST advance fee",
        "turns": [
            T("caller", "Congratulations! Your number won 25 lakh in the KBC Lucky Draw!", "00:03"),
            T("user", "But I never entered any draw.", "00:09"),
            T("caller", "It is automatic for all subscribers. Just pay the 5% GST clearance of Rs 12,500 to release the prize.", "00:21"),
            T("caller", "Send it via UPI to kbcclaim2024@ybl and the full amount credits in 24 hours.", "00:33"),
        ],
    },
    {
        "id": "scam_loan_fraud_01",
        "scam_type": "loan_fraud",
        "title": "Instant pre-approved loan / processing fee",
        "turns": [
            T("caller", "Sir, you are pre-approved for a 5 lakh instant loan at 2% interest, no documents needed.", "00:04"),
            T("user", "That sounds very low. What is the catch?", "00:11"),
            T("caller", "No catch. Only a refundable processing fee of Rs 3,500 is required before disbursal. Pay to account 771100294455 and the loan is credited today.", "00:27"),
            T("user", "Why do I pay before getting the loan?", "00:34"),
            T("caller", "It is a security formality, fully refundable with your first EMI. Pay now to lock this offer.", "00:47"),
        ],
    },
    {
        "id": "scam_job_scam_01",
        "scam_type": "job_scam",
        "title": "Work-from-home task job / registration fee",
        "turns": [
            T("caller", "We saw your resume. A work-from-home data job pays Rs 3,000 daily, just two hours of tasks.", "00:05"),
            T("user", "That sounds good. How do I start?", "00:12"),
            T("caller", "A one-time registration and training-kit fee of Rs 1,999 is required. Pay to raj.hr@paytm and we activate your account.", "00:26"),
            T("caller", "Slots are filling fast, please pay within the hour to confirm your seat.", "00:37"),
        ],
    },
    {
        "id": "scam_investment_fraud_01",
        "scam_type": "investment_fraud",
        "title": "Guaranteed-return trading group",
        "turns": [
            T("caller", "Join our VIP trading group. Our members double their money every month, guaranteed returns.", "00:04"),
            T("user", "Guaranteed? Really?", "00:09"),
            T("caller", "Yes, our AI algorithm never loses. Deposit Rs 50,000 to start on our platform, link is invest-profit-pro.co.", "00:22"),
            T("caller", "This offer closes tonight. Transfer to UPI winbig.trade@okhdfcbank now to secure your slot.", "00:36"),
        ],
    },
    {
        "id": "scam_tech_support_01",
        "scam_type": "tech_support",
        "title": "Fake tech support / remote access",
        "turns": [
            T("caller", "This is Microsoft support. Your computer is sending virus signals and your bank account is at risk.", "00:04"),
            T("user", "Oh! What should I do?", "00:10"),
            T("caller", "Install AnyDesk immediately so I can remove the virus and secure your net banking. Do not turn off the screen.", "00:24"),
            T("caller", "Now open your banking app so I can verify no money was stolen. Read me the OTP if one arrives.", "00:39"),
        ],
    },
]

# --- LEGITIMATE transcripts (half are hard negatives) -----------------------

LEGIT = [
    {
        "id": "legit_bank_fraud_alert_01",
        "category": "bank_fraud_alert",
        "is_hard_negative": True,
        "title": "Genuine bank fraud desk — confirm transaction",
        "turns": [
            T("caller", "Hi, this is Priya from HDFC Bank's fraud monitoring team. Am I speaking with Mr. Anand?", "00:04"),
            T("user", "Yes, speaking.", "00:08"),
            T("caller", "We flagged a Rs 45,000 transaction on your card ending 4412 in Hyderabad ten minutes ago. Can you confirm if this was you?", "00:20"),
            T("user", "No, I am in Pune. That was not me.", "00:27"),
            T("caller", "I am blocking the card now. I will never ask for your OTP, PIN, or password, and no bank employee ever will.", "00:40"),
            T("caller", "Your dispute reference is DSP-88214. To verify this call, please hang up and dial the number on the back of your card.", "00:55"),
        ],
    },
    {
        "id": "legit_delivery_otp_01",
        "category": "delivery_otp",
        "is_hard_negative": True,
        "title": "Genuine courier — delivery OTP for real parcel",
        "turns": [
            T("caller", "Hello, this is Ravi from Delhivery. I am at your gate with an Amazon parcel.", "00:03"),
            T("user", "Yes, I was expecting it. Coming down.", "00:09"),
            T("caller", "Could you share the delivery OTP that came to your phone so I can mark it delivered?", "00:18"),
            T("user", "Sure, it is 7721.", "00:24"),
            T("caller", "Thank you, delivered. Have a good day!", "00:29"),
        ],
    },
    {
        "id": "legit_collections_01",
        "category": "collections_reminder",
        "is_hard_negative": True,
        "title": "Genuine overdue-EMI reminder",
        "turns": [
            T("caller", "Good afternoon, this is Sneha from Bajaj Finance about your personal loan EMI.", "00:04"),
            T("user", "Yes, I know it is a few days late.", "00:10"),
            T("caller", "Your EMI of Rs 8,400 was due on the 5th. A late fee applies and it may affect your credit score.", "00:22"),
            T("caller", "You can pay through the Bajaj Finserv app or net banking. Would you like the payment link by SMS?", "00:34"),
            T("user", "Yes please, I will pay today.", "00:40"),
        ],
    },
    {
        "id": "legit_recruiter_01",
        "category": "recruiter_call",
        "is_hard_negative": True,
        "title": "Genuine recruiter — interview scheduling, no fee",
        "turns": [
            T("caller", "Hi Meera, this is Karan from TCS talent acquisition, about the software role you applied for.", "00:05"),
            T("user", "Yes, hello.", "00:09"),
            T("caller", "We would like to schedule a technical interview. Are you available Thursday at 3pm?", "00:19"),
            T("user", "Thursday works. Is there any fee for the process?", "00:26"),
            T("caller", "No, absolutely not — we never charge candidates. You will get a calendar invite from our official domain shortly.", "00:39"),
        ],
    },
    {
        "id": "legit_customer_support_01",
        "category": "customer_support",
        "is_hard_negative": False,
        "title": "Routine broadband support (user initiated)",
        "turns": [
            T("user", "Hi, I called because my broadband has been down since morning.", "00:04"),
            T("caller", "Sorry about that. I can see an outage in your area, engineers are on it. It should be back within four hours.", "00:17"),
            T("user", "Okay, will I get a refund for the downtime?", "00:24"),
            T("caller", "Yes, a pro-rated credit will apply automatically to your next bill. Your ticket number is BB-55210.", "00:36"),
        ],
    },
    {
        "id": "legit_everyday_01",
        "category": "everyday_conversation",
        "is_hard_negative": False,
        "title": "Ordinary personal call",
        "turns": [
            T("user", "Hey, are we still on for dinner on Saturday?", "00:03"),
            T("caller", "Yes! I booked a table at that new place near the lake for 8pm.", "00:10"),
            T("user", "Perfect. Should I pick you up?", "00:15"),
            T("caller", "Sure, around 7:30 works. I will transfer you my share for the last time too.", "00:23"),
        ],
    },
    {
        "id": "legit_bank_branch_01",
        "category": "customer_support",
        "is_hard_negative": True,
        "title": "Genuine branch callback about a form",
        "turns": [
            T("caller", "Hello, this is Amit from your ICICI home branch. Your cheque book request is ready for pickup.", "00:05"),
            T("user", "Oh good. Do I need to bring anything?", "00:11"),
            T("caller", "Just your ID. We do not need any OTP or online details — please collect it at the branch counter.", "00:23"),
            T("user", "Great, I will come tomorrow.", "00:28"),
        ],
    },
    {
        "id": "legit_insurance_renewal_01",
        "category": "customer_support",
        "is_hard_negative": False,
        "title": "Insurance renewal reminder",
        "turns": [
            T("caller", "Hello, this is a reminder from LIC that your policy premium is due next week.", "00:05"),
            T("user", "Thanks. How can I pay?", "00:10"),
            T("caller", "Through the official LIC website, the app, or any branch. Your policy number is on your bond document.", "00:22"),
            T("user", "Alright, I will pay online.", "00:27"),
        ],
    },
]


def main() -> int:
    records = []
    for r in SCAM:
        records.append(
            {
                "id": r["id"],
                "label": "scam",
                "scam_type": r["scam_type"],
                "category": r["scam_type"],
                "is_hard_negative": False,
                "title": r["title"],
                "turns": r["turns"],
            }
        )
    for r in LEGIT:
        records.append(
            {
                "id": r["id"],
                "label": "legitimate",
                "scam_type": "none",
                "category": r["category"],
                "is_hard_negative": r["is_hard_negative"],
                "title": r["title"],
                "turns": r["turns"],
            }
        )

    dataset = {
        "meta": {
            "description": (
                "Hand-curated labeled conversation transcripts for AntiScam AI "
                "benchmarking. Human-authored for trustworthy labels and full "
                "reproducibility with no API key. Illustrative, not real call data."
            ),
            "generated_by_model": "hand-authored",
            "counts": {
                "total": len(records),
                "scam": len(SCAM),
                "legitimate": len(LEGIT),
                "hard_negatives": sum(1 for r in LEGIT if r["is_hard_negative"]),
            },
            "scam_types": sorted({r["scam_type"] for r in SCAM}),
        },
        "records": records,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(dataset, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(records)} curated records to {OUTPUT_PATH}")
    print(f"  scam: {len(SCAM)}  legitimate: {len(LEGIT)} "
          f"(hard negatives: {dataset['meta']['counts']['hard_negatives']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
