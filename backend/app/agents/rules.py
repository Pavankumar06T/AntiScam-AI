"""Deterministic tripwire layer: fast, explainable, LLM-independent.

Why this exists alongside the LLM classifier:

1. *Latency floor.* Regex matching costs microseconds. The dashboard can move
   the risk score the instant a turn arrives, before the LLM round-trip lands.
2. *Graceful degradation.* If Groq is slow, rate-limited, or down mid-demo, the
   system still produces a defensible score instead of failing open.
3. *Explainability.* "It matched these named coercion patterns" is auditable in
   a way "the model said 82" is not. For a law-enforcement tool that matters.
4. *Guarding against LLM drift.* A prompt change can't silently erase a hard
   signal like "share your OTP".

The rule score is deliberately a *minority* vote (RULE_WEIGHT, default 0.25).
The LLM handles context and sarcasm; rules handle the non-negotiables.

Coverage note: patterns include Hindi/Hinglish transliterations common in Indian
scam calls, since real transcripts code-switch constantly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.models.schemas import (
    ExtractedEntities,
    RedFlagCategory,
    RuleSignal,
    Severity,
)


@dataclass(frozen=True)
class Pattern:
    label: str
    category: RedFlagCategory
    weight: int  # contribution toward the 0-100 rule score
    severity: Severity
    regex: re.Pattern[str]
    explanation: str


def _p(label, category, weight, severity, pattern, explanation) -> Pattern:
    return Pattern(
        label=label,
        category=category,
        weight=weight,
        severity=severity,
        regex=re.compile(pattern, re.IGNORECASE),
        explanation=explanation,
    )


# --- Coercion patterns -------------------------------------------------------
# Weights are additive but the total is squashed (see score_text), so no single
# pattern can max out the score on its own.

PATTERNS: list[Pattern] = [
    # Authority impersonation
    _p(
        "law_enforcement_claim",
        RedFlagCategory.AUTHORITY_IMPERSONATION,
        22,
        Severity.HIGH,
        r"\b(?:i am|this is|calling from|speaking from|officer|inspector|sub[- ]?inspector|"
        r"deputy commissioner)\b[^.\n]{0,40}\b(?:cbi|c\.b\.i|enforcement directorate|\bed\b|"
        r"narcotics|ncb|customs|income tax|cyber cell|cyber crime|crime branch|police|"
        r"trai|telecom regulatory|rbi|reserve bank|delhi police|mumbai police|interpol)\b",
        "Caller claims to be a law-enforcement or regulatory officer. Indian agencies "
        "do not conduct investigations or demand money over phone or video calls.",
    ),
    _p(
        "agency_selfid",
        RedFlagCategory.AUTHORITY_IMPERSONATION,
        14,
        Severity.MEDIUM,
        r"\b(?:cbi|enforcement directorate|narcotics control bureau|ncb|customs department|"
        r"cyber crime (?:cell|branch)|crime branch)\b",
        "An investigative agency is named as the caller's employer.",
    ),
    # Digital arrest — the signature move
    _p(
        "digital_arrest_phrase",
        RedFlagCategory.THREAT_OF_ARREST,
        30,
        Severity.CRITICAL,
        r"\b(?:digital(?:ly)? arrest(?:ed)?|virtual(?:ly)? arrest(?:ed)?|"
        r"house arrest (?:order|warrant)|online custody)\b",
        "'Digital arrest' is not a legal concept anywhere in Indian law. Its mention is "
        "close to conclusive evidence of this specific scam.",
    ),
    _p(
        "arrest_threat",
        RedFlagCategory.THREAT_OF_ARREST,
        20,
        Severity.HIGH,
        r"\b(?:arrest(?:ed|ing)?|non[- ]?bailable|warrant (?:has been )?issued|"
        r"taken into custody|jail|imprison(?:ment|ed)?|lookout notice)\b",
        "Threat of arrest or imprisonment used as leverage.",
    ),
    _p(
        "fake_case",
        RedFlagCategory.FAKE_CASE_REFERENCE,
        16,
        Severity.HIGH,
        r"\b(?:fir(?:\s*(?:no|number|#))?|case (?:no|number|id|registered)|"
        r"money laundering|drug (?:parcel|consignment|trafficking)|"
        r"illegal (?:parcel|consignment|transaction)|aadhaar (?:has been )?(?:misused|linked)|"
        r"your (?:aadhaar|pan) (?:number )?(?:is|has been) (?:used|linked|involved))\b",
        "A fabricated criminal case is cited to justify the pressure.",
    ),
    # Isolation — the tactic that makes victims unreachable
    _p(
        "isolation",
        RedFlagCategory.ISOLATION_TACTIC,
        26,
        Severity.CRITICAL,
        r"\b(?:do(?:\s+not|n'?t)\s+(?:tell|inform|disclose|talk to|contact|hang up|"
        r"disconnect|cut|end the call|leave)|stay on (?:the )?(?:call|line)|"
        r"remain on (?:the )?(?:call|video)|keep (?:the )?(?:camera|video) on|"
        r"cannot (?:hang up|disconnect|leave)|kisi ko mat bata|kisi se baat mat)\b",
        "Isolation tactic: the caller is trying to cut you off from anyone who "
        "could tell you this is a scam.",
    ),
    _p(
        "secrecy",
        RedFlagCategory.SECRECY_DEMAND,
        18,
        Severity.HIGH,
        r"\b(?:strictly confidential|official secrets? act|classified (?:case|investigation)|"
        r"cannot (?:be )?(?:discuss|tell) (?:this )?(?:with )?(?:anyone|family)|"
        r"under (?:legal )?(?:gag|non[- ]disclosure))\b",
        "Demand for secrecy, often dressed up with fake legal authority.",
    ),
    # Extraction
    _p(
        "safe_account_transfer",
        RedFlagCategory.FUND_TRANSFER_DEMAND,
        30,
        Severity.CRITICAL,
        r"\b(?:safe|secure|verification|verified|escrow|government|rbi|nodal|holding)\s+"
        r"account\b|\btransfer (?:the )?(?:funds|money|amount)\b[^.\n]{0,30}\b(?:verif|safe|secure|clear)",
        "The 'safe account' / 'verification account' demand. No agency will ever ask you "
        "to move money to prove it is clean.",
    ),
    _p(
        "credential_request",
        RedFlagCategory.CREDENTIAL_REQUEST,
        30,
        Severity.CRITICAL,
        r"\b(?:otp|one[- ]time password|upi pin|mpin|m[- ]?pin|atm pin|cvv|"
        r"card number|net ?banking (?:password|credential)|password|"
        r"otp share|share (?:the )?otp)\b",
        "Request for OTP/PIN/CVV. No legitimate bank, agency, or company ever asks for these.",
    ),
    _p(
        "remote_access",
        RedFlagCategory.REMOTE_ACCESS_REQUEST,
        24,
        Severity.CRITICAL,
        r"\b(?:anydesk|teamviewer|quick ?support|screen ?share|remote (?:access|desktop)|"
        r"install (?:this )?(?:app|apk)|download (?:the )?(?:apk|application))\b",
        "Request to install remote-access software — hands the scammer your device.",
    ),
    _p(
        "urgency",
        RedFlagCategory.URGENCY_PRESSURE,
        14,
        Severity.MEDIUM,
        r"\b(?:immediately|right now|within (?:the next )?(?:\d+\s*)?(?:minute|hour)s?|"
        r"before (?:the )?(?:deadline|day end)|urgent(?:ly)?|last (?:chance|warning)|"
        r"no time|act (?:now|fast)|turant|abhi ke abhi)\b",
        "Artificial time pressure to prevent you from thinking or verifying.",
    ),
    _p(
        "verification_pretext",
        RedFlagCategory.VERIFICATION_PRETEXT,
        16,
        Severity.HIGH,
        r"\b(?:verify (?:your )?(?:account|funds|identity|balance)|"
        r"verification (?:process|purpose|fee)|kyc (?:update|expired|pending|verification)|"
        r"account (?:will be |shall be )?(?:blocked|suspended|frozen|deactivated))\b",
        "'Verification' pretext — a manufactured reason to extract money or credentials.",
    ),
    _p(
        "advance_fee",
        RedFlagCategory.ADVANCE_FEE,
        20,
        Severity.HIGH,
        r"\b(?:processing fee|registration fee|security deposit|clearance (?:fee|charge)|"
        r"gst (?:charge|amount|fee)|customs duty|refundable (?:fee|deposit)|"
        r"(?:training[- ]?kit|registration|enrol?lment|activation|joining|membership) "
        r"(?:and [\w-]+ )?fee|one[- ]time fee|"
        r"pay (?:a |the )?(?:small )?(?:fee|amount) (?:to|for) (?:release|claim|process))\b",
        "Advance-fee pattern: pay a small amount now to unlock a larger promised sum.",
    ),
    _p(
        "unrealistic_reward",
        RedFlagCategory.UNREALISTIC_REWARD,
        16,
        Severity.MEDIUM,
        r"\b(?:you have won|lottery|lucky (?:draw|winner)|prize money|"
        r"guaranteed (?:return|profit|income)s?|"
        r"double (?:your|their|his|her|the) (?:money|investment|amount)|"
        r"work from home[^.\n]{0,30}\b(?:daily|per day|earn))\b",
        "Reward that is too good to be true — the hook for prize/investment/job scams.",
    ),
    _p(
        "payment_rail",
        RedFlagCategory.FUND_TRANSFER_DEMAND,
        12,
        Severity.MEDIUM,
        r"\b(?:upi|google ?pay|gpay|phone ?pe|phonepe|paytm|neft|rtgs|imps|"
        r"scan (?:the )?qr|bitcoin|usdt|crypto|gift card)\b",
        "A fast, hard-to-reverse payment rail is being steered toward.",
    ),
]


# --- Entity extraction -------------------------------------------------------
# Deterministic on purpose: these identifiers become graph nodes in Phase 2, and
# a hallucinated phone number would poison cross-victim linking.

_RE_PHONE = re.compile(r"(?<![\d)])(?:\+?91[\-\s]?)?[6-9]\d{9}(?!\d)")
_RE_UPI = re.compile(r"\b[\w.\-]{2,64}@(?:ok(?:hdfcbank|icici|axis|sbi)|paytm|ybl|upi|apl|ibl|axl|"
                     r"hdfcbank|icici|sbi|axisbank|pnb|kotak|jio|fam|airtel)\b", re.IGNORECASE)
_RE_ACCOUNT = re.compile(r"\b(?:a/?c(?:count)?(?:\s*(?:no|number|#))?\.?\s*[:\-]?\s*)(\d{9,18})\b", re.IGNORECASE)
_RE_BARE_ACCOUNT = re.compile(r"(?<!\d)\d{11,18}(?!\d)")
_RE_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_RE_CASE = re.compile(
    r"\b(?:fir|case|complaint|reference|ref|dd|diary)\s*(?:no\.?|number|#|id)?\s*[:\-]?\s*"
    r"([A-Z0-9][A-Z0-9/\-]{3,24})\b",
    re.IGNORECASE,
)
_RE_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')]+", re.IGNORECASE)
_RE_AMOUNT = re.compile(
    r"(?:(?:rs\.?|inr|₹)\s*[\d,]+(?:\.\d+)?\s*(?:lakh|lakhs|crore|crores|k|thousand)?)"
    r"|(?:\b[\d,]+(?:\.\d+)?\s*(?:lakh|lakhs|crore|crores)\b)",
    re.IGNORECASE,
)
# The title is matched case-insensitively, but the captured name must stay
# properly capitalised — otherwise "officer speaking" yields a person named "Speaking".
_RE_NAME = re.compile(
    r"\b(?i:inspector|sub[- ]?inspector|officer|deputy commissioner|dcp|acp|ips|"
    r"superintendent|agent|constable|advocate|dr|mr|shri)\.?\s+"
    r"([A-Z][a-z]{2,15}(?:\s+[A-Z][a-z]{2,15})?)\b"
)
_RE_DEPT = re.compile(
    r"\b(CBI|Central Bureau of Investigation|Enforcement Directorate|ED|"
    r"Narcotics Control Bureau|NCB|Customs(?: Department)?|Income Tax Department|"
    r"Cyber Crime (?:Cell|Branch)|Crime Branch|TRAI|Reserve Bank of India|RBI|"
    r"Delhi Police|Mumbai Police|Interpol)\b",
    re.IGNORECASE,
)

# Words that look like officer names but aren't.
_NAME_STOPWORDS = {"sharma", "verma"} & set()  # intentionally empty; kept for future tuning


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for i in items:
        k = i.strip().lower()
        if k and k not in seen:
            seen.add(k)
            out.append(i.strip())
    return out


def _normalize_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    return digits


def extract_entities(text: str) -> ExtractedEntities:
    """Pull scammer-side identifiers out of a transcript.

    Runs on every classification (not just high-risk ones) so that the Phase 2
    graph agent gets a consistent feed and the Phase 1 API is already useful.
    """
    phones = _dedupe([_normalize_phone(m) for m in _RE_PHONE.findall(text)])

    accounts = _dedupe(_RE_ACCOUNT.findall(text))
    # Long bare digit runs are account numbers, unless we already claimed them as phones.
    phone_digits = set(phones)
    for m in _RE_BARE_ACCOUNT.findall(text):
        if m not in phone_digits and m not in accounts:
            accounts.append(m)
    accounts = _dedupe(accounts + _RE_IFSC.findall(text))

    case_numbers = _dedupe(
        [m for m in _RE_CASE.findall(text) if any(c.isdigit() for c in m)]
    )

    return ExtractedEntities(
        phone_numbers=phones,
        upi_ids=_dedupe(_RE_UPI.findall(text)),
        bank_accounts=accounts,
        claimed_names=_dedupe(_RE_NAME.findall(text)),
        claimed_departments=_dedupe([d.upper() for d in _RE_DEPT.findall(text)]),
        case_numbers=case_numbers,
        urls=_dedupe(_RE_URL.findall(text)),
        amounts_mentioned=_dedupe(_RE_AMOUNT.findall(text)),
    )


# --- Scoring -----------------------------------------------------------------

def find_signals(text: str) -> list[RuleSignal]:
    """Return every tripwire that fired, with the span that triggered it."""
    signals: list[RuleSignal] = []
    for pattern in PATTERNS:
        match = pattern.regex.search(text)
        if not match:
            continue
        start = max(0, match.start() - 40)
        end = min(len(text), match.end() + 40)
        quote = text[start:end].strip().replace("\n", " ")
        if start > 0:
            quote = "…" + quote
        if end < len(text):
            quote = quote + "…"
        signals.append(
            RuleSignal(
                category=pattern.category,
                pattern_label=pattern.label,
                quote=quote,
                weight=pattern.weight,
            )
        )
    return signals


def score_text(text: str) -> tuple[int, list[RuleSignal]]:
    """Score 0-100 from tripwires alone.

    Weights are summed then squashed with a saturating curve, so that stacking
    many weak signals approaches but never reaches certainty, while two or three
    critical signals get most of the way there. This keeps the rule layer from
    screaming 100 at a single unlucky keyword.
    """
    signals = find_signals(text)
    if not signals:
        return 0, []

    total = sum(s.weight for s in signals)
    # Saturating curve: 60 points of weight -> ~63, 120 -> ~86, 200 -> ~96.
    score = 100 * (1 - 2.718281828 ** (-total / 60.0))
    return int(round(min(99.0, score))), signals


def signals_to_categories(signals: list[RuleSignal]) -> set[RedFlagCategory]:
    return {s.category for s in signals}


PATTERN_BY_LABEL = {p.label: p for p in PATTERNS}
