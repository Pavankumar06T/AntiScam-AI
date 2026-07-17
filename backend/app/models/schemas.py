"""Pydantic schemas for the AntiScam AI API.

These types are the contract between the Detection Agent, the FastAPI layer,
and (from Phase 2 onward) the LangGraph orchestrator and the React dashboard.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class ScamType(str, Enum):
    """Taxonomy of conversational fraud we classify into."""

    DIGITAL_ARREST = "digital_arrest"
    KYC_FRAUD = "kyc_fraud"
    LOTTERY_PRIZE = "lottery_prize"
    LOAN_FRAUD = "loan_fraud"
    JOB_SCAM = "job_scam"
    INVESTMENT_FRAUD = "investment_fraud"
    TECH_SUPPORT = "tech_support"
    OTHER_SCAM = "other_scam"
    NONE = "none"


class RedFlagCategory(str, Enum):
    """The coercion techniques we name explicitly, so warnings can cite them."""

    AUTHORITY_IMPERSONATION = "authority_impersonation"
    URGENCY_PRESSURE = "urgency_pressure"
    THREAT_OF_ARREST = "threat_of_arrest"
    ISOLATION_TACTIC = "isolation_tactic"
    SECRECY_DEMAND = "secrecy_demand"
    FUND_TRANSFER_DEMAND = "fund_transfer_demand"
    CREDENTIAL_REQUEST = "credential_request"
    FAKE_CASE_REFERENCE = "fake_case_reference"
    VERIFICATION_PRETEXT = "verification_pretext"
    ADVANCE_FEE = "advance_fee"
    UNREALISTIC_REWARD = "unrealistic_reward"
    REMOTE_ACCESS_REQUEST = "remote_access_request"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EscalationStage(str, Enum):
    """Stages of the digital-arrest coercion playbook.

    Scam calls follow a predictable script. Naming where a live call sits on
    that script is what lets us warn *before* the extraction step rather than
    after, and it gives the Phase 4 lead-time metric something to measure.
    """

    NO_CONTACT_RISK = "no_contact_risk"
    PRETEXT_ESTABLISHED = "pretext_established"
    AUTHORITY_ASSERTED = "authority_asserted"
    FEAR_INDUCED = "fear_induced"
    VICTIM_ISOLATED = "victim_isolated"
    EXTRACTION_ATTEMPTED = "extraction_attempted"


class RecommendedAction(str, Enum):
    MONITOR = "monitor"
    CAUTION = "caution"
    WARN_USER = "warn_user"
    URGENT_INTERVENTION = "urgent_intervention"


class Speaker(str, Enum):
    CALLER = "caller"
    USER = "user"
    UNKNOWN = "unknown"


class Turn(BaseModel):
    """One utterance in a conversation.

    Turn-level structure (rather than a single opaque blob) is what makes the
    evidence packet in Phase 2 able to quote a red flag with a timestamp, and
    what makes the Phase 4 lead-time metric computable.
    """

    speaker: Speaker = Speaker.UNKNOWN
    text: str
    timestamp: str | None = Field(
        default=None, description="Wall clock or offset, e.g. '00:42' or ISO-8601."
    )
    turn_index: int | None = None


class RedFlag(BaseModel):
    category: RedFlagCategory
    severity: Severity
    quote: str = Field(description="Verbatim span from the transcript.")
    explanation: str = Field(description="Plain-language reason this is a red flag.")
    turn_index: int | None = None
    timestamp: str | None = None


class ExtractedEntities(BaseModel):
    """Scammer-side identifiers. Feeds the Phase 2 fraud network graph."""

    phone_numbers: list[str] = Field(default_factory=list)
    upi_ids: list[str] = Field(default_factory=list)
    bank_accounts: list[str] = Field(default_factory=list)
    claimed_names: list[str] = Field(default_factory=list)
    claimed_departments: list[str] = Field(default_factory=list)
    case_numbers: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    amounts_mentioned: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(getattr(self, f) for f in type(self).model_fields)


class RuleSignal(BaseModel):
    """A hit from the deterministic tripwire layer."""

    category: RedFlagCategory
    pattern_label: str
    quote: str
    weight: int


class DetectorBreakdown(BaseModel):
    """Per-layer scores, exposed so a reviewer can see we don't blindly trust the LLM."""

    rule_score: int = Field(ge=0, le=100)
    llm_score: int | None = Field(default=None, ge=0, le=100)
    fused_score: int = Field(ge=0, le=100)
    rule_weight: float
    llm_available: bool
    signals_fired: int


class ClassifyRequest(BaseModel):
    conversation_id: str = Field(min_length=1, max_length=128)
    transcript: str = Field(
        default="",
        description="Raw transcript text. Optional if `turns` is supplied.",
    )
    turns: list[Turn] | None = Field(
        default=None,
        description="Structured turns. Preferred: enables timestamped evidence.",
    )
    is_full_conversation: bool = Field(
        default=True,
        description="False when this is a live partial chunk of an ongoing call.",
    )
    language_hint: Literal["en", "hi", "ta", "auto"] = "auto"

    @field_validator("transcript")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @model_validator(mode="after")
    def _require_content(self) -> ClassifyRequest:
        has_turns = bool(self.turns) and any(t.text.strip() for t in self.turns)
        if not self.transcript and not has_turns:
            raise ValueError(
                "Provide non-empty `transcript` text or at least one non-empty `turns` entry."
            )
        return self

    def normalized_turns(self) -> list[Turn]:
        """Return turns, deriving them from raw text when only `transcript` was sent.

        Accepts 'Speaker: text' lines, which is how the synthetic dataset and
        most ASR exports look.
        """
        if self.turns:
            return [
                t.model_copy(update={"turn_index": t.turn_index if t.turn_index is not None else i})
                for i, t in enumerate(self.turns)
                if t.text.strip()
            ]

        turns: list[Turn] = []
        for i, line in enumerate(self.transcript.splitlines()):
            line = line.strip()
            if not line:
                continue
            speaker = Speaker.UNKNOWN
            text = line
            if ":" in line:
                head, _, tail = line.partition(":")
                head_l = head.strip().lower()
                if len(head_l) <= 24 and tail.strip():
                    if any(k in head_l for k in ("caller", "scammer", "officer", "agent", "unknown")):
                        speaker, text = Speaker.CALLER, tail.strip()
                    elif any(k in head_l for k in ("user", "victim", "customer", "citizen", "me")):
                        speaker, text = Speaker.USER, tail.strip()
            turns.append(Turn(speaker=speaker, text=text, turn_index=i))

        if not turns and self.transcript:
            turns.append(Turn(speaker=Speaker.UNKNOWN, text=self.transcript, turn_index=0))
        return turns

    def as_text(self) -> str:
        """Flatten to the text form shown to the LLM."""
        if self.turns:
            return "\n".join(
                f"[{t.timestamp}] {t.speaker.value}: {t.text}" if t.timestamp
                else f"{t.speaker.value}: {t.text}"
                for t in self.turns
                if t.text.strip()
            )
        return self.transcript


class ClassifyResponse(BaseModel):
    conversation_id: str
    scam_probability: int = Field(ge=0, le=100, description="0 = benign, 100 = certain fraud.")
    scam_type: ScamType
    red_flags: list[RedFlag] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    recommended_action: RecommendedAction
    escalation_stage: EscalationStage = EscalationStage.NO_CONTACT_RISK
    extracted_entities: ExtractedEntities = Field(default_factory=ExtractedEntities)
    breakdown: DetectorBreakdown
    latency_ms: int
    model: str
    degraded: bool = Field(
        default=False,
        description="True when the LLM was unavailable and the score is rule-only.",
    )
    degraded_reason: str | None = Field(
        default=None, description="Why the LLM layer was skipped, when it was."
    )


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    groq_configured: bool
    model: str
    version: str
