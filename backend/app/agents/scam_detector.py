"""Scam Pattern Detection Agent.

Two layers, fused:

    transcript ──┬──> deterministic tripwires (rules.py)  ── rule_score  ─┐
                 │                                                        ├─> fused score
                 └──> Groq LLM (JSON mode, few-shot)       ── llm_score  ─┘

The LLM is the primary judge; the rule layer is a minority vote that anchors the
score on non-negotiable signals and keeps the system alive if Groq is unavailable.
See rules.py for the full rationale.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.agents import rules
from app.agents.prompts import (
    DETECTION_SYSTEM_PROMPT,
    FEW_SHOT_EXAMPLES,
    build_user_prompt,
)
from app.config import get_settings, resolve_model_name
from app.models.schemas import (
    ClassifyRequest,
    ClassifyResponse,
    DetectorBreakdown,
    EscalationStage,
    ExtractedEntities,
    RecommendedAction,
    RedFlag,
    RedFlagCategory,
    ScamType,
    Severity,
)

logger = logging.getLogger(__name__)

MAX_TRANSCRIPT_CHARS = 24_000

_STAGE_ORDER = [
    EscalationStage.NO_CONTACT_RISK,
    EscalationStage.PRETEXT_ESTABLISHED,
    EscalationStage.AUTHORITY_ASSERTED,
    EscalationStage.FEAR_INDUCED,
    EscalationStage.VICTIM_ISOLATED,
    EscalationStage.EXTRACTION_ATTEMPTED,
]

# Rule categories that imply a minimum escalation stage, used to backstop the
# LLM's stage call when it is unavailable or obviously behind the evidence.
_CATEGORY_STAGE_FLOOR = {
    RedFlagCategory.AUTHORITY_IMPERSONATION: EscalationStage.AUTHORITY_ASSERTED,
    RedFlagCategory.FAKE_CASE_REFERENCE: EscalationStage.FEAR_INDUCED,
    RedFlagCategory.THREAT_OF_ARREST: EscalationStage.FEAR_INDUCED,
    RedFlagCategory.ISOLATION_TACTIC: EscalationStage.VICTIM_ISOLATED,
    RedFlagCategory.SECRECY_DEMAND: EscalationStage.VICTIM_ISOLATED,
    RedFlagCategory.FUND_TRANSFER_DEMAND: EscalationStage.EXTRACTION_ATTEMPTED,
    RedFlagCategory.CREDENTIAL_REQUEST: EscalationStage.EXTRACTION_ATTEMPTED,
    RedFlagCategory.REMOTE_ACCESS_REQUEST: EscalationStage.EXTRACTION_ATTEMPTED,
    RedFlagCategory.ADVANCE_FEE: EscalationStage.EXTRACTION_ATTEMPTED,
}


class DetectionError(RuntimeError):
    """Raised when detection fails in a way the caller should see as a 5xx."""


def _get_client():
    from groq import Groq

    settings = get_settings()
    if not settings.groq_configured:
        raise DetectionError(
            "GROQ_API_KEY is not set. Create backend/.env with "
            "GROQ_API_KEY=<your key> from https://console.groq.com/keys"
        )
    # max_retries=0 is deliberate. The SDK's default retry sleeps ~25s inside the
    # call when it hits a 429. In a live interception system a silent 25s stall is
    # strictly worse than a fast, honest rule-only score: the user is being scammed
    # *now*. We own the retry policy here instead (see classify()).
    return Groq(
        api_key=settings.groq_api_key,
        timeout=settings.request_timeout,
        max_retries=0,
    )


def _rate_limit_reason(exc: Exception | None) -> str:
    """Report which Groq quota we actually hit.

    Worth the effort: the per-day cap and the per-minute cap produce the same 429,
    and the TPM headers read *full* while TPD is exhausted. Saying "tokens/min" when
    it was really the daily cap sends whoever reads this log down the wrong path.
    """
    body = str(exc or "")
    if "tokens per day" in body or "TPD" in body:
        return (
            "Groq daily token quota exhausted (free tier: 100k tokens/day, "
            "~25 detection calls). Upgrade at console.groq.com/settings/billing"
        )
    if "tokens per minute" in body or "TPM" in body:
        return "Groq per-minute token limit reached (free tier: 12k tokens/min)"
    if "requests per" in body or "RPM" in body or "RPD" in body:
        return "Groq request-rate limit reached"
    return "Groq rate limit reached"


def _retry_after_seconds(exc: Exception, default: float) -> float:
    """Honour Groq's retry-after / rate-limit-reset hint when it gives us one."""
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", None) or {}
    for key in ("retry-after", "x-ratelimit-reset-tokens", "x-ratelimit-reset-requests"):
        raw = headers.get(key)
        if not raw:
            continue
        try:
            text = str(raw).strip()
            if text.endswith("ms"):
                return min(60.0, float(text[:-2]) / 1000.0)
            if text.endswith("s") and "m" in text:  # e.g. "1m31.2s"
                minutes, _, secs = text.partition("m")
                return min(60.0, float(minutes) * 60 + float(secs.rstrip("s") or 0))
            if text.endswith("s"):
                return min(60.0, float(text[:-1]))
            return min(60.0, float(text))
        except (TypeError, ValueError):
            continue
    return default


def _action_for(score: int) -> RecommendedAction:
    settings = get_settings()
    if score >= settings.urgent_threshold:
        return RecommendedAction.URGENT_INTERVENTION
    if score >= settings.warn_threshold:
        return RecommendedAction.WARN_USER
    if score >= 30:
        return RecommendedAction.CAUTION
    return RecommendedAction.MONITOR


def _coerce_enum(value: Any, enum_cls, default):
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value).strip().lower())
    except (ValueError, AttributeError):
        return default


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        return max(lo, min(hi, int(round(float(value)))))
    except (TypeError, ValueError):
        return default


def _clamp_float(value: Any, lo: float, hi: float, default: float) -> float:
    try:
        return max(lo, min(hi, float(value)))
    except (TypeError, ValueError):
        return default


def _locate_quote(quote: str, turns) -> tuple[int | None, str | None]:
    """Map a quoted span back to the turn it came from.

    The Phase 2 evidence packet needs timestamped excerpts, so we resolve each
    LLM-reported quote to its source turn here rather than asking the model to
    track indices (which it does unreliably).
    """
    needle = quote.strip().lower()
    if not needle:
        return None, None
    for turn in turns:
        if needle in turn.text.lower():
            return turn.turn_index, turn.timestamp
    # Fall back to a looser overlap check for lightly-paraphrased quotes.
    words = [w for w in needle.split() if len(w) > 3]
    if len(words) >= 3:
        for turn in turns:
            hay = turn.text.lower()
            hits = sum(1 for w in words if w in hay)
            if hits >= max(3, len(words) * 0.6):
                return turn.turn_index, turn.timestamp
    return None, None


def _parse_red_flags(raw: Any, turns) -> list[RedFlag]:
    if not isinstance(raw, list):
        return []
    flags: list[RedFlag] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        quote = str(item.get("quote", "")).strip()
        if not quote:
            continue
        category = _coerce_enum(item.get("category"), RedFlagCategory, None)
        if category is None:
            continue
        turn_index, timestamp = _locate_quote(quote, turns)
        flags.append(
            RedFlag(
                category=category,
                severity=_coerce_enum(item.get("severity"), Severity, Severity.MEDIUM),
                quote=quote[:400],
                explanation=str(item.get("explanation", "")).strip()[:600]
                or "Recognised coercion pattern.",
                turn_index=turn_index,
                timestamp=timestamp,
            )
        )
    return flags


def _stage_floor_from_signals(signals) -> EscalationStage:
    floor = EscalationStage.NO_CONTACT_RISK
    for signal in signals:
        candidate = _CATEGORY_STAGE_FLOOR.get(signal.category)
        if candidate and _STAGE_ORDER.index(candidate) > _STAGE_ORDER.index(floor):
            floor = candidate
    return floor


def _fuse(rule_score: int, llm_score: int) -> int:
    """Blend rule and LLM scores.

    Weighted average, with one asymmetry: when the rule layer fires a critical
    signal that the LLM scored low, we do not let the average bury it entirely.
    Missing a real scam costs a citizen their savings; a slightly elevated score
    on a benign call costs a dismissed banner.
    """
    settings = get_settings()
    w = settings.rule_weight
    fused = (1 - w) * llm_score + w * rule_score
    return _clamp_int(fused, 0, 100, llm_score)


def _rule_red_flags(turns) -> list[RedFlag]:
    """Build red flags from tripwires, quoting each turn's own text.

    Two problems this solves, both visible in the generated complaint before it
    existed:

    1. The scorer runs over the flattened transcript ("[00:12] caller: ..."), so
       quoting its match window embedded timestamps and speaker labels inside the
       evidence quote. Re-matching per turn yields a clean verbatim quote and an
       exact turn attribution instead of a fuzzy text search.
    2. Several patterns share a category (law_enforcement_claim and agency_selfid
       are both authority_impersonation). Emitting one flag per *pattern* produced
       near-duplicate evidence items. We keep the strongest pattern per category
       per turn.
    """
    flags: list[RedFlag] = []

    for turn in turns:
        best_by_category: dict[RedFlagCategory, tuple[int, RedFlag]] = {}

        for signal in rules.find_signals(turn.text):
            pattern = rules.PATTERN_BY_LABEL[signal.pattern_label]
            candidate = RedFlag(
                category=signal.category,
                severity=pattern.severity,
                quote=turn.text.strip()[:400],
                explanation=pattern.explanation,
                turn_index=turn.turn_index,
                timestamp=turn.timestamp,
            )
            existing = best_by_category.get(signal.category)
            if existing is None or signal.weight > existing[0]:
                best_by_category[signal.category] = (signal.weight, candidate)

        flags.extend(flag for _, flag in best_by_category.values())

    return flags


def _rule_only_response(
    request: ClassifyRequest,
    rule_score: int,
    signals,
    entities: ExtractedEntities,
    turns,
    latency_ms: int,
    model: str,
    reason: str,
) -> ClassifyResponse:
    """Degraded-mode result built purely from tripwires."""
    red_flags = _rule_red_flags(turns)

    scam_type = ScamType.NONE
    if rule_score >= 30:
        cats = rules.signals_to_categories(signals)
        if {RedFlagCategory.THREAT_OF_ARREST, RedFlagCategory.AUTHORITY_IMPERSONATION} & cats:
            scam_type = ScamType.DIGITAL_ARREST
        elif RedFlagCategory.UNREALISTIC_REWARD in cats:
            scam_type = ScamType.LOTTERY_PRIZE
        elif RedFlagCategory.REMOTE_ACCESS_REQUEST in cats:
            scam_type = ScamType.TECH_SUPPORT
        elif RedFlagCategory.VERIFICATION_PRETEXT in cats:
            scam_type = ScamType.KYC_FRAUD
        else:
            scam_type = ScamType.OTHER_SCAM

    return ClassifyResponse(
        conversation_id=request.conversation_id,
        scam_probability=rule_score,
        scam_type=scam_type,
        red_flags=red_flags,
        confidence=0.4 if signals else 0.25,
        reasoning=(
            f"DEGRADED MODE — scored by the deterministic pattern layer only ({reason}). "
            f"{len(signals)} known coercion pattern(s) matched. "
            "Treat this score as a floor, not a considered judgement."
        ),
        degraded_reason=reason,
        recommended_action=_action_for(rule_score),
        escalation_stage=_stage_floor_from_signals(signals),
        extracted_entities=entities,
        breakdown=DetectorBreakdown(
            rule_score=rule_score,
            llm_score=None,
            fused_score=rule_score,
            rule_weight=1.0,
            llm_available=False,
            signals_fired=len(signals),
        ),
        latency_ms=latency_ms,
        model=model,
        degraded=True,
    )


def classify(
    request: ClassifyRequest,
    *,
    allow_backoff: bool = False,
) -> ClassifyResponse:
    """Classify a transcript. Never raises for LLM failures — degrades to rules.

    allow_backoff: when True, wait out a 429 rate limit and retry rather than
    degrading. Live traffic must stay fast, so the API leaves this False. Batch
    jobs (dataset generation, the Phase 4 metrics run) set it True because a
    complete result matters more than latency there.
    """
    started = time.perf_counter()

    turns = request.normalized_turns()
    text = request.as_text()[:MAX_TRANSCRIPT_CHARS]

    # Layer 1: deterministic. Microseconds, always runs.
    rule_score, signals = rules.score_text(text)
    entities = rules.extract_entities(text)

    settings = get_settings()
    model = resolve_model_name()

    if not settings.groq_configured:
        elapsed = int((time.perf_counter() - started) * 1000)
        return _rule_only_response(
            request, rule_score, signals, entities, turns, elapsed, model,
            "GROQ_API_KEY not configured",
        )

    messages = [
        {"role": "system", "content": DETECTION_SYSTEM_PROMPT},
        *FEW_SHOT_EXAMPLES,
        {"role": "user", "content": build_user_prompt(text, request.is_full_conversation)},
    ]

    payload: dict[str, Any] | None = None
    last_error: Exception | None = None
    rate_limited = False

    max_attempts = 6 if allow_backoff else 2

    # Layer 2: LLM. Retry covers malformed JSON and transient API errors.
    for attempt in range(1, max_attempts + 1):
        try:
            client = _get_client()
            completion = client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=settings.temperature,
                max_completion_tokens=1600,
                response_format={"type": "json_object"},
                seed=7,  # reproducible scores across metric runs
            )
            content = completion.choices[0].message.content or ""
            payload = json.loads(content)
            if not isinstance(payload, dict):
                raise ValueError(f"Expected a JSON object, got {type(payload).__name__}")
            break
        except Exception as exc:
            last_error = exc
            payload = None
            is_rate_limit = type(exc).__name__ == "RateLimitError"
            rate_limited = rate_limited or is_rate_limit

            if is_rate_limit and not allow_backoff:
                # Fail fast: the rule layer answers now rather than stalling the call.
                logger.warning(
                    "Rate limited on conversation %s — degrading to rule-only score "
                    "rather than stalling.",
                    request.conversation_id,
                )
                break

            logger.warning(
                "Detection attempt %d/%d failed for conversation %s: %s: %s",
                attempt, max_attempts, request.conversation_id, type(exc).__name__, exc,
            )
            if attempt < max_attempts and is_rate_limit:
                wait = _retry_after_seconds(exc, default=8.0 * attempt)
                logger.info("Waiting %.1fs for rate limit to clear…", wait)
                time.sleep(wait)

    elapsed = int((time.perf_counter() - started) * 1000)

    if payload is None:
        reason = (
            _rate_limit_reason(last_error)
            if rate_limited
            else f"LLM unavailable: {type(last_error).__name__}"
        )
        logger.error(
            "LLM detection failed for conversation %s; falling back to rule-only "
            "scoring. Reason: %s",
            request.conversation_id, reason,
        )
        return _rule_only_response(
            request, rule_score, signals, entities, turns, elapsed, model, reason,
        )

    llm_score = _clamp_int(payload.get("scam_probability"), 0, 100, rule_score)
    scam_type = _coerce_enum(payload.get("scam_type"), ScamType, ScamType.NONE)
    red_flags = _parse_red_flags(payload.get("red_flags"), turns)
    confidence = _clamp_float(payload.get("confidence"), 0.0, 1.0, 0.5)
    reasoning = str(payload.get("reasoning", "")).strip() or "No reasoning returned."

    fused = _fuse(rule_score, llm_score)

    # Keep type and score consistent: a high score with scam_type "none" is
    # incoherent output, and vice versa.
    if fused >= settings.warn_threshold and scam_type is ScamType.NONE:
        scam_type = ScamType.OTHER_SCAM
    if fused < 30 and scam_type is not ScamType.NONE and not red_flags:
        scam_type = ScamType.NONE

    stage = _coerce_enum(
        payload.get("escalation_stage"), EscalationStage, EscalationStage.NO_CONTACT_RISK
    )
    floor = _stage_floor_from_signals(signals)
    if _STAGE_ORDER.index(floor) > _STAGE_ORDER.index(stage):
        stage = floor

    return ClassifyResponse(
        conversation_id=request.conversation_id,
        scam_probability=fused,
        scam_type=scam_type,
        red_flags=red_flags,
        confidence=confidence,
        reasoning=reasoning,
        # Action is derived from the fused score, not the model's own suggestion,
        # so thresholds stay consistent across the API, UI, and orchestrator.
        recommended_action=_action_for(fused),
        escalation_stage=stage,
        extracted_entities=entities,
        breakdown=DetectorBreakdown(
            rule_score=rule_score,
            llm_score=llm_score,
            fused_score=fused,
            rule_weight=settings.rule_weight,
            llm_available=True,
            signals_fired=len(signals),
        ),
        latency_ms=elapsed,
        model=model,
        degraded=False,
    )
