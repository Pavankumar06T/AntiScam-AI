"""Detection Agent internals: fusion, degraded mode, and output coherence.

All offline — the LLM is stubbed, so these assert our logic rather than Groq's.
"""

from __future__ import annotations

import pytest

from app.agents import scam_detector
from app.config import get_settings
from app.models.schemas import (
    ClassifyRequest,
    EscalationStage,
    RecommendedAction,
    ScamType,
)
from tests.conftest import OBVIOUS_LEGITIMATE, OBVIOUS_SCAM


class _StubMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _StubChoice:
    def __init__(self, content: str) -> None:
        self.message = _StubMessage(content)


class _StubCompletion:
    def __init__(self, content: str) -> None:
        self.choices = [_StubChoice(content)]


def _stub_client(payload: str, fail_times: int = 0):
    """Build a fake Groq client that returns `payload`, failing the first N calls."""
    state = {"calls": 0}

    class _Completions:
        def create(self, **kwargs):
            state["calls"] += 1
            if state["calls"] <= fail_times:
                raise RuntimeError("simulated Groq outage")
            return _StubCompletion(payload)

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    return _Client(), state


VALID_PAYLOAD = """{
  "scam_probability": 95,
  "scam_type": "digital_arrest",
  "confidence": 0.97,
  "escalation_stage": "extraction_attempted",
  "reasoning": "Full digital arrest playbook.",
  "recommended_action": "urgent_intervention",
  "red_flags": [
    {"category": "threat_of_arrest", "severity": "critical",
     "quote": "You are under digital arrest from this moment",
     "explanation": "Not a real legal procedure."}
  ]
}"""


@pytest.fixture(autouse=True)
def _force_groq_configured(monkeypatch):
    """Pretend a key exists so the LLM path is exercised against the stub."""
    settings = get_settings()
    monkeypatch.setattr(settings, "groq_api_key", "test-key-not-real", raising=False)
    monkeypatch.setattr(scam_detector, "resolve_model_name", lambda: "stub-model")
    yield


def test_valid_llm_response_is_parsed_and_fused(monkeypatch):
    client, _ = _stub_client(VALID_PAYLOAD)
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )

    assert result.degraded is False
    assert result.breakdown.llm_score == 95
    assert result.breakdown.rule_score > 0
    assert result.scam_probability == result.breakdown.fused_score
    assert result.scam_type is ScamType.DIGITAL_ARREST
    assert result.recommended_action is RecommendedAction.URGENT_INTERVENTION
    assert result.escalation_stage is EscalationStage.EXTRACTION_ATTEMPTED
    assert result.latency_ms >= 0
    assert result.model == "stub-model"


def test_red_flag_quote_is_resolved_to_its_turn(monkeypatch):
    client, _ = _stub_client(VALID_PAYLOAD)
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )
    flag = result.red_flags[0]
    assert flag.turn_index is not None, "quote should map back to a turn for evidence packets"


def test_malformed_json_retries_then_succeeds(monkeypatch):
    """First attempt returns garbage; the retry must recover."""
    state = {"calls": 0}

    class _Completions:
        def create(self, **kwargs):
            state["calls"] += 1
            if state["calls"] == 1:
                return _StubCompletion("Sure! Here you go: {not valid json")
            return _StubCompletion(VALID_PAYLOAD)

    class _Client:
        chat = type("C", (), {"completions": _Completions()})()

    monkeypatch.setattr(scam_detector, "_get_client", lambda: _Client())

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )
    assert state["calls"] == 2
    assert result.degraded is False
    assert result.breakdown.llm_score == 95


def test_llm_outage_degrades_to_rules_instead_of_failing(monkeypatch):
    client, state = _stub_client(VALID_PAYLOAD, fail_times=99)
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )

    assert state["calls"] == 2, "should retry exactly once before degrading"
    assert result.degraded is True
    assert result.breakdown.llm_available is False
    assert result.breakdown.llm_score is None
    # The whole point: an obvious scam still gets caught with the LLM down.
    assert result.scam_probability >= 70
    assert result.scam_type is ScamType.DIGITAL_ARREST
    assert result.red_flags
    assert "DEGRADED MODE" in result.reasoning


def test_degraded_mode_stays_quiet_on_legitimate_calls(monkeypatch):
    client, _ = _stub_client(VALID_PAYLOAD, fail_times=99)
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c2", transcript=OBVIOUS_LEGITIMATE)
    )
    assert result.scam_probability < 30
    assert result.scam_type is ScamType.NONE


def test_out_of_range_llm_score_is_clamped(monkeypatch):
    client, _ = _stub_client(
        VALID_PAYLOAD.replace('"scam_probability": 95', '"scam_probability": 175')
    )
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )
    assert result.breakdown.llm_score == 100
    assert 0 <= result.scam_probability <= 100


def test_unknown_enum_values_fall_back_safely(monkeypatch):
    client, _ = _stub_client(
        VALID_PAYLOAD.replace('"scam_type": "digital_arrest"', '"scam_type": "alien_invasion"')
    )
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )
    # Unknown type degrades to "none", but a high score must not stay incoherent.
    assert result.scam_type is ScamType.OTHER_SCAM


def test_action_is_derived_from_fused_score_not_the_model(monkeypatch):
    """The model suggesting 'monitor' on a 95 must not override our thresholds."""
    client, _ = _stub_client(
        VALID_PAYLOAD.replace('"recommended_action": "urgent_intervention"',
                              '"recommended_action": "monitor"')
    )
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )
    assert result.recommended_action is RecommendedAction.URGENT_INTERVENTION


def test_escalation_stage_floor_is_enforced_by_rules(monkeypatch):
    """If the LLM under-calls the stage, hard evidence raises it."""
    client, _ = _stub_client(
        VALID_PAYLOAD.replace('"escalation_stage": "extraction_attempted"',
                              '"escalation_stage": "pretext_established"')
    )
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )
    assert result.escalation_stage is EscalationStage.EXTRACTION_ATTEMPTED


def test_entities_extracted_regardless_of_llm(monkeypatch):
    client, _ = _stub_client(VALID_PAYLOAD, fail_times=99)
    monkeypatch.setattr(scam_detector, "_get_client", lambda: client)

    result = scam_detector.classify(
        ClassifyRequest(conversation_id="c1", transcript=OBVIOUS_SCAM)
    )
    assert "50100294471882" in result.extracted_entities.bank_accounts
    assert "CBI" in result.extracted_entities.claimed_departments


def test_fusion_math():
    settings = get_settings()
    original = settings.rule_weight
    try:
        object.__setattr__(settings, "rule_weight", 0.25)
        # 0.75*80 + 0.25*40 = 70
        assert scam_detector._fuse(rule_score=40, llm_score=80) == 70
        assert scam_detector._fuse(rule_score=0, llm_score=0) == 0
        assert scam_detector._fuse(rule_score=100, llm_score=100) == 100
    finally:
        object.__setattr__(settings, "rule_weight", original)
