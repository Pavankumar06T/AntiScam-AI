"""API contract tests.

Validation and schema tests run offline. Tests marked `live` hit the real Groq
API and are skipped automatically when GROQ_API_KEY is unset.
"""

from __future__ import annotations

import pytest

from app.models.schemas import ClassifyRequest, RecommendedAction, ScamType
from tests.conftest import (
    OBVIOUS_LEGITIMATE,
    OBVIOUS_SCAM,
    requires_groq,
    skip_if_degraded,
)


# --- Offline: validation and contract ---------------------------------------

def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in ("ok", "degraded")
    assert isinstance(body["groq_configured"], bool)
    assert body["model"]


def test_empty_transcript_is_rejected(client):
    response = client.post(
        "/api/classify", json={"conversation_id": "t1", "transcript": ""}
    )
    assert response.status_code == 422


def test_whitespace_only_transcript_is_rejected(client):
    response = client.post(
        "/api/classify", json={"conversation_id": "t1", "transcript": "   \n  \t "}
    )
    assert response.status_code == 422


def test_missing_conversation_id_is_rejected(client):
    response = client.post("/api/classify", json={"transcript": "hello there"})
    assert response.status_code == 422


def test_empty_turns_list_is_rejected(client):
    response = client.post(
        "/api/classify",
        json={"conversation_id": "t1", "transcript": "", "turns": [{"text": "  "}]},
    )
    assert response.status_code == 422


def test_turns_alone_are_accepted():
    request = ClassifyRequest(
        conversation_id="t1",
        turns=[{"speaker": "caller", "text": "Hello", "timestamp": "00:01"}],
    )
    assert request.normalized_turns()[0].text == "Hello"


class TestTranscriptNormalization:
    def test_speaker_prefixes_are_parsed(self):
        request = ClassifyRequest(
            conversation_id="t1",
            transcript="caller: Hello sir\nuser: Who is this?",
        )
        turns = request.normalized_turns()
        assert [t.speaker.value for t in turns] == ["caller", "user"]
        assert turns[0].text == "Hello sir"
        assert [t.turn_index for t in turns] == [0, 1]

    def test_unprefixed_text_becomes_one_turn(self):
        request = ClassifyRequest(conversation_id="t1", transcript="Just some text")
        turns = request.normalized_turns()
        assert len(turns) == 1
        assert turns[0].text == "Just some text"

    def test_colon_in_sentence_is_not_a_speaker(self):
        request = ClassifyRequest(
            conversation_id="t1",
            transcript="The situation is this: your account is fine.",
        )
        turns = request.normalized_turns()
        assert turns[0].text == "The situation is this: your account is fine."


# --- Live: real Groq calls ---------------------------------------------------

@requires_groq
@pytest.mark.live
def test_obvious_scam_scores_above_70(client):
    response = client.post(
        "/api/classify",
        json={
            "conversation_id": "live_scam_01",
            "transcript": OBVIOUS_SCAM,
            "is_full_conversation": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["scam_probability"] > 70, f"got {body['scam_probability']}: {body['reasoning']}"
    skip_if_degraded(body)  # assertions below are about the LLM's judgement
    assert body["scam_type"] == ScamType.DIGITAL_ARREST.value
    assert body["recommended_action"] in (
        RecommendedAction.WARN_USER.value,
        RecommendedAction.URGENT_INTERVENTION.value,
    )
    assert len(body["red_flags"]) >= 3
    assert body["escalation_stage"] == "extraction_attempted"
    assert body["degraded"] is False


@requires_groq
@pytest.mark.live
def test_obvious_legitimate_scores_below_30(client):
    response = client.post(
        "/api/classify",
        json={
            "conversation_id": "live_legit_01",
            "transcript": OBVIOUS_LEGITIMATE,
            "is_full_conversation": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    # No skip here: staying quiet on a benign call must hold in degraded mode too.
    assert body["scam_probability"] < 30, f"got {body['scam_probability']}: {body['reasoning']}"
    assert body["scam_type"] == ScamType.NONE.value
    assert body["recommended_action"] == RecommendedAction.MONITOR.value


@requires_groq
@pytest.mark.live
def test_response_schema_is_complete(client):
    response = client.post(
        "/api/classify",
        json={"conversation_id": "live_schema_01", "transcript": OBVIOUS_SCAM},
    )
    assert response.status_code == 200
    body = response.json()
    skip_if_degraded(body)

    for field in (
        "conversation_id", "scam_probability", "scam_type", "red_flags",
        "confidence", "reasoning", "recommended_action", "escalation_stage",
        "extracted_entities", "breakdown", "latency_ms", "model", "degraded",
    ):
        assert field in body, f"missing field: {field}"

    assert body["conversation_id"] == "live_schema_01"
    assert 0 <= body["scam_probability"] <= 100
    assert 0.0 <= body["confidence"] <= 1.0
    assert body["reasoning"].strip()

    for flag in body["red_flags"]:
        assert flag["quote"].strip()
        assert flag["explanation"].strip()
        assert flag["category"]
        assert flag["severity"] in ("low", "medium", "high", "critical")

    breakdown = body["breakdown"]
    assert 0 <= breakdown["rule_score"] <= 100
    assert 0 <= breakdown["llm_score"] <= 100
    assert breakdown["llm_available"] is True


@requires_groq
@pytest.mark.live
def test_red_flag_quotes_are_grounded_in_the_transcript(client):
    """Quotes must be real spans, not hallucinations. Evidence packets depend on this."""
    response = client.post(
        "/api/classify",
        json={"conversation_id": "live_ground_01", "transcript": OBVIOUS_SCAM},
    )
    body = response.json()
    skip_if_degraded(body)  # rule-layer quotes carry context padding by design
    haystack = OBVIOUS_SCAM.lower()
    assert body["red_flags"], "expected red flags on an obvious scam"

    grounded = sum(1 for f in body["red_flags"] if f["quote"].strip().lower() in haystack)
    ratio = grounded / len(body["red_flags"])
    assert ratio >= 0.6, (
        f"only {grounded}/{len(body['red_flags'])} quotes were verbatim spans. "
        "Quotes must be grounded for the evidence packet to be usable."
    )


@requires_groq
@pytest.mark.live
def test_entities_are_extracted_from_a_scam_call(client):
    response = client.post(
        "/api/classify",
        json={"conversation_id": "live_entity_01", "transcript": OBVIOUS_SCAM},
    )
    # Entities come from the deterministic layer, so this must hold either way.
    entities = response.json()["extracted_entities"]
    assert "50100294471882" in entities["bank_accounts"]
    assert "CBI" in entities["claimed_departments"]


@requires_groq
@pytest.mark.live
def test_latency_is_reported_and_reasonable(client):
    """Groq's speed is a core claim of this project — assert it, don't assume it.

    Skips rather than fails when the free-tier rate limit degrades the call: that
    measures Groq's queue, not the detector, and shouldn't turn the suite red.
    """
    response = client.post(
        "/api/classify",
        json={"conversation_id": "live_latency_01", "transcript": OBVIOUS_SCAM},
    )
    body = response.json()
    if body["degraded"]:
        pytest.skip(f"rate limited, cannot measure model latency: {body['degraded_reason']}")

    assert body["latency_ms"] > 0
    assert body["latency_ms"] < 8_000, f"detection took {body['latency_ms']}ms"
    assert "X-Response-Time-Ms" in response.headers


@requires_groq
@pytest.mark.stress
def test_rate_limit_degrades_fast_instead_of_stalling(client):
    """A 429 must never stall a live call — it must fall through to the rules.

    Fires enough concurrent calls to trip the free-tier token limit, then asserts
    that every response came back promptly, degraded or not.

    Marked `stress` and excluded from the default run: one burst costs ~23k tokens,
    which is two minutes of the free-tier budget, and would rate-limit every test
    after it. Run explicitly with:  pytest -m stress
    """
    import concurrent.futures

    def fire(i: int):
        return client.post(
            "/api/classify",
            json={"conversation_id": f"live_burst_{i}", "transcript": OBVIOUS_SCAM},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(fire, range(6)))

    assert all(r.status_code == 200 for r in responses), "burst must never 5xx"

    for r in responses:
        body = r.json()
        # The SDK's default retry would sleep ~25s here. We disabled it on purpose.
        assert body["latency_ms"] < 15_000, (
            f"a rate-limited call stalled {body['latency_ms']}ms instead of degrading"
        )
        # Degraded or not, an obvious scam must still be caught.
        assert body["scam_probability"] >= 70, (
            f"burst call scored {body['scam_probability']} (degraded={body['degraded']})"
        )


@requires_groq
@pytest.mark.live
def test_partial_chunk_lowers_confidence(client):
    """An early fragment should be flagged but held less certain than a full call."""
    partial = "caller: Sir, I am calling from TRAI. Your number will be deactivated in two hours."
    response = client.post(
        "/api/classify",
        json={
            "conversation_id": "live_partial_01",
            "transcript": partial,
            "is_full_conversation": False,
        },
    )
    body = response.json()
    skip_if_degraded(body)
    assert body["confidence"] < 0.9
