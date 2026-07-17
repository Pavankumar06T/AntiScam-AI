"""Orchestration tests: routing, agent sequencing, and end-to-end wiring.

Offline — the LLM layers degrade to their rule/template fallbacks, which is
exactly what lets these run at zero token cost. Routing and sequencing are the
logic we own; they should not need Groq to verify.
"""

from __future__ import annotations

import pytest

from app.agents.fraud_graph import get_graph
from app.agents.graph_seed import SHARED_MULE_ACCOUNT, seed_graph
from app.models.schemas import ScamType
from app.orchestrator import process_session
from tests.conftest import OBVIOUS_LEGITIMATE

# A scam transcript quoting the mule account already in the seed graph — the
# demo's headline moment.
REPEAT_SCAMMER_TRANSCRIPT = f"""\
caller: This is Inspector Vikram Rathore from CBI Mumbai. A money laundering case is registered against your Aadhaar.
user: What? I haven't done anything.
caller: You are under digital arrest. Do not disconnect this video call and do not inform your family.
user: Please, what should I do?
caller: Transfer Rs 4,50,000 to the RBI verification account {SHARED_MULE_ACCOUNT} immediately or a non-bailable warrant will be issued.
"""

NOVEL_SCAM_TRANSCRIPT = """\
caller: This is Officer Sharma from the Narcotics Control Bureau. You are under digital arrest.
user: What is happening?
caller: Do not tell your family. Transfer Rs 2,00,000 to account 99887766554433 for verification immediately.
"""


@pytest.fixture(autouse=True)
def _fresh_graph():
    seed_graph(get_graph(), reset=True)
    yield
    seed_graph(get_graph(), reset=True)


class TestRouting:
    def test_low_risk_stops_after_detection(self):
        """Most calls are ordinary. They must not burn the graph/advisory agents."""
        state = process_session("LOW-001", transcript=OBVIOUS_LEGITIMATE)

        assert state["path"] == ["detect", "monitor"]
        assert state["detection"].scam_probability < 50
        assert state.get("graph_match") is None
        assert state.get("warning") is None
        assert state.get("complaint") is None

    def test_high_risk_runs_graph_then_advisory(self):
        state = process_session("HIGH-001", transcript=NOVEL_SCAM_TRANSCRIPT)

        assert state["path"] == ["detect", "graph", "advisory"]
        assert state["detection"].scam_probability >= 50
        assert state["graph_match"] is not None
        assert state["warning"] is not None
        assert state.get("complaint") is None, "no complaint without user confirmation"

    def test_confirmed_fraud_reaches_the_reporting_agent(self):
        state = process_session(
            "CONF-001", transcript=NOVEL_SCAM_TRANSCRIPT, user_confirmed_fraud=True
        )
        assert state["path"] == ["detect", "graph", "advisory", "report"]
        assert state["complaint"] is not None

    def test_confirmation_alone_does_not_force_a_complaint(self):
        """A benign call must not produce a police complaint just because a flag was set."""
        state = process_session(
            "CONF-002", transcript=OBVIOUS_LEGITIMATE, user_confirmed_fraud=True
        )
        assert state["path"] == ["detect", "monitor"]
        assert state.get("complaint") is None


class TestCrossVictimIntelligence:
    def test_repeat_scammer_is_detected_end_to_end(self):
        """The differentiating claim, verified through the whole pipeline."""
        state = process_session("LIVE-REPEAT", transcript=REPEAT_SCAMMER_TRANSCRIPT)

        match = state["graph_match"]
        assert match.is_repeat_scammer is True
        assert match.cluster_id is not None
        assert match.total_victims_in_cluster >= 2
        linked = {s.session_id for s in match.linked_sessions}
        assert "SEED-001" in linked and "SEED-002" in linked

    def test_repeat_finding_reaches_the_warning(self):
        state = process_session("LIVE-REPEAT-2", transcript=REPEAT_SCAMMER_TRANSCRIPT)
        warning = state["warning"]
        assert warning is not None
        assert warning.citations, "warning must cite the advisory it drew on"

    def test_novel_scam_reports_no_prior_match(self):
        state = process_session("LIVE-NOVEL", transcript=NOVEL_SCAM_TRANSCRIPT)
        assert state["graph_match"].is_repeat_scammer is False

    def test_session_is_ingested_and_findable_afterwards(self):
        graph = get_graph()
        before = graph.stats().total_sessions

        process_session("LIVE-INGEST", transcript=NOVEL_SCAM_TRANSCRIPT)
        assert graph.stats().total_sessions == before + 1

        # A second victim of the same operation now links to the first.
        state = process_session("LIVE-INGEST-2", transcript=NOVEL_SCAM_TRANSCRIPT)
        match = state["graph_match"]
        assert match.is_repeat_scammer is True
        assert "LIVE-INGEST" in {s.session_id for s in match.linked_sessions}

    def test_ingest_can_be_disabled(self):
        graph = get_graph()
        before = graph.stats().total_sessions
        process_session(
            "LIVE-NOINGEST", transcript=NOVEL_SCAM_TRANSCRIPT, ingest_into_graph=False
        )
        assert graph.stats().total_sessions == before

    def test_a_session_never_matches_itself(self):
        """Cross-reference must run before ingestion, or every session self-matches."""
        state = process_session("SELF-001", transcript=NOVEL_SCAM_TRANSCRIPT)
        linked = {s.session_id for s in state["graph_match"].linked_sessions}
        assert "SELF-001" not in linked


class TestComplaintPacket:
    def test_complaint_carries_evidence_and_identifiers(self):
        state = process_session(
            "COMP-001", transcript=REPEAT_SCAMMER_TRANSCRIPT, user_confirmed_fraud=True
        )
        c = state["complaint"]

        assert c.complaint_id.startswith("ASAI-")
        assert c.session_id == "COMP-001"
        assert SHARED_MULE_ACCOUNT in c.suspect_bank_accounts
        assert "CBI" in c.suspect_claimed_agency
        assert c.evidence, "a complaint with no quoted evidence is useless"
        assert c.applicable_provisions
        assert c.recommended_channels
        assert "DRAFT" in c.disclaimer.upper()

    def test_complaint_references_the_fraud_cluster(self):
        state = process_session(
            "COMP-002", transcript=REPEAT_SCAMMER_TRANSCRIPT, user_confirmed_fraud=True
        )
        c = state["complaint"]
        assert c.linked_cluster_id is not None
        assert c.linked_session_count >= 2
        assert c.network_note and "REPEAT SCAMMER" in c.network_note

    def test_complaint_renders_as_readable_text(self):
        state = process_session(
            "COMP-003", transcript=REPEAT_SCAMMER_TRANSCRIPT, user_confirmed_fraud=True
        )
        text = state["complaint"].to_text()

        assert "CYBER FRAUD COMPLAINT" in text
        assert "DRAFT" in text
        assert SHARED_MULE_ACCOUNT in text
        assert "1930" in text, "must tell the victim where to actually get help"
        assert "cybercrime.gov.in" in text

    def test_evidence_quotes_are_grounded_in_the_transcript(self):
        """A complaint containing invented quotes would be actively harmful."""
        state = process_session(
            "COMP-004", transcript=REPEAT_SCAMMER_TRANSCRIPT, user_confirmed_fraud=True
        )
        # Quotes are whitespace-normalised when extracted (a quote may span turns),
        # so normalise the haystack the same way before comparing.
        haystack = " ".join(REPEAT_SCAMMER_TRANSCRIPT.split()).lower()
        assert state["complaint"].evidence

        for e in state["complaint"].evidence:
            core = " ".join(e.quote.strip("… ").split()).lower()
            # Rule-layer quotes carry ±40 chars of context; probe a solid interior
            # span so the check is about groundedness, not exact boundaries.
            probe = core[10:50] if len(core) > 60 else core
            assert probe in haystack, f"ungrounded quote in complaint: {e.quote!r}"


class TestWarning:
    def test_warning_is_generated_with_actions_and_citations(self):
        state = process_session("WARN-001", transcript=NOVEL_SCAM_TRANSCRIPT)
        w = state["warning"]

        assert w.headline.strip()
        assert w.body.strip()
        assert w.immediate_actions, "a warning with no actions tells the user nothing"
        assert w.citations
        assert "1930" in w.disclaimer

    @pytest.mark.parametrize("language", ["en", "hi", "ta"])
    def test_warning_renders_in_each_language(self, language):
        state = process_session(
            f"LANG-{language}", transcript=NOVEL_SCAM_TRANSCRIPT, language=language
        )
        w = state["warning"]
        assert w.language.value == language
        assert w.headline.strip()
        assert w.immediate_actions

    def test_hindi_and_tamil_warnings_are_not_english(self):
        """Template fallbacks must be genuinely localised, not English placeholders."""
        hi = process_session("LANG-HI-2", transcript=NOVEL_SCAM_TRANSCRIPT, language="hi")
        ta = process_session("LANG-TA-2", transcript=NOVEL_SCAM_TRANSCRIPT, language="ta")

        # Devanagari / Tamil unicode blocks.
        assert any("ऀ" <= c <= "ॿ" for c in hi["warning"].headline)
        assert any("஀" <= c <= "௿" for c in ta["warning"].headline)

    def test_urgency_scales_with_risk(self):
        low = process_session("URG-LOW", transcript=OBVIOUS_LEGITIMATE)
        high = process_session("URG-HIGH", transcript=REPEAT_SCAMMER_TRANSCRIPT)

        assert low.get("warning") is None  # never reached the advisory agent
        assert high["warning"].urgency.value in ("warning", "critical")


class TestDegradedOperation:
    def test_full_pipeline_survives_without_the_llm(self):
        """With Groq exhausted, every agent must still produce something usable.

        This is the demo-day insurance policy: a quota 429 mid-pitch degrades the
        output, it does not break the product.
        """
        state = process_session(
            "DEGRADED-001", transcript=REPEAT_SCAMMER_TRANSCRIPT, user_confirmed_fraud=True
        )

        assert state["path"] == ["detect", "graph", "advisory", "report"]
        assert state["detection"].scam_probability >= 70
        assert state["detection"].scam_type is ScamType.DIGITAL_ARREST
        assert state["graph_match"].is_repeat_scammer is True
        assert state["warning"].headline.strip()
        assert state["complaint"].evidence
