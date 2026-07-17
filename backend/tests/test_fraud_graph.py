"""Fraud Network Graph Agent tests.

Fully offline — no LLM, no network. The graph is the project's differentiating
claim, so its failure modes get more attention than its happy path:
false linking is worse than no linking, because it would name innocent people.
"""

from __future__ import annotations

import pytest

from app.agents.fraud_graph import FraudGraph
from app.agents.graph_seed import (
    SHARED_LOTTERY_UPI,
    SHARED_MULE_ACCOUNT,
    SHARED_MULE_UPI,
    seed_graph,
)
from app.models.graph_schemas import EntityType
from app.models.schemas import ExtractedEntities


@pytest.fixture
def graph() -> FraudGraph:
    g = FraudGraph()
    seed_graph(g, reset=True)
    return g


@pytest.fixture
def empty_graph() -> FraudGraph:
    return FraudGraph()


# --- The core claim ---------------------------------------------------------

class TestCrossVictimMatching:
    def test_reused_mule_account_identifies_repeat_scammer(self, graph):
        """The demo's key moment: a live call quoting a known mule account."""
        match = graph.cross_reference(
            session_id="LIVE-001",
            entities=ExtractedEntities(bank_accounts=[SHARED_MULE_ACCOUNT]),
            scam_type="digital_arrest",
            scam_probability=95,
        )
        assert match.is_repeat_scammer is True
        assert match.confidence >= 0.9
        # SEED-001 and SEED-002 both used this account.
        linked = {s.session_id for s in match.linked_sessions}
        assert linked == {"SEED-001", "SEED-002"}
        assert "REPEAT SCAMMER" in match.summary
        assert SHARED_MULE_ACCOUNT in match.summary

    def test_summary_distinguishes_direct_from_transitive_links(self, graph):
        """The account was seen by 2 victims; the operation spans 3. Don't conflate.

        This sentence is shown to a frightened person and copied into a police
        complaint, so an overstated count is a false statement, not a rounding error.
        """
        match = graph.cross_reference(
            session_id="LIVE-PRECISE",
            entities=ExtractedEntities(bank_accounts=[SHARED_MULE_ACCOUNT]),
        )
        # SEED-001 and SEED-002 share the account itself.
        assert "2 other victims" in match.summary
        # SEED-003 joins the cluster via a different identifier.
        assert match.total_victims_in_cluster == 3
        assert "3 victims in total" in match.summary
        assert "3 other victims" not in match.summary, "overstated the direct count"

    def test_reused_upi_links_across_sessions(self, graph):
        match = graph.cross_reference(
            session_id="LIVE-002",
            entities=ExtractedEntities(upi_ids=[SHARED_MULE_UPI]),
        )
        assert match.is_repeat_scammer is True
        assert {s.session_id for s in match.linked_sessions} == {"SEED-001", "SEED-003"}

    def test_reused_phone_links_across_sessions(self, graph):
        match = graph.cross_reference(
            session_id="LIVE-003",
            entities=ExtractedEntities(phone_numbers=["9876501234"]),
        )
        assert match.is_repeat_scammer is True
        assert {s.session_id for s in match.linked_sessions} == {"SEED-001", "SEED-003"}

    def test_unknown_entities_produce_no_match(self, graph):
        match = graph.cross_reference(
            session_id="LIVE-004",
            entities=ExtractedEntities(
                phone_numbers=["9999888877"],
                bank_accounts=["11112222333344"],
            ),
        )
        assert match.is_repeat_scammer is False
        assert match.linked_sessions == []
        assert match.confidence == 0.0
        assert len(match.new_entities) == 2
        assert "No prior session" in match.summary

    def test_empty_graph_never_matches(self, empty_graph):
        match = empty_graph.cross_reference(
            session_id="LIVE-005",
            entities=ExtractedEntities(bank_accounts=[SHARED_MULE_ACCOUNT]),
        )
        assert match.is_repeat_scammer is False

    def test_no_entities_produces_no_match(self, graph):
        match = graph.cross_reference("LIVE-006", ExtractedEntities())
        assert match.is_repeat_scammer is False
        assert match.new_entities == []


# --- The failure mode that matters most -------------------------------------

class TestFalseLinkingGuards:
    """Linking innocent people together is worse than missing a link."""

    def test_shared_claimed_department_does_not_link(self, graph):
        """Thousands of unrelated scammers all say 'CBI'. That must not link them."""
        match = graph.cross_reference(
            session_id="LIVE-007",
            entities=ExtractedEntities(claimed_departments=["CBI"]),
        )
        assert match.is_repeat_scammer is False, (
            "linking on claimed department would merge every digital-arrest scam "
            "in the country into one meaningless cluster"
        )

    def test_shared_claimed_name_does_not_link(self, graph):
        """'Inspector Sharma' is a stock alias, not an identity."""
        match = graph.cross_reference(
            session_id="LIVE-008",
            entities=ExtractedEntities(claimed_names=["Vikram Rathore"]),
        )
        assert match.is_repeat_scammer is False

    def test_department_plus_real_identifier_still_links_on_the_identifier(self, graph):
        """A generic attribute must not suppress a genuine link either."""
        match = graph.cross_reference(
            session_id="LIVE-009",
            entities=ExtractedEntities(
                claimed_departments=["CBI"],
                bank_accounts=[SHARED_MULE_ACCOUNT],
            ),
        )
        assert match.is_repeat_scammer is True
        # The link is attributed to the account, not the department.
        types = {e.entity_type for e in match.shared_entities}
        assert types == {EntityType.BANK_ACCOUNT}

    def test_separate_operations_do_not_merge(self, graph):
        """The lottery ring and the digital-arrest ring must stay distinct clusters."""
        arrest = graph.cross_reference(
            "LIVE-010", ExtractedEntities(bank_accounts=[SHARED_MULE_ACCOUNT])
        )
        lottery = graph.cross_reference(
            "LIVE-011", ExtractedEntities(upi_ids=[SHARED_LOTTERY_UPI])
        )
        assert arrest.is_repeat_scammer and lottery.is_repeat_scammer
        assert arrest.cluster_id != lottery.cluster_id, (
            "two unrelated operations collapsed into one cluster"
        )
        arrest_sessions = {s.session_id for s in arrest.linked_sessions}
        lottery_sessions = {s.session_id for s in lottery.linked_sessions}
        assert not (arrest_sessions & lottery_sessions)

    def test_a_session_does_not_link_to_itself(self, graph):
        graph.add_session(
            "LIVE-012",
            ExtractedEntities(bank_accounts=["55556666777788"]),
            "digital_arrest",
            90,
        )
        match = graph.cross_reference(
            "LIVE-012", ExtractedEntities(bank_accounts=["55556666777788"])
        )
        assert match.is_repeat_scammer is False, "a session matched itself"


# --- Clustering -------------------------------------------------------------

class TestClustering:
    def test_cluster_spans_the_whole_operation(self, graph):
        """SEED-001/002/003 are one operation, linked transitively.

        002 shares only an account with 001; 003 shares only a UPI/phone with 001.
        002 and 003 share nothing directly — they are still one cluster via 001.
        That transitivity is the point of using a graph rather than a lookup table.
        """
        match = graph.cross_reference(
            "LIVE-013", ExtractedEntities(bank_accounts=[SHARED_MULE_ACCOUNT])
        )
        assert match.cluster_id is not None
        assert match.total_victims_in_cluster == 3, (
            f"expected the full 3-victim operation, got {match.total_victims_in_cluster}"
        )

    def test_cluster_id_is_stable_across_queries(self, graph):
        a = graph.cross_reference("X1", ExtractedEntities(bank_accounts=[SHARED_MULE_ACCOUNT]))
        b = graph.cross_reference("X2", ExtractedEntities(bank_accounts=[SHARED_MULE_ACCOUNT]))
        assert a.cluster_id == b.cluster_id

    def test_lottery_cluster_has_two_victims(self, graph):
        match = graph.cross_reference("X3", ExtractedEntities(upi_ids=[SHARED_LOTTERY_UPI]))
        assert match.total_victims_in_cluster == 2


# --- Ingestion & state ------------------------------------------------------

class TestIngestion:
    def test_seed_loads_expected_shape(self, graph):
        stats = graph.stats()
        assert stats.total_sessions == 6
        assert stats.total_entities > 0
        # Cluster A (3) + Cluster B (2) + isolated (1) = 3 components.
        assert stats.clusters == 3, f"expected 3 operations, got {stats.clusters}"

    def test_adding_a_session_makes_it_findable(self, empty_graph):
        empty_graph.add_session(
            "S1", ExtractedEntities(upi_ids=["scam@ybl"]), "digital_arrest", 90
        )
        match = empty_graph.cross_reference("S2", ExtractedEntities(upi_ids=["scam@ybl"]))
        assert match.is_repeat_scammer is True
        assert match.linked_sessions[0].session_id == "S1"
        assert match.linked_sessions[0].scam_probability == 90

    def test_cross_reference_does_not_mutate_the_graph(self, graph):
        before = len(graph)
        graph.cross_reference("PROBE", ExtractedEntities(bank_accounts=["99998888777766"]))
        assert len(graph) == before, "cross_reference must be read-only"

    def test_entity_matching_is_case_insensitive(self, empty_graph):
        empty_graph.add_session("S1", ExtractedEntities(upi_ids=["Scam@YBL"]), "x", 90)
        match = empty_graph.cross_reference("S2", ExtractedEntities(upi_ids=["scam@ybl"]))
        assert match.is_repeat_scammer is True

    def test_reset_clears_everything(self, graph):
        assert len(graph) > 0
        graph.reset()
        assert len(graph) == 0
        assert graph.stats().total_sessions == 0


# --- Frontend view ----------------------------------------------------------

class TestGraphView:
    def test_view_serializes_nodes_and_edges(self, graph):
        view = graph.view()
        assert view.nodes and view.edges
        ids = {n.id for n in view.nodes}
        # Every edge must reference real nodes, or react-force-graph will throw.
        for edge in view.edges:
            assert edge.source in ids
            assert edge.target in ids

    def test_session_nodes_carry_scam_metadata(self, graph):
        view = graph.view()
        sessions = [n for n in view.nodes if n.type == "session"]
        assert len(sessions) == 6
        assert all(n.scam_probability is not None for n in sessions)

    def test_shared_entities_show_higher_degree(self, graph):
        view = graph.view()
        mule = next(n for n in view.nodes if n.label == SHARED_MULE_ACCOUNT)
        assert mule.session_count == 2, "the shared account should link 2 sessions"
