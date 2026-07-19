"""Fraud Network Graph Agent.

The differentiator. A detector that reads one conversation can only ever say
"this looks like a scam". A graph that remembers every prior flagged session can
say something far more actionable:

    "The account this caller wants you to pay was used against two other people
     this week. This is an organised operation, not a mistake."

Design: sessions and identifiers are nodes in one bipartite graph.

    SESSION_a ──> upi:fraud@ybl <── SESSION_b
    SESSION_a ──> phone:98765…

Two sessions sharing an identifier sit at distance 2. A connected component is
therefore a *fraud cluster* — one operation, many victims — and NetworkX gives us
components, paths, and centrality for free.

Two decisions worth understanding:

1. **We only link on identifiers that actually implicate a shared operator**
   (phone, UPI, account, case number, URL). Not on "CBI" or "Inspector Sharma" —
   thousands of unrelated scammers claim both. Linking on those would collapse the
   entire dataset into one giant component and produce confident nonsense. Claimed
   names/departments are still *stored* as attributes for the evidence packet; they
   just don't create edges.

2. **Only high-risk sessions are ingested.** Recording every benign call would
   grow the graph without adding signal, and would risk linking innocent people
   (two legitimate HDFC calls share a bank helpline number).

In-memory NetworkX is a deliberate hackathon trade-off: no external DB, restart
loses state. Phase 4 notes this. A real deployment needs Neo4j and, far more
importantly, a legal basis for retaining this data.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

import networkx as nx

from app.models.graph_schemas import (
    LINK_STRENGTH,
    LINKABLE_TYPES,
    EntityLink,
    EntityType,
    GraphEdgeView,
    GraphMatch,
    GraphNodeView,
    GraphStats,
    GraphView,
    LinkedSession,
)
from app.models.schemas import ExtractedEntities

logger = logging.getLogger(__name__)

# Identifier types we store as attributes but never link on. See module docstring.
_NON_LINKABLE_FIELDS = {
    "claimed_names": EntityType.CLAIMED_NAME,
    "claimed_departments": EntityType.CLAIMED_DEPARTMENT,
}

_ENTITY_FIELD_TYPES = {
    "phone_numbers": EntityType.PHONE,
    "upi_ids": EntityType.UPI,
    "bank_accounts": EntityType.BANK_ACCOUNT,
    "case_numbers": EntityType.CASE_NUMBER,
    "urls": EntityType.URL,
    **_NON_LINKABLE_FIELDS,
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _node_id(entity_type: EntityType, value: str) -> str:
    return f"{entity_type.value}:{value.strip().lower()}"


def _session_id(session: str) -> str:
    return f"session:{session}"


class FraudGraph:
    """Thread-safe in-memory fraud entity graph.

    Thread safety matters: FastAPI serves requests from a threadpool, and a
    concurrent read during a write would otherwise see a half-built session.
    """

    def __init__(self) -> None:
        self._g = nx.Graph()
        self._lock = threading.RLock()

    # --- ingestion -----------------------------------------------------------

    def add_session(
        self,
        session_id: str,
        entities: ExtractedEntities,
        scam_type: str,
        scam_probability: int,
        observed_at: str | None = None,
    ) -> list[str]:
        """Add a flagged session and its identifiers. Returns new entity ids."""
        observed_at = observed_at or _now()
        new_entities: list[str] = []

        with self._lock:
            sid = _session_id(session_id)
            self._g.add_node(
                sid,
                type=EntityType.SESSION.value,
                value=session_id,
                scam_type=scam_type,
                scam_probability=scam_probability,
                observed_at=observed_at,
                first_seen=observed_at,
                last_seen=observed_at,
            )

            for field, entity_type in _ENTITY_FIELD_TYPES.items():
                for raw in getattr(entities, field, []) or []:
                    value = str(raw).strip()
                    if not value:
                        continue
                    nid = _node_id(entity_type, value)
                    if nid not in self._g:
                        self._g.add_node(
                            nid,
                            type=entity_type.value,
                            value=value,
                            first_seen=observed_at,
                            last_seen=observed_at,
                        )
                        new_entities.append(nid)
                    else:
                        self._g.nodes[nid]["last_seen"] = observed_at
                    self._g.add_edge(sid, nid, type="observed_in")

        logger.info(
            "graph: added session=%s entities=%d new=%d",
            session_id, self._g.degree(sid), len(new_entities),
        )
        return new_entities

    # --- querying ------------------------------------------------------------

    def cross_reference(
        self,
        session_id: str,
        entities: ExtractedEntities,
        scam_type: str = "unknown",
        scam_probability: int = 0,
    ) -> GraphMatch:
        """Check a session's identifiers against every prior session.

        Read-only: does NOT add the session. The orchestrator decides whether to
        ingest, so that a cross-reference can be run speculatively without
        polluting the graph.
        """
        with self._lock:
            sid = _session_id(session_id)
            shared: list[EntityLink] = []
            new_ids: list[str] = []
            linked_session_ids: set[str] = set()

            for field, entity_type in _ENTITY_FIELD_TYPES.items():
                for raw in getattr(entities, field, []) or []:
                    value = str(raw).strip()
                    if not value:
                        continue
                    nid = _node_id(entity_type, value)

                    if nid not in self._g:
                        new_ids.append(nid)
                        continue

                    # Which *other* sessions have this identifier?
                    others = [
                        n for n in self._g.neighbors(nid)
                        if self._g.nodes[n].get("type") == EntityType.SESSION.value
                        and n != sid
                    ]
                    if not others:
                        new_ids.append(nid)
                        continue

                    if entity_type not in LINKABLE_TYPES:
                        # Seen before, but too generic to imply a shared operator.
                        continue

                    linked_session_ids.update(others)
                    shared.append(
                        EntityLink(
                            entity_id=nid,
                            entity_type=entity_type,
                            value=value,
                            strength=LINK_STRENGTH.get(entity_type, 0.5),
                            shared_with_sessions=[
                                self._g.nodes[o]["value"] for o in sorted(others)
                            ],
                        )
                    )

            if not shared:
                return GraphMatch(
                    is_repeat_scammer=False,
                    new_entities=new_ids,
                    summary=(
                        "No prior session shares an identifier with this one. "
                        "Either a first sighting, or the operation is rotating identifiers."
                    ),
                )

            linked = [
                LinkedSession(
                    session_id=self._g.nodes[s]["value"],
                    scam_type=self._g.nodes[s].get("scam_type", "unknown"),
                    scam_probability=self._g.nodes[s].get("scam_probability", 0),
                    observed_at=self._g.nodes[s].get("observed_at", ""),
                    shared_entities=[
                        link.entity_id for link in shared
                        if self._g.nodes[s]["value"] in link.shared_with_sessions
                    ],
                )
                for s in sorted(linked_session_ids)
            ]

            cluster_id, cluster_size, victims = self._cluster_for(sid, shared)
            confidence = max(link.strength for link in shared)

            return GraphMatch(
                is_repeat_scammer=True,
                cluster_id=cluster_id,
                cluster_size=cluster_size,
                confidence=confidence,
                linked_sessions=linked,
                shared_entities=shared,
                new_entities=new_ids,
                total_victims_in_cluster=victims,
                summary=self._summarize(shared, linked, victims),
            )

    def _cluster_for(
        self, current_sid: str | None, shared: list[EntityLink]
    ) -> tuple[str | None, int, int]:
        """Identify the connected component, counting only *other* victims.

        The victim count deliberately excludes the querying session, so it reads the
        same whether or not this call has been ingested yet: "this scammer has
        already hit N *other* people." That keeps the number stable across replays
        (a demo would otherwise drift 3→4 as the live session joins the cluster) and
        is also the more honest claim — the current caller is the one being protected,
        not counted among the prior victims.
        """
        # Anchor on a shared identifier (always in the graph); fall back to the
        # session node only if it is already ingested.
        anchor = None
        if shared:
            anchor = shared[0].entity_id
        elif current_sid and current_sid in self._g:
            anchor = current_sid
        if anchor is None or anchor not in self._g:
            return None, 0, 0

        component = nx.node_connected_component(self._g, anchor)
        sessions = [
            n for n in component
            if self._g.nodes[n].get("type") == EntityType.SESSION.value
        ]
        # Stable id: index of this component among all components, sorted by size.
        components = sorted(
            nx.connected_components(self._g),
            key=lambda c: (-len(c), min(c)),
        )
        index = next((i for i, c in enumerate(components) if anchor in c), 0)

        other_victims = len([s for s in sessions if s != current_sid])
        total = other_victims + 1  # + the current caller being protected
        return f"CLUSTER-{index + 1:03d}", total, other_victims

    def _summarize(
        self, shared: list[EntityLink], linked: list[LinkedSession], victims: int
    ) -> str:
        """Describe the finding precisely.

        Two different numbers are in play and conflating them would be a false
        statement: how many victims saw *this specific identifier*, versus how many
        victims the wider operation touches (reached transitively via other shared
        identifiers). This claim ends up in front of a victim and inside a police
        complaint, so it distinguishes them.
        """
        strongest = max(shared, key=lambda s: s.strength)
        label = {
            EntityType.BANK_ACCOUNT: "bank account",
            EntityType.UPI: "UPI ID",
            EntityType.PHONE: "phone number",
            EntityType.CASE_NUMBER: "case number",
            EntityType.URL: "website",
        }.get(strongest.entity_type, "identifier")

        direct = len(strongest.shared_with_sessions)
        direct_phrase = (
            "another victim" if direct == 1 else f"{direct} other victims"
        )

        summary = (
            f"REPEAT SCAMMER. The {label} {strongest.value} in this call has already "
            f"been recorded against {direct_phrase}."
        )

        if victims > direct:
            summary += (
                f" Through other shared identifiers, this caller is linked to "
                f"{victims} victims in total."
            )

        summary += (
            " This is an organised operation running the same script on multiple "
            "people, not an isolated incident."
        )
        return summary

    # --- views ---------------------------------------------------------------

    def stats(self) -> GraphStats:
        with self._lock:
            by_type: dict[str, int] = {}
            sessions = 0
            for _, data in self._g.nodes(data=True):
                t = data.get("type", "unknown")
                by_type[t] = by_type.get(t, 0) + 1
                if t == EntityType.SESSION.value:
                    sessions += 1

            components = list(nx.connected_components(self._g))
            return GraphStats(
                total_sessions=sessions,
                total_entities=self._g.number_of_nodes() - sessions,
                total_links=self._g.number_of_edges(),
                clusters=len(components),
                largest_cluster_size=max((len(c) for c in components), default=0),
                entities_by_type={k: v for k, v in sorted(by_type.items())},
            )

    def view(self) -> GraphView:
        """Serialize for react-force-graph."""
        with self._lock:
            nodes = []
            for nid, data in self._g.nodes(data=True):
                t = data.get("type", "unknown")
                nodes.append(
                    GraphNodeView(
                        id=nid,
                        label=data.get("value", nid),
                        type=t,
                        session_count=(
                            1 if t == EntityType.SESSION.value else self._g.degree(nid)
                        ),
                        scam_type=data.get("scam_type"),
                        scam_probability=data.get("scam_probability"),
                    )
                )
            edges = [
                GraphEdgeView(source=u, target=v, type=d.get("type", "observed_in"))
                for u, v, d in self._g.edges(data=True)
            ]
            return GraphView(nodes=nodes, edges=edges, stats=self.stats())

    def reset(self) -> None:
        with self._lock:
            self._g.clear()

    def __len__(self) -> int:
        return self._g.number_of_nodes()


# Process-wide singleton. In-memory by design for the hackathon; see module docstring.
_graph = FraudGraph()


def get_graph() -> FraudGraph:
    return _graph
