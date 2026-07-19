"""Schemas for the Fraud Network Graph Agent.

The graph answers a question a single-conversation detector structurally cannot:
"is this caller already working other victims right now?"
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class EntityType(str, Enum):
    """Node types in the fraud graph.

    SESSION nodes and IDENTIFIER nodes share one graph: sessions link to the
    identifiers seen in them, so two sessions sharing an identifier are connected
    by a path of length 2. That adjacency *is* the cross-victim signal.
    """

    SESSION = "session"
    PHONE = "phone"
    UPI = "upi"
    BANK_ACCOUNT = "bank_account"
    CLAIMED_NAME = "claimed_name"
    CLAIMED_DEPARTMENT = "claimed_department"
    CASE_NUMBER = "case_number"
    URL = "url"


# Identifiers whose reuse across sessions genuinely implicates the same operation.
# Deliberately excludes CLAIMED_DEPARTMENT and CLAIMED_NAME: thousands of unrelated
# scammers all say "CBI" and "Inspector Sharma". Linking on those would merge the
# entire dataset into one meaningless blob and produce confident nonsense.
LINKABLE_TYPES = frozenset(
    {
        EntityType.PHONE,
        EntityType.UPI,
        EntityType.BANK_ACCOUNT,
        EntityType.CASE_NUMBER,
        EntityType.URL,
    }
)

# How much a shared identifier implies a shared operator, 0-1.
# A reused mule account is near-conclusive; a reused fake case number is strong
# but could be a template copied between unrelated gangs.
LINK_STRENGTH: dict[EntityType, float] = {
    EntityType.BANK_ACCOUNT: 0.95,
    EntityType.UPI: 0.95,
    EntityType.PHONE: 0.90,
    EntityType.URL: 0.75,
    EntityType.CASE_NUMBER: 0.60,
}


class GraphEntity(BaseModel):
    id: str = Field(description="Stable node id, e.g. 'phone:9876543210'.")
    type: EntityType
    value: str
    first_seen: str
    last_seen: str
    session_count: int = Field(description="How many sessions this identifier appears in.")


class EntityLink(BaseModel):
    """An identifier shared between the current session and a prior one."""

    entity_id: str
    entity_type: EntityType
    value: str
    strength: float = Field(ge=0.0, le=1.0)
    shared_with_sessions: list[str]


class LinkedSession(BaseModel):
    session_id: str
    scam_type: str
    scam_probability: int
    observed_at: str
    shared_entities: list[str] = Field(description="Entity ids shared with the query session.")


class GraphMatch(BaseModel):
    """Result of cross-referencing a session against the fraud graph."""

    is_repeat_scammer: bool = Field(
        description="True when this session shares a linkable identifier with a prior session."
    )
    cluster_id: str | None = Field(
        default=None, description="Connected-component id, e.g. 'CLUSTER-003'."
    )
    cluster_size: int = Field(default=0, description="Sessions in this cluster, including this one.")
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Strongest shared-identifier link strength."
    )
    linked_sessions: list[LinkedSession] = Field(default_factory=list)
    shared_entities: list[EntityLink] = Field(default_factory=list)
    new_entities: list[str] = Field(
        default_factory=list, description="Identifiers seen for the first time in this session."
    )
    summary: str = Field(description="Plain-language finding, safe to show an operator.")
    total_victims_in_cluster: int = Field(
        default=0, description="Distinct victim sessions linked to this operation."
    )


class DisruptionAction(BaseModel):
    """One recommended containment action against a scammer identifier."""

    action: Literal["freeze", "block", "takedown"]
    target_type: str  # bank_account, upi, phone, url
    value: str
    recipient: str  # who should action it
    rationale: str
    seen_in_sessions: int = 1


class DisruptionPackage(BaseModel):
    """A dispatch-ready containment packet — the 'disrupt' step.

    Detection warns the victim; this proposes cutting the operation off at the
    infrastructure — freezing the mule account, blocking the number — which, when
    the identifier is shared across a cluster, protects every linked victim at once.
    Deterministically assembled from captured identifiers so it is court-auditable.
    """

    package_id: str
    generated_at: str
    urgency: Literal["routine", "priority", "immediate"]
    cluster_id: str | None = None
    linked_victims: int = 0
    actions: list[DisruptionAction] = Field(default_factory=list)
    recipients: list[str] = Field(default_factory=list)
    note: str


class GraphStats(BaseModel):
    """Whole-graph state, for the Phase 3 dashboard."""

    total_sessions: int
    total_entities: int
    total_links: int
    clusters: int
    largest_cluster_size: int
    entities_by_type: dict[str, int]


class GraphNodeView(BaseModel):
    """A node shaped for react-force-graph."""

    id: str
    label: str
    type: str
    session_count: int = 1
    scam_type: str | None = None
    scam_probability: int | None = None


class GraphEdgeView(BaseModel):
    source: str
    target: str
    type: str


class GraphView(BaseModel):
    """Serialized graph for the frontend."""

    nodes: list[GraphNodeView]
    edges: list[GraphEdgeView]
    stats: GraphStats
