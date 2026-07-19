"""Phase 2 endpoints: full orchestration and fraud graph state."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator

from app.agents.disruption import build_disruption_package
from app.agents.fraud_graph import get_graph
from app.agents.graph_seed import seed_graph
from app.config import get_settings
from app.models.advisory_schemas import AdvisoryWarning, ComplaintPacket
from app.models.graph_schemas import DisruptionPackage, GraphMatch, GraphStats, GraphView
from app.models.schemas import ClassifyResponse, Turn
from app.orchestrator import process_session

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["orchestration"])


class SessionProcessRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    transcript: str = ""
    turns: list[Turn] | None = None
    is_full_conversation: bool = True
    language: str = Field(default="en", pattern="^(en|hi|ta)$")
    user_confirmed_fraud: bool = Field(
        default=False,
        description="Set true once the person confirms this was fraud; triggers the complaint draft.",
    )
    ingest_into_graph: bool = Field(
        default=True,
        description="False to cross-reference without recording the session.",
    )

    @model_validator(mode="after")
    def _require_content(self) -> "SessionProcessRequest":
        has_turns = bool(self.turns) and any(t.text.strip() for t in self.turns)
        if not self.transcript.strip() and not has_turns:
            raise ValueError("Provide non-empty `transcript` or `turns`.")
        return self


class SessionProcessResponse(BaseModel):
    session_id: str
    detection: ClassifyResponse
    graph_match: GraphMatch | None = None
    warning: AdvisoryWarning | None = None
    disruption: DisruptionPackage | None = None
    complaint: ComplaintPacket | None = None
    complaint_text: str | None = Field(
        default=None, description="Human-readable rendering of the complaint draft."
    )
    path: list[str] = Field(description="Agents that fired, in order.")


@router.post("/session/process", response_model=SessionProcessResponse)
def process(request: SessionProcessRequest) -> SessionProcessResponse:
    """Run a transcript through the full multi-agent pipeline."""
    try:
        state = process_session(
            session_id=request.session_id,
            transcript=request.transcript,
            turns=[t.model_dump() for t in request.turns] if request.turns else None,
            is_full_conversation=request.is_full_conversation,
            language=request.language,
            user_confirmed_fraud=request.user_confirmed_fraud,
            ingest_into_graph=request.ingest_into_graph,
        )
    except Exception as exc:
        logger.exception("Orchestration failed for %s", request.session_id)
        raise HTTPException(status_code=500, detail="Orchestration failed.") from exc

    complaint = state.get("complaint")
    detection = state["detection"]
    settings = get_settings()
    disruption = build_disruption_package(
        request.session_id,
        detection,
        state.get("graph_match"),
        warn_threshold=settings.warn_threshold,
        urgent_threshold=settings.urgent_threshold,
    )
    logger.info(
        "session/process id=%s path=%s disruption=%s",
        request.session_id, "->".join(state.get("path", [])),
        disruption.package_id if disruption else "none",
    )
    return SessionProcessResponse(
        session_id=request.session_id,
        detection=detection,
        graph_match=state.get("graph_match"),
        warning=state.get("warning"),
        disruption=disruption,
        complaint=complaint,
        complaint_text=complaint.to_text() if complaint else None,
        path=state.get("path", []),
    )


@router.get("/graph/entities", response_model=GraphView)
def graph_entities() -> GraphView:
    """Current fraud graph, shaped for react-force-graph."""
    return get_graph().view()


@router.get("/graph/stats", response_model=GraphStats)
def graph_stats() -> GraphStats:
    return get_graph().stats()


class SeedResponse(BaseModel):
    seeded: int
    stats: GraphStats


@router.post("/graph/seed", response_model=SeedResponse)
def reseed_graph(reset: bool = True) -> SeedResponse:
    """Reload the demo's prior sessions. Handy for resetting between demo runs."""
    graph = get_graph()
    count = seed_graph(graph, reset=reset)
    return SeedResponse(seeded=count, stats=graph.stats())
