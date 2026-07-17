"""LangGraph orchestration for AntiScam AI.

    transcript chunk
          │
          ▼
    ┌───────────┐
    │  detect   │  Scam Pattern Detection Agent
    └─────┬─────┘
          │  risk >= WARN_THRESHOLD ?
          ├── no ──> monitor ──> END        (cheap path: most calls end here)
          │
         yes
          ▼
    ┌───────────┐
    │   graph   │  Fraud Network Graph Agent — cross-victim lookup
    └─────┬─────┘
          ▼
    ┌───────────┐
    │ advisory  │  Advisory Agent — RAG-grounded warning
    └─────┬─────┘
          │  user confirmed fraud ?
          ├── no ──> END
         yes
          ▼
    ┌───────────┐
    │  report   │  Evidence & Reporting Agent — complaint draft
    └─────┬─────┘
          ▼
         END

Why conditional routing rather than running everything: the graph, advisory and
reporting agents are only meaningful once risk is real. Most monitored
conversations are ordinary calls, and running four agents on "hello, is that
Ramesh?" would waste the token budget that the genuine scams need.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph import END, StateGraph

from app.agents.advisory import generate_warning
from app.agents.fraud_graph import FraudGraph, get_graph
from app.agents.reporting import build_complaint
from app.agents.scam_detector import classify
from app.config import get_settings
from app.models.advisory_schemas import AdvisoryWarning, ComplaintPacket, Language
from app.models.graph_schemas import GraphMatch
from app.models.schemas import ClassifyRequest, ClassifyResponse

logger = logging.getLogger(__name__)


class SessionState(TypedDict, total=False):
    """State threaded through the graph."""

    # Inputs
    session_id: str
    transcript: str
    turns: list[dict[str, Any]] | None
    is_full_conversation: bool
    language: str
    user_confirmed_fraud: bool
    ingest_into_graph: bool

    # Agent outputs
    detection: ClassifyResponse
    graph_match: GraphMatch | None
    warning: AdvisoryWarning | None
    complaint: ComplaintPacket | None

    # Trace of which agents fired, for the dashboard and for debugging.
    path: list[str]


def _append_path(state: SessionState, node: str) -> list[str]:
    return [*state.get("path", []), node]


# --- Nodes ------------------------------------------------------------------

def detect_node(state: SessionState) -> dict[str, Any]:
    request = ClassifyRequest(
        conversation_id=state["session_id"],
        transcript=state.get("transcript", ""),
        turns=state.get("turns"),
        is_full_conversation=state.get("is_full_conversation", True),
    )
    detection = classify(request)
    logger.info(
        "orchestrator: detect session=%s score=%d type=%s",
        state["session_id"], detection.scam_probability, detection.scam_type.value,
    )
    return {"detection": detection, "path": _append_path(state, "detect")}


def graph_node(state: SessionState) -> dict[str, Any]:
    detection: ClassifyResponse = state["detection"]
    graph: FraudGraph = get_graph()

    match = graph.cross_reference(
        session_id=state["session_id"],
        entities=detection.extracted_entities,
        scam_type=detection.scam_type.value,
        scam_probability=detection.scam_probability,
    )

    # Cross-reference first, then ingest — otherwise the session would match itself.
    if state.get("ingest_into_graph", True):
        graph.add_session(
            session_id=state["session_id"],
            entities=detection.extracted_entities,
            scam_type=detection.scam_type.value,
            scam_probability=detection.scam_probability,
        )

    logger.info(
        "orchestrator: graph session=%s repeat=%s cluster=%s",
        state["session_id"], match.is_repeat_scammer, match.cluster_id,
    )
    return {"graph_match": match, "path": _append_path(state, "graph")}


def advisory_node(state: SessionState) -> dict[str, Any]:
    detection: ClassifyResponse = state["detection"]
    match: GraphMatch | None = state.get("graph_match")

    try:
        language = Language(state.get("language", "en"))
    except ValueError:
        language = Language.ENGLISH

    warning = generate_warning(
        detection,
        language=language,
        graph_note=match.summary if match and match.is_repeat_scammer else None,
    )
    return {"warning": warning, "path": _append_path(state, "advisory")}


def report_node(state: SessionState) -> dict[str, Any]:
    complaint = build_complaint(
        session_id=state["session_id"],
        detection=state["detection"],
        match=state.get("graph_match"),
    )
    logger.info(
        "orchestrator: report session=%s complaint=%s",
        state["session_id"], complaint.complaint_id,
    )
    return {"complaint": complaint, "path": _append_path(state, "report")}


def monitor_node(state: SessionState) -> dict[str, Any]:
    """Terminal node for low-risk conversations. Exists so the trace is explicit."""
    return {"path": _append_path(state, "monitor")}


# --- Routing ----------------------------------------------------------------

def route_after_detection(state: SessionState) -> Literal["graph", "monitor"]:
    detection: ClassifyResponse = state["detection"]
    threshold = get_settings().warn_threshold
    return "graph" if detection.scam_probability >= threshold else "monitor"


def route_after_advisory(state: SessionState) -> Literal["report", "__end__"]:
    return "report" if state.get("user_confirmed_fraud") else END


# --- Graph ------------------------------------------------------------------

def build_orchestrator():
    workflow = StateGraph(SessionState)

    workflow.add_node("detect", detect_node)
    workflow.add_node("graph", graph_node)
    workflow.add_node("advisory", advisory_node)
    workflow.add_node("report", report_node)
    workflow.add_node("monitor", monitor_node)

    workflow.set_entry_point("detect")
    workflow.add_conditional_edges(
        "detect", route_after_detection, {"graph": "graph", "monitor": "monitor"}
    )
    workflow.add_edge("graph", "advisory")
    workflow.add_conditional_edges(
        "advisory", route_after_advisory, {"report": "report", END: END}
    )
    workflow.add_edge("report", END)
    workflow.add_edge("monitor", END)

    return workflow.compile()


_orchestrator = None


def get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = build_orchestrator()
    return _orchestrator


def process_session(
    session_id: str,
    transcript: str = "",
    turns: list[dict[str, Any]] | None = None,
    *,
    is_full_conversation: bool = True,
    language: str = "en",
    user_confirmed_fraud: bool = False,
    ingest_into_graph: bool = True,
) -> SessionState:
    """Run a transcript through the full agent pipeline."""
    initial: SessionState = {
        "session_id": session_id,
        "transcript": transcript,
        "turns": turns,
        "is_full_conversation": is_full_conversation,
        "language": language,
        "user_confirmed_fraud": user_confirmed_fraud,
        "ingest_into_graph": ingest_into_graph,
        "path": [],
    }
    return get_orchestrator().invoke(initial)
