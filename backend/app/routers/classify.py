"""Detection endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from app.agents.scam_detector import DetectionError, classify
from app.config import get_settings, resolve_model_name
from app.models.schemas import ClassifyRequest, ClassifyResponse, HealthResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["detection"])

VERSION = "0.1.0"


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    settings = get_settings()
    return HealthResponse(
        status="ok" if settings.groq_configured else "degraded",
        groq_configured=settings.groq_configured,
        model=resolve_model_name(),
        version=VERSION,
    )


@router.post("/classify", response_model=ClassifyResponse)
def classify_transcript(request: ClassifyRequest) -> ClassifyResponse:
    """Score a transcript (full or partial) for conversational-fraud risk."""
    try:
        result = classify(request)
    except DetectionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Unexpected detection failure for %s", request.conversation_id)
        raise HTTPException(status_code=500, detail="Detection failed.") from exc

    logger.info(
        "classify conversation_id=%s score=%d type=%s stage=%s flags=%d "
        "latency_ms=%d degraded=%s",
        result.conversation_id,
        result.scam_probability,
        result.scam_type.value,
        result.escalation_stage.value,
        len(result.red_flags),
        result.latency_ms,
        result.degraded,
    )
    return result
