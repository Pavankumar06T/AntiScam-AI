"""Voice transcription endpoint.

Turns a spoken clip into a transcript via Groq Whisper (whisper-large-v3), so the
same detection pipeline that scores demo transcripts can score a real, live voice.
This is what lets the system work on *real* input — a person speaks a suspicious
call and it is analysed end to end — and it exercises the Speech-AI capability the
problem statement calls for.

Whisper auto-detects the spoken language (Indian scam calls code-switch constantly
between English, Hindi and Tamil), so we do not force a language on transcription.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from app.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["voice"])

WHISPER_MODEL = "whisper-large-v3"
MAX_AUDIO_BYTES = 25 * 1024 * 1024  # Groq's per-file limit


class TranscribeResponse(BaseModel):
    transcript: str
    model: str
    language: str | None = None


@router.post("/transcribe", response_model=TranscribeResponse)
async def transcribe(audio: UploadFile = File(...)) -> TranscribeResponse:
    """Transcribe an uploaded audio clip to text."""
    settings = get_settings()
    if not settings.groq_configured:
        raise HTTPException(
            status_code=503,
            detail="Voice transcription needs a Groq API key (whisper-large-v3).",
        )

    data = await audio.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty audio upload.")
    if len(data) > MAX_AUDIO_BYTES:
        raise HTTPException(status_code=413, detail="Audio too large (max 25 MB).")

    from groq import Groq

    client = Groq(api_key=settings.groq_api_key, timeout=60.0, max_retries=1)
    filename = audio.filename or "audio.webm"

    try:
        result = client.audio.transcriptions.create(
            model=WHISPER_MODEL,
            file=(filename, data),
            response_format="json",  # auto-detects spoken language
        )
    except Exception as exc:  # noqa: BLE001 - surface a clean 502 to the UI
        logger.warning("Whisper transcription failed: %s: %s", type(exc).__name__, exc)
        detail = "Transcription failed."
        if type(exc).__name__ == "RateLimitError":
            detail = "Groq audio quota reached — try again shortly."
        raise HTTPException(status_code=502, detail=detail) from exc

    text = (getattr(result, "text", "") or "").strip()
    logger.info("transcribe: %d bytes -> %d chars", len(data), len(text))
    return TranscribeResponse(
        transcript=text,
        model=WHISPER_MODEL,
        language=getattr(result, "language", None),
    )
