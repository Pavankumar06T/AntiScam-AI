"""Configuration loading for AntiScam AI.

All secrets come from the environment (loaded from a local .env in development).
Nothing sensitive is ever hardcoded here.
"""

from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

BACKEND_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_ROOT / "data"

load_dotenv(BACKEND_ROOT / ".env")

# Ordered fallbacks used if MODEL_NAME is not offered by the account/region.
# Groq rotates its lineup, so we resolve against the live catalogue at startup.
MODEL_FALLBACKS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "moonshotai/kimi-k2-instruct",
]


class Settings:
    def __init__(self) -> None:
        self.groq_api_key: str | None = os.environ.get("GROQ_API_KEY") or None
        self.model_name: str = os.environ.get("MODEL_NAME", MODEL_FALLBACKS[0])
        self.temperature: float = float(os.environ.get("TEMPERATURE", "0.2"))
        self.request_timeout: float = float(os.environ.get("GROQ_TIMEOUT_SECONDS", "30"))

        # Risk thresholds. Shared by the API, the UI, and the Phase 2 orchestrator
        # so that "what counts as a warning" is defined in exactly one place.
        self.warn_threshold: int = int(os.environ.get("WARN_THRESHOLD", "50"))
        self.urgent_threshold: int = int(os.environ.get("URGENT_THRESHOLD", "75"))

        # Weight of the deterministic rule layer when fused with the LLM score.
        self.rule_weight: float = float(os.environ.get("RULE_WEIGHT", "0.25"))

        self.cors_origins: list[str] = [
            o.strip()
            for o in os.environ.get(
                "CORS_ORIGINS", "http://localhost:5173,http://localhost:3000"
            ).split(",")
            if o.strip()
        ]

    @property
    def groq_configured(self) -> bool:
        return bool(self.groq_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


@lru_cache(maxsize=1)
def resolve_model_name() -> str:
    """Return a model id that this Groq account can actually serve.

    Groq's catalogue changes over time. Rather than hard-failing when the
    configured model is retired, we check the live list and fall back to the
    closest available substitute, logging the substitution loudly.
    """
    settings = get_settings()
    configured = settings.model_name

    if not settings.groq_configured:
        return configured

    try:
        from groq import Groq

        client = Groq(api_key=settings.groq_api_key, timeout=10.0)
        available = {m.id for m in client.models.list().data}
    except Exception as exc:  # network/auth issues shouldn't block startup
        logger.warning(
            "Could not fetch Groq model catalogue (%s). Using configured model %r as-is.",
            exc,
            configured,
        )
        return configured

    if configured in available:
        return configured

    for candidate in MODEL_FALLBACKS:
        if candidate in available:
            logger.warning(
                "Configured MODEL_NAME %r is not available on this Groq account. "
                "Falling back to %r.",
                configured,
                candidate,
            )
            return candidate

    raise RuntimeError(
        f"MODEL_NAME {configured!r} is unavailable and none of the fallbacks "
        f"{MODEL_FALLBACKS} are offered. Available models: {sorted(available)}"
    )
