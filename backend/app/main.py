"""AntiScam AI — FastAPI application entrypoint.

Phase 1: Detection Agent + /api/classify + /api/health.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.agents.fraud_graph import get_graph
from app.agents.graph_seed import seed_graph
from app.config import get_settings
from app.routers import classify as classify_router
from app.routers import session as session_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("antiscam")


@asynccontextmanager
async def lifespan(_: FastAPI):
    if not get_settings().groq_configured:
        logger.warning(
            "GROQ_API_KEY is not set — the Detection Agent will run in DEGRADED "
            "(rule-only) mode. Add your key to backend/.env to enable the LLM layer. "
            "Get one at https://console.groq.com/keys"
        )
    else:
        logger.info("Groq configured. Detection Agent ready.")

    # Seed prior sessions so the fraud graph has history to match against.
    # Without this the cross-victim lookup has nothing to find and the graph
    # agent looks broken rather than empty.
    seeded = seed_graph(get_graph(), reset=True)
    logger.info("Fraud graph seeded with %d prior sessions.", seeded)
    yield


app = FastAPI(
    lifespan=lifespan,
    title="AntiScam AI",
    description=(
        "Real-time interception of conversational fraud (digital arrest, KYC, "
        "prize, loan, job and investment scams) from live call/chat transcripts."
    ),
    version=classify_router.VERSION,
)

settings = get_settings()

# CORS. A wildcard origin ("*") and allow_credentials=True are mutually exclusive
# per the CORS spec — the browser rejects the combination. Since this API uses no
# cookies or auth, we drop credentials when the deployment opts into a wildcard,
# which is the common case for a public read-only demo API.
_wildcard = "*" in settings.cors_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if _wildcard else settings.cors_origins,
    allow_credentials=not _wildcard,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000
    logger.info(
        "%s %s -> %d in %.1fms",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.1f}"
    return response


app.include_router(classify_router.router)
app.include_router(session_router.router)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {
        "service": "AntiScam AI",
        "version": classify_router.VERSION,
        "docs": "/docs",
        "health": "/api/health",
    }
