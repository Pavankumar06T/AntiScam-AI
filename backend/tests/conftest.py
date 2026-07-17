from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.main import app  # noqa: E402


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "live: hits the real Groq API; skipped when GROQ_API_KEY is unset."
    )
    config.addinivalue_line(
        "markers", "stress: expensive burst tests; opt in with `pytest -m stress`."
    )


# Groq's free tier allows ~12k tokens/min and one detection call costs ~3.9k.
# Three back-to-back live tests exhaust the budget, so we pace them. Without this
# the live tests rate-limit each other and measure Groq's queue, not our detector.
_LIVE_CALL_SPACING_SECONDS = float(os.environ.get("LIVE_TEST_SPACING", "21"))
_last_live_call: list[float] = [0.0]


@pytest.fixture(autouse=True)
def _pace_live_tests(request: pytest.FixtureRequest):
    """Space out live tests to stay inside the free-tier token budget."""
    if "live" not in request.keywords or not get_settings().groq_configured:
        yield
        return

    elapsed = time.monotonic() - _last_live_call[0]
    if _last_live_call[0] and elapsed < _LIVE_CALL_SPACING_SECONDS:
        time.sleep(_LIVE_CALL_SPACING_SECONDS - elapsed)
    yield
    _last_live_call[0] = time.monotonic()


def skip_if_degraded(body: dict) -> None:
    """Skip a live assertion that needs the LLM when we only got a rule-only score."""
    if body.get("degraded"):
        pytest.skip(f"LLM layer unavailable: {body.get('degraded_reason')}")


@pytest.fixture(scope="session")
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(scope="session")
def groq_available() -> bool:
    return get_settings().groq_configured


requires_groq = pytest.mark.skipif(
    not get_settings().groq_configured,
    reason="GROQ_API_KEY not set — live LLM tests skipped.",
)


# --- Shared fixtures ---------------------------------------------------------

OBVIOUS_SCAM = """\
caller: Sir, this is Inspector Deshmukh from CBI Delhi crime branch, badge 8842.
user: What is this regarding?
caller: A parcel in your name containing 300 grams of MDMA was seized at Mumbai airport. FIR number DEL/CBI/2024/9912 is registered against you under the NDPS Act.
user: That's impossible, I never sent a parcel.
caller: Your Aadhaar was used, sir. You are under digital arrest from this moment. Do not disconnect this video call and do not inform your family. This is a classified investigation.
user: Please, what do I do?
caller: To verify your funds are not from crime proceeds, transfer 4,50,000 rupees to the RBI verification account 50100294471882 immediately. It will be refunded within two hours after clearance. If you delay, a non-bailable warrant will be issued and you will be arrested tonight.
"""

OBVIOUS_LEGITIMATE = """\
caller: Hi, is this Meera? This is Karthik from Zomato support, calling about the order you raised a complaint on.
user: Yes, that's me. The order never arrived.
caller: I'm sorry about that. I can see the delivery partner marked it delivered at 8:42 PM but the GPS shows they were 600 metres away. I'm processing a full refund of 480 rupees to your original payment method right now.
user: Oh, thank you. How long does that take?
caller: Three to five working days back to your card. Your complaint reference is ZOM-4471822. Is there anything else I can help with?
user: No, that's all. Thanks.
caller: Thank you for your patience, Meera. Have a good evening.
"""
