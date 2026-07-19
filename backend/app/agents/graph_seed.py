"""Pre-seeded prior sessions for the fraud graph.

Without history, the graph agent has nothing to match against and the killer demo
moment ("this account already hit two other people") cannot happen. These represent
sessions AntiScam AI would have flagged over the preceding days.

Design of the seed set — it is built to prove three distinct things:

1. **A real cross-victim link.** SEED-001/002/003 form one digital-arrest operation:
   they share the mule account 50100294471882 and the UPI id cbi.verify@okaxis
   across three different victims. A live call quoting that account lights up.
2. **Separate operations stay separate.** SEED-004/005 are a lottery ring sharing
   their own UPI. They must NOT merge with the digital-arrest cluster — proving we
   don't link on "everyone says CBI".
3. **A lone session.** SEED-006 shares nothing, so "no match" is a real outcome and
   not an artefact of an empty graph.

All identifiers are fictional. Phone numbers use the 9876xxxxx range and accounts
are invented; none are real numbers.
"""

from __future__ import annotations

from app.agents.fraud_graph import FraudGraph
from app.models.schemas import ExtractedEntities

# The mule account and UPI that tie the digital-arrest cluster together.
# Referenced by tests and by the demo script.
SHARED_MULE_ACCOUNT = "50100294471882"
SHARED_MULE_UPI = "cbi.verify@okaxis"
SHARED_LOTTERY_UPI = "kbcclaim2024@ybl"

SEED_SESSIONS: list[dict] = [
    # --- Cluster A: one digital-arrest operation, three victims ---------------
    {
        "session_id": "SEED-001",
        "scam_type": "digital_arrest",
        "scam_probability": 96,
        "observed_at": "2026-07-14T10:22:00+00:00",
        "entities": ExtractedEntities(
            phone_numbers=["9876501234"],
            upi_ids=[SHARED_MULE_UPI],
            bank_accounts=[SHARED_MULE_ACCOUNT],
            claimed_names=["Vikram Rathore"],
            claimed_departments=["CBI"],
            case_numbers=["MUM/CBI/2024/8871"],
            amounts_mentioned=["Rs 4,50,000"],
        ),
    },
    {
        "session_id": "SEED-002",
        "scam_type": "digital_arrest",
        "scam_probability": 93,
        "observed_at": "2026-07-15T14:05:00+00:00",
        "entities": ExtractedEntities(
            # Different caller ID — the operation rotates phones but reuses the
            # account, which is exactly why we link on accounts.
            phone_numbers=["9876509988"],
            bank_accounts=[SHARED_MULE_ACCOUNT],
            claimed_names=["Anil Deshmukh"],
            claimed_departments=["CBI", "RBI"],
            case_numbers=["DEL/CBI/2024/9912"],
            amounts_mentioned=["Rs 2,75,000"],
        ),
    },
    {
        "session_id": "SEED-003",
        "scam_type": "digital_arrest",
        "scam_probability": 91,
        "observed_at": "2026-07-16T09:41:00+00:00",
        "entities": ExtractedEntities(
            phone_numbers=["9876501234"],  # phone reused from SEED-001
            upi_ids=[SHARED_MULE_UPI],
            claimed_names=["Vikram Rathore"],
            claimed_departments=["ENFORCEMENT DIRECTORATE"],
            urls=["www.cbi-verify-portal.in"],
            amounts_mentioned=["Rs 8,00,000"],
        ),
    },
    # --- Cluster B: a separate lottery ring. Must not merge with Cluster A. ---
    {
        "session_id": "SEED-004",
        "scam_type": "lottery_prize",
        "scam_probability": 89,
        "observed_at": "2026-07-15T11:30:00+00:00",
        "entities": ExtractedEntities(
            phone_numbers=["9876577001"],
            upi_ids=[SHARED_LOTTERY_UPI],
            claimed_names=["Rahul Verma"],
            # Note: no shared department with Cluster A, and even if there were,
            # departments do not create links.
            amounts_mentioned=["Rs 12,500", "25 lakh"],
        ),
    },
    {
        "session_id": "SEED-005",
        "scam_type": "lottery_prize",
        "scam_probability": 87,
        "observed_at": "2026-07-16T16:12:00+00:00",
        "entities": ExtractedEntities(
            phone_numbers=["9876577002"],
            upi_ids=[SHARED_LOTTERY_UPI],
            claimed_names=["Rahul Verma"],
            amounts_mentioned=["Rs 15,000"],
        ),
    },
    # --- Isolated: proves "no match" is a genuine outcome --------------------
    {
        "session_id": "SEED-006",
        "scam_type": "kyc_fraud",
        "scam_probability": 78,
        "observed_at": "2026-07-16T18:55:00+00:00",
        "entities": ExtractedEntities(
            phone_numbers=["9876533333"],
            upi_ids=["kycupdate.help@paytm"],
            claimed_departments=["HDFC"],
        ),
    },
]


# Victim locations for the geospatial view. The digital-arrest cluster
# (SEED-001/002/003) deliberately spans Mumbai → Delhi → Bengaluru: one operation
# working victims across jurisdictions, which is exactly the cross-jurisdiction
# fraud-campaign mapping the problem statement asks for. Coordinates are real city
# centroids; the victim assignment is synthetic.
SEED_LOCATIONS: dict[str, tuple[str, float, float]] = {
    "SEED-001": ("Mumbai", 19.076, 72.877),
    "SEED-002": ("New Delhi", 28.614, 77.209),
    "SEED-003": ("Bengaluru", 12.972, 77.594),
    "SEED-004": ("Kolkata", 22.573, 88.364),
    "SEED-005": ("Chennai", 13.083, 80.271),
    "SEED-006": ("Hyderabad", 17.385, 78.487),
}


def seed_graph(graph: FraudGraph, *, reset: bool = False) -> int:
    """Load the prior sessions. Returns the number seeded."""
    if reset:
        graph.reset()
    for record in SEED_SESSIONS:
        city, lat, lon = SEED_LOCATIONS.get(record["session_id"], (None, None, None))
        graph.add_session(
            session_id=record["session_id"],
            entities=record["entities"],
            scam_type=record["scam_type"],
            scam_probability=record["scam_probability"],
            observed_at=record["observed_at"],
            city=city,
            lat=lat,
            lon=lon,
        )
    return len(SEED_SESSIONS)
