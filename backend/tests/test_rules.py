"""Tests for the deterministic tripwire layer.

These run with no API key and no network — they are the safety net that keeps
working when the LLM layer is unavailable.
"""

from __future__ import annotations

import pytest

from app.agents import rules
from app.models.schemas import RedFlagCategory
from tests.conftest import OBVIOUS_LEGITIMATE, OBVIOUS_SCAM


def test_obvious_scam_scores_high_on_rules_alone():
    score, signals = rules.score_text(OBVIOUS_SCAM)
    assert score >= 70, f"rule score {score} too low; signals={[s.pattern_label for s in signals]}"
    assert len(signals) >= 4


def test_obvious_legitimate_scores_low_on_rules_alone():
    score, _ = rules.score_text(OBVIOUS_LEGITIMATE)
    assert score < 30, f"rule score {score} too high for a benign support call"


def test_empty_text_scores_zero():
    score, signals = rules.score_text("")
    assert score == 0
    assert signals == []


def test_digital_arrest_phrase_is_caught():
    _, signals = rules.score_text("You are under digital arrest, do not disconnect.")
    labels = {s.pattern_label for s in signals}
    assert "digital_arrest_phrase" in labels
    assert "isolation" in labels


@pytest.mark.parametrize(
    "text,expected_category",
    [
        ("Please share the OTP you just received", RedFlagCategory.CREDENTIAL_REQUEST),
        ("Transfer the money to this safe account", RedFlagCategory.FUND_TRANSFER_DEMAND),
        ("Install AnyDesk so I can check your phone", RedFlagCategory.REMOTE_ACCESS_REQUEST),
        ("A non-bailable warrant has been issued", RedFlagCategory.THREAT_OF_ARREST),
        ("You have won 25 lakh in the lucky draw", RedFlagCategory.UNREALISTIC_REWARD),
        ("Pay the processing fee to claim it", RedFlagCategory.ADVANCE_FEE),
        ("Do not tell anyone about this call", RedFlagCategory.ISOLATION_TACTIC),
        ("Your KYC is pending, account will be blocked", RedFlagCategory.VERIFICATION_PRETEXT),
    ],
)
def test_individual_patterns_fire(text, expected_category):
    _, signals = rules.score_text(text)
    assert expected_category in rules.signals_to_categories(signals)


def test_score_saturates_below_100():
    """Stacking every pattern must not produce false certainty."""
    everything = " ".join(
        [
            "I am Inspector Kumar from CBI. You are under digital arrest.",
            "A non-bailable warrant is issued. FIR number 8871 registered for money laundering.",
            "Do not tell anyone, stay on the call. This is strictly confidential.",
            "Transfer to the RBI verification account immediately via UPI.",
            "Share the OTP and your UPI PIN. Install AnyDesk now.",
            "You have won a lottery, pay the processing fee.",
        ]
    )
    score, signals = rules.score_text(everything)
    assert len(signals) >= 10
    assert 90 <= score <= 99, f"expected saturation near but below 100, got {score}"


def test_no_single_keyword_maxes_the_score():
    score, _ = rules.score_text("upi")
    assert score < 30, f"a lone payment-rail mention should not alarm; got {score}"


class TestEntityExtraction:
    def test_extracts_phone_upi_account_and_case(self):
        text = (
            "Call me back on +91 9876543210. Send the amount to fraudster42@ybl "
            "or account number 50100294471882, IFSC HDFC0001234. "
            "Your FIR no. MUM/CBI/2024/8871 is registered. "
            "Visit www.cbi-verify-portal.in and pay Rs 4,50,000."
        )
        e = rules.extract_entities(text)
        assert "9876543210" in e.phone_numbers
        assert "fraudster42@ybl" in e.upi_ids
        assert "50100294471882" in e.bank_accounts
        assert "HDFC0001234" in e.bank_accounts
        assert any("8871" in c for c in e.case_numbers)
        assert any("cbi-verify-portal" in u for u in e.urls)
        assert any("4,50,000" in a for a in e.amounts_mentioned)

    def test_normalizes_country_code(self):
        e = rules.extract_entities("Reach me at +919876543210 or 91-9876543210")
        assert e.phone_numbers == ["9876543210"]

    def test_extracts_claimed_officer_and_department(self):
        e = rules.extract_entities(
            "This is Inspector Vikram Rathore from the Enforcement Directorate."
        )
        assert "Vikram Rathore" in e.claimed_names
        assert "ENFORCEMENT DIRECTORATE" in e.claimed_departments

    def test_phone_not_double_counted_as_account(self):
        e = rules.extract_entities("My number is 9876543210")
        assert e.phone_numbers == ["9876543210"]
        assert e.bank_accounts == []

    def test_clean_text_yields_nothing(self):
        e = rules.extract_entities("Hello, how are you today? The weather is nice.")
        assert e.is_empty()
