"""Advisory knowledge base for the RAG layer.

⚠️ IMPORTANT — READ BEFORE RELYING ON ANY OF THIS ⚠️

This content is **illustrative reference material written for a hackathon
prototype**. It is a good-faith summary of publicly reported guidance from Indian
authorities (MHA / I4C, RBI, TRAI, PIB Fact Check) and of statutory provisions,
but it is:

  - NOT retrieved from live official sources,
  - NOT verified legal advice,
  - NOT guaranteed current — law and advisories change.

Statutory references reflect the Bharatiya Nyaya Sanhita (BNS) 2023, which
replaced the Indian Penal Code with effect from 1 July 2024; a lot of secondary
material still cites the old IPC sections, so both are noted where useful.

Anything user-facing generated from this must be framed as general guidance, and
must always point to the official channels (1930 / cybercrime.gov.in) rather than
positioning itself as authoritative. A production deployment must replace this
file with documents ingested from official sources under review by a lawyer.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Advisory:
    id: str
    title: str
    source: str
    scam_types: tuple[str, ...]
    red_flag_categories: tuple[str, ...]
    text: str


ADVISORIES: list[Advisory] = [
    Advisory(
        id="ADV-DA-001",
        title="'Digital arrest' has no basis in Indian law",
        source="Illustrative summary of MHA / I4C and PIB Fact Check guidance",
        scam_types=("digital_arrest",),
        red_flag_categories=("threat_of_arrest", "authority_impersonation"),
        text=(
            "There is no procedure in Indian law called 'digital arrest', 'virtual "
            "arrest', or 'online custody'. No police officer, CBI officer, Enforcement "
            "Directorate officer, Customs officer, or judge can arrest, detain, or "
            "interrogate you over a phone call, a video call, WhatsApp, or Skype. "
            "An arrest is a physical act carried out by identifiable officers, in person, "
            "under a documented legal process. "
            "If someone on a video call tells you that you are under arrest and must stay "
            "on camera, that statement is definitionally false and the call is a scam. "
            "The correct response is to disconnect immediately. You do not need permission "
            "to hang up, and hanging up is not an offence or an admission of guilt."
        ),
    ),
    Advisory(
        id="ADV-DA-002",
        title="No agency asks you to transfer money to a 'safe' or 'verification' account",
        source="Illustrative summary of RBI and MHA / I4C guidance",
        scam_types=("digital_arrest", "kyc_fraud"),
        red_flag_categories=("fund_transfer_demand", "verification_pretext"),
        text=(
            "No Indian investigative agency, and not the Reserve Bank of India, will ever "
            "ask you to move money to a 'safe account', 'verification account', 'escrow "
            "account', 'RBI account', or 'nodal account' to prove that your funds are "
            "clean. No such account exists. The RBI does not hold accounts for individual "
            "citizens at all. "
            "Verification of funds is never done by asking a citizen to transfer them. "
            "Where money is genuinely subject to legal process, it is frozen or attached "
            "through the banking system under a written order — never by asking you to "
            "send it somewhere yourself. "
            "Any request to transfer money in order to prove innocence is, without "
            "exception, fraud. Once sent by UPI or IMPS, the money is effectively "
            "irrecoverable within minutes."
        ),
    ),
    Advisory(
        id="ADV-CRED-001",
        title="Never share OTP, PIN, CVV or passwords — no legitimate party asks",
        source="Illustrative summary of RBI customer-awareness guidance",
        scam_types=("kyc_fraud", "digital_arrest", "loan_fraud", "lottery_prize"),
        red_flag_categories=("credential_request",),
        text=(
            "No bank, wallet, government body, or police officer will ever ask you for a "
            "One Time Password (OTP), UPI PIN, ATM PIN, CVV, or net-banking password. "
            "Bank staff do not need these to help you, and asking for them is itself the "
            "clearest sign of fraud. "
            "Note an important distinction: a UPI PIN is required to SEND money, never to "
            "receive it. If someone asks you to enter your UPI PIN or scan a QR code in "
            "order to 'receive' a refund, prize, or cashback, they are taking money from "
            "you, not giving it. "
            "The one legitimate case where a stranger may ask for an OTP is a delivery "
            "agent confirming a parcel that you actually ordered — that OTP authorises a "
            "delivery, not a payment or an account change."
        ),
    ),
    Advisory(
        id="ADV-ISO-001",
        title="Isolation from family is the core of the digital arrest scam",
        source="Illustrative summary of MHA / I4C guidance",
        scam_types=("digital_arrest",),
        red_flag_categories=("isolation_tactic", "secrecy_demand"),
        text=(
            "The single most reliable indicator of a digital arrest scam is an instruction "
            "not to tell anyone. Callers demand that you stay on a video call for hours, "
            "forbid you from contacting family, and invoke the 'Official Secrets Act' or a "
            "'classified investigation' to justify the silence. "
            "This exists for one reason: the scam collapses the moment any other person "
            "hears it. Isolation is not a feature of a real investigation. No lawful "
            "process forbids you from speaking to your family or a lawyer — in fact the "
            "right to consult a lawyer is constitutionally protected under Article 22(1). "
            "If you are told to keep a call secret from your family, that instruction is "
            "the proof it is a scam. Tell someone immediately."
        ),
    ),
    Advisory(
        id="ADV-VERIFY-001",
        title="How to verify a caller claiming to be an official",
        source="Illustrative summary of MHA / I4C and TRAI guidance",
        scam_types=("digital_arrest", "kyc_fraud", "tech_support"),
        red_flag_categories=("authority_impersonation", "fake_case_reference"),
        text=(
            "Caller ID can be spoofed. A call that displays a police station's number, or "
            "a number starting +91-11, proves nothing. Uniforms, backdrops resembling a "
            "police station, ID cards shown on camera, badge numbers, and official-looking "
            "letterheads with a case number are all trivially faked and are routine in "
            "these scams. "
            "To verify: hang up completely, wait a minute so the line actually clears, then "
            "call the organisation yourself using a number you looked up independently — "
            "from the back of your card, an official website, or a printed bill. Never use "
            "a number the caller gives you, and never let them 'transfer' you. "
            "TRAI does not call subscribers about disconnection, and does not run a cyber "
            "crime department. Agencies do not announce FIRs by phone."
        ),
    ),
    Advisory(
        id="ADV-FEE-001",
        title="Advance-fee pattern: nobody pays to receive money",
        source="Illustrative summary of consumer-protection and RBI guidance",
        scam_types=("lottery_prize", "loan_fraud", "job_scam", "investment_fraud"),
        red_flag_categories=("advance_fee", "unrealistic_reward"),
        text=(
            "If you must pay in order to receive money, it is a scam. This covers prize or "
            "lottery 'GST clearance' and 'customs duty', loan 'processing fees', "
            "'insurance premiums' or 'security deposits' demanded before disbursal, and "
            "job 'registration' or 'training kit' fees. "
            "You cannot win a lottery you never entered. Tax on genuine winnings is deducted "
            "at source by the payer — it is never collected from the winner in advance, and "
            "never to a personal UPI ID. A genuine regulated lender deducts any processing "
            "fee from the disbursed amount; it does not ask you to pay up front. A genuine "
            "employer does not charge you to be hired. "
            "Each payment is typically followed by a demand for another, until the victim "
            "stops."
        ),
    ),
    Advisory(
        id="ADV-REMOTE-001",
        title="Remote access apps hand over your device and your bank account",
        source="Illustrative summary of RBI and MHA / I4C guidance",
        scam_types=("tech_support", "kyc_fraud", "digital_arrest"),
        red_flag_categories=("remote_access_request",),
        text=(
            "Never install AnyDesk, TeamViewer, QuickSupport, or any APK sent to you by a "
            "caller, and never share your screen with one. These give the caller full "
            "control of your phone: they can read the OTPs arriving on it, open your "
            "banking apps, and move money while you watch. "
            "No bank, no telecom operator, and no government body needs remote access to "
            "your device to resolve anything. A request to install such an app during a "
            "call about your account, KYC, a refund, or a 'case' is fraud."
        ),
    ),
    Advisory(
        id="ADV-REPORT-001",
        title="What to do if you have already paid",
        source="Illustrative summary of MHA / I4C and RBI guidance",
        scam_types=(
            "digital_arrest", "kyc_fraud", "lottery_prize", "loan_fraud",
            "job_scam", "investment_fraud", "tech_support", "other_scam",
        ),
        red_flag_categories=(),
        text=(
            "Act within the first hours — that window decides whether the money can be "
            "held. "
            "1. Call the National Cyber Crime Helpline on 1930 immediately. It operates a "
            "'golden hour' process that can freeze funds still sitting in the mule account. "
            "2. File at cybercrime.gov.in. "
            "3. Tell your bank at once and ask them to raise a dispute and freeze the "
            "beneficiary. "
            "4. Keep everything: call recordings, numbers, UPI IDs, account numbers, "
            "screenshots, transaction references. "
            "Under RBI's limited-liability framework, a customer's liability for an "
            "unauthorised electronic transaction can be reduced or eliminated where the "
            "customer reports promptly — delay increases what you bear. "
            "Being scammed is not a crime and not something to be ashamed of. These are "
            "professional, organised operations that defraud lawyers, doctors, and "
            "engineers daily. Shame is what keeps victims silent and keeps the operation "
            "running."
        ),
    ),
    Advisory(
        id="ADV-LAW-001",
        title="Statutory provisions typically invoked (illustrative)",
        source="Illustrative summary — BNS 2023 / IT Act 2000. NOT legal advice.",
        scam_types=(
            "digital_arrest", "kyc_fraud", "lottery_prize", "loan_fraud",
            "job_scam", "investment_fraud", "tech_support", "other_scam",
        ),
        red_flag_categories=(),
        text=(
            "Offences of this kind are commonly registered under the following provisions. "
            "This is general information for orientation, not legal advice, and the "
            "sections actually applied depend on the facts and on the investigating officer.\n\n"
            "Bharatiya Nyaya Sanhita, 2023 (in force from 1 July 2024, replacing the IPC):\n"
            "- Section 318 — Cheating (corresponds broadly to the former IPC 420).\n"
            "- Section 319 — Cheating by personation (corresponds broadly to former IPC 419). "
            "Impersonating a police or agency officer falls here.\n"
            "- Section 308 — Extortion. Threatening arrest to obtain money engages this.\n"
            "- Section 204 — Personating a public servant.\n"
            "- Section 61 — Criminal conspiracy, where an organised group is involved.\n\n"
            "Information Technology Act, 2000:\n"
            "- Section 66C — Identity theft (fraudulent use of another's identifiers).\n"
            "- Section 66D — Cheating by personation using a computer resource. This is the "
            "provision most directly aimed at scams run over calls and video calls.\n\n"
            "Where proceeds are laundered through mule accounts, the Prevention of Money "
            "Laundering Act, 2002 may also be invoked against the operators."
        ),
    ),
    Advisory(
        id="ADV-LEGIT-001",
        title="What a genuine bank or agency call looks like",
        source="Illustrative summary of RBI customer-awareness guidance",
        scam_types=("none",),
        red_flag_categories=(),
        text=(
            "Not every urgent call is a scam, and treating every caller as a fraudster has "
            "its own cost. Genuine calls do happen: a bank's fraud desk may call to ask "
            "whether you made a particular transaction; a courier may ask for a delivery "
            "OTP for a parcel you ordered; a lender may call about a genuinely overdue EMI; "
            "a recruiter may call about a role you applied for. "
            "What marks these out is what they never do. A genuine caller does not ask for "
            "your OTP, PIN, CVV or password. They do not ask you to transfer money to prove "
            "anything. They do not threaten you with arrest. They do not tell you to keep "
            "the call secret from your family. They do not object if you say you will hang "
            "up and call the official number back — a real one will encourage exactly that. "
            "If in doubt, end the call and dial the official number yourself. A legitimate "
            "matter will still be there in five minutes."
        ),
    ),
]


DISCLAIMER = (
    "General guidance from a prototype system — not legal advice. "
    "For help, call the National Cyber Crime Helpline 1930 or visit cybercrime.gov.in."
)


def get_advisory(advisory_id: str) -> Advisory | None:
    return next((a for a in ADVISORIES if a.id == advisory_id), None)
