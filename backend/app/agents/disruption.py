"""Disruption package builder — the 'disrupt' step of detect / disrupt / respond.

Detection warns the victim. This turns a flagged session into a dispatch-ready
containment packet: freeze the mule account, block the caller's number, take down
the phishing URL. When an identifier is shared across a cluster, actioning it
protects every linked victim at once — which is the shift from reactive
case-investigation to proactive threat neutralisation the problem statement asks for.

Assembled deterministically from identifiers we already captured (never generated
by an LLM), so every line is traceable to the transcript — the auditability a
legally-admissible intelligence package needs.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.graph_schemas import DisruptionAction, DisruptionPackage, GraphMatch
from app.models.schemas import ClassifyResponse

# Which recipient actions which identifier type.
_BANK = "Beneficiary bank fraud desk / NPCI"
_TELECOM = "Telecom operator / DoT (Sanchar Saathi)"
_CERT = "CERT-In / hosting provider"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _package_id(session_id: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = "".join(c for c in session_id if c.isalnum())[-5:].upper() or "00000"
    return f"DISRUPT-{stamp}-{suffix}"


def build_disruption_package(
    session_id: str,
    detection: ClassifyResponse,
    match: GraphMatch | None,
    *,
    warn_threshold: int,
    urgent_threshold: int,
) -> DisruptionPackage | None:
    """Build a containment packet, or None if there's nothing actionable.

    Emitted for any warning-level-or-higher session that exposed a financial rail,
    a caller number, or a phishing URL — the identifiers a bank/telecom/CERT can act
    on. Repeat-scammer sessions carry the cluster reference so the freeze is framed
    as protecting all linked victims.
    """
    if detection.scam_probability < warn_threshold:
        return None

    e = detection.extracted_entities
    # How many sessions each shared identifier appears in, for the rationale.
    shared_counts = {
        link.value.strip().lower(): len(link.shared_with_sessions) + 1
        for link in (match.shared_entities if match else [])
    }

    def seen(value: str) -> int:
        return shared_counts.get(value.strip().lower(), 1)

    actions: list[DisruptionAction] = []

    for acc in e.bank_accounts:
        n = seen(acc)
        actions.append(DisruptionAction(
            action="freeze", target_type="bank_account", value=acc, recipient=_BANK,
            seen_in_sessions=n,
            rationale=(
                f"Mule account used to receive fraud proceeds"
                + (f"; recorded across {n} victim sessions — freezing halts the operation network-wide."
                   if n > 1 else "; freeze before funds are layered onward.")
            ),
        ))
    for upi in e.upi_ids:
        n = seen(upi)
        actions.append(DisruptionAction(
            action="freeze", target_type="upi", value=upi, recipient=_BANK,
            seen_in_sessions=n,
            rationale=(
                "Collection UPI handle for fraud proceeds"
                + (f"; shared across {n} victims." if n > 1 else "; block the VPA at NPCI.")
            ),
        ))
    for ph in e.phone_numbers:
        n = seen(ph)
        actions.append(DisruptionAction(
            action="block", target_type="phone", value=ph, recipient=_TELECOM,
            seen_in_sessions=n,
            rationale=(
                "Caller number used for the scam"
                + (f"; reused against {n} victims — disconnect and flag on Sanchar Saathi."
                   if n > 1 else "; disconnect and flag on Sanchar Saathi.")
            ),
        ))
    for url in e.urls:
        actions.append(DisruptionAction(
            action="takedown", target_type="url", value=url, recipient=_CERT,
            rationale="Fake government / verification portal used to harvest data or payments.",
        ))

    if not actions:
        return None

    is_repeat = bool(match and match.is_repeat_scammer)
    urgency = "immediate" if detection.scam_probability >= urgent_threshold else "priority"
    recipients = sorted({a.recipient for a in actions})

    if is_repeat:
        note = (
            f"This caller is linked to {match.total_victims_in_cluster} victims "
            f"(cluster {match.cluster_id}). Actioning the shared identifiers below "
            f"disrupts the operation for every linked victim, not just this one. "
            f"Dispatch immediately — mule funds move within minutes."
        )
    else:
        note = (
            "First recorded sighting of these identifiers. Freeze/block now to contain "
            "the operation before it scales to more victims. Dispatch immediately — "
            "mule funds move within minutes."
        )

    return DisruptionPackage(
        package_id=_package_id(session_id),
        generated_at=_now(),
        urgency=urgency,
        cluster_id=match.cluster_id if is_repeat else None,
        linked_victims=match.total_victims_in_cluster if is_repeat else 0,
        actions=actions,
        recipients=recipients,
        note=note,
    )
