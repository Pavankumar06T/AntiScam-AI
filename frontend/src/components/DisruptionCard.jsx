// Disruption Package — the "disrupt" step, dispatch-ready.
//
// Detection protects the person on this call; this card proposes cutting the
// operation off at the infrastructure (freeze the account, block the number),
// which — when an identifier is shared across a cluster — protects every linked
// victim at once. It is the reactive→proactive shift the problem statement asks for.

const ACTION_META = {
  freeze: { icon: '🧊', label: 'FREEZE' },
  block: { icon: '🚫', label: 'BLOCK' },
  takedown: { icon: '🌐', label: 'TAKEDOWN' },
};

const TARGET_LABEL = {
  bank_account: 'Bank account',
  upi: 'UPI ID',
  phone: 'Phone number',
  url: 'Website',
};

function toText(dp) {
  const lines = [
    `DISRUPTION PACKAGE — ${dp.package_id}`,
    `Urgency: ${dp.urgency.toUpperCase()}  |  Generated: ${dp.generated_at}`,
    dp.cluster_id ? `Fraud cluster: ${dp.cluster_id} (${dp.linked_victims} linked victims)` : '',
    '',
    'RECOMMENDED CONTAINMENT ACTIONS:',
    ...dp.actions.map(
      (a, i) => `  ${i + 1}. ${a.action.toUpperCase()} ${TARGET_LABEL[a.target_type] || a.target_type}: ${a.value}\n     → ${a.recipient}\n     ${a.rationale}`
    ),
    '',
    `Dispatch to: ${dp.recipients.join('; ')}`,
    '',
    dp.note,
  ];
  return lines.filter((l) => l !== undefined).join('\n');
}

export default function DisruptionCard({ disruption }) {
  if (!disruption) return null;
  const dp = disruption;

  return (
    <div className={`disrupt-card ${dp.urgency}`}>
      <div className="disrupt-head">
        <span className="disrupt-title">🚨 Disruption Package</span>
        <span className={`disrupt-urgency ${dp.urgency}`}>{dp.urgency}</span>
      </div>

      <div className="disrupt-sub">
        <span className="mono">{dp.package_id}</span>
        {dp.cluster_id && <span> · protects {dp.linked_victims} linked victims</span>}
      </div>

      <div className="disrupt-actions">
        {dp.actions.map((a, i) => {
          const m = ACTION_META[a.action] || { icon: '•', label: a.action };
          return (
            <div key={i} className="disrupt-action">
              <span className="da-badge">{m.icon} {m.label}</span>
              <div className="da-body">
                <div className="da-target">
                  <span className="da-type">{TARGET_LABEL[a.target_type] || a.target_type}</span>
                  <span className="da-value mono">{a.value}</span>
                  {a.seen_in_sessions > 1 && <span className="da-shared">×{a.seen_in_sessions} victims</span>}
                </div>
                <div className="da-recipient">→ {a.recipient}</div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="disrupt-note">{dp.note}</div>

      <button className="btn btn-ghost" style={{ width: '100%', marginTop: 10 }} onClick={() => navigator.clipboard?.writeText(toText(dp))}>
        ⧉ Copy dispatch packet
      </button>
    </div>
  );
}
