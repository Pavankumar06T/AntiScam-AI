import { ESCALATION_STAGES, stageIndex } from '../lib/risk';

// The Coercion Kill-Chain.
//
// This is the view no single-conversation scam detector offers: WHERE on the
// manipulation script a live call currently sits. Digital-arrest scams follow a
// fixed playbook — establish a pretext, assert authority, induce fear, isolate the
// victim, then extract money. Naming the stage is what lets us warn *before* the
// extraction step instead of after, and it turns an opaque risk number into a
// story a person (or a judge) can read at a glance.

export default function EscalationTracker({ stage }) {
  const current = stageIndex(stage); // -1 = no contact risk yet
  const reachedFrac = current < 0 ? 0 : (current + 0.5) / ESCALATION_STAGES.length;

  const currentStage = current >= 0 ? ESCALATION_STAGES[current] : null;
  const atExtraction = stage === 'extraction_attempted';

  return (
    <div className="killchain">
      <div className="kc-track">
        <div className="kc-line" />
        <div className="kc-line-fill" style={{ width: `${reachedFrac * 88}%` }} />
        {ESCALATION_STAGES.map((s, i) => {
          const state = i < current ? 'reached' : i === current ? 'current reached' : '';
          return (
            <div key={s.key} className={`kc-stage ${state}`} title={s.desc}>
              <div className="kc-node">{s.icon}</div>
              <div className="kc-lbl">{s.short}</div>
            </div>
          );
        })}
      </div>

      <div className="kc-caption">
        {current < 0 ? (
          <span>No coercion pattern established yet.</span>
        ) : atExtraction ? (
          <span>
            ⛔ Attack at <b>extraction</b> — this is the moment money would be lost.
          </span>
        ) : (
          <span>
            Attack has reached <b style={{ color: 'var(--risk-warn)' }}>{currentStage.short}</b>.
            {current < ESCALATION_STAGES.length - 1 && ' Extraction is the next escalation.'}
          </span>
        )}
      </div>
    </div>
  );
}
