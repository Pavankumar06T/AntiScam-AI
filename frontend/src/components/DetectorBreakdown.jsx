// Detector fusion breakdown — makes the two-layer design visible and honest.
//
// The score is not a black box: it is a deterministic rule layer fused with the
// Groq LLM. Showing both inputs and the fused result is the explainability a
// public-safety tool needs — "the model said 82" is not auditable; "rules fired
// these signals, the AI agreed, here is the blend" is. It also makes the graceful
// degradation legible: when the AI is offline the AI bar reads "offline" and the
// score stands on the rule layer alone.

export default function DetectorBreakdown({ breakdown }) {
  if (!breakdown) return null;
  const { rule_score, llm_score, fused_score, llm_available, signals_fired, rule_weight } = breakdown;

  return (
    <div className="fusion">
      <div className="fusion-row">
        <div className="fusion-k" title="Deterministic tripwires — regex patterns for known coercion moves.">
          Rules
        </div>
        <div className="fusion-track">
          <div className="fusion-bar rules" style={{ width: `${rule_score}%` }} />
        </div>
        <div className="fusion-v">{rule_score}</div>
      </div>

      <div className="fusion-row">
        <div className="fusion-k" title="Groq LLM judgement (llama-3.3-70b).">AI</div>
        <div className="fusion-track">
          <div
            className="fusion-bar ai"
            style={{ width: `${llm_available && llm_score != null ? llm_score : 0}%` }}
          />
        </div>
        <div className="fusion-v" style={{ color: llm_available ? undefined : 'var(--risk-caution)' }}>
          {llm_available && llm_score != null ? llm_score : 'off'}
        </div>
      </div>

      <div className="fusion-row">
        <div className="fusion-k" style={{ color: 'var(--text)' }}>Fused</div>
        <div className="fusion-track">
          <div className="fusion-bar fused" style={{ width: `${fused_score}%` }} />
        </div>
        <div className="fusion-v" style={{ color: 'var(--accent-bright)' }}>{fused_score}</div>
      </div>

      <div className="fusion-note">
        {signals_fired} rule signal{signals_fired === 1 ? '' : 's'} fired ·{' '}
        {llm_available
          ? `blended ${Math.round((1 - rule_weight) * 100)}% AI / ${Math.round(rule_weight * 100)}% rules`
          : 'AI offline — score held on the rule layer as a floor'}
      </div>
    </div>
  );
}
