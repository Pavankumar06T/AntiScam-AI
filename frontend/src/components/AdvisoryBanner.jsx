// The warning the person being targeted would actually see. This is the payload
// of the whole system — everything else is instrumentation. Styled as a real
// intervention alert: a decisive headline, plain-language body, numbered actions,
// and the advisory it is grounded in.

const URGENCY_ICON = {
  critical: '🛑',
  warning: '⚠️',
  caution: '⚡',
  info: '✓',
  safe: '✓',
};

const LANG_LABEL = { en: 'EN', hi: 'हिन्दी', ta: 'தமிழ்' };

export default function AdvisoryBanner({ warning }) {
  if (!warning) return null;
  const level = warning.urgency || 'info';

  return (
    <div className={`banner ${level}`}>
      <div className="banner-lang">{LANG_LABEL[warning.language] || warning.language}</div>

      <div className="banner-head">
        <span className="ba-icon">{URGENCY_ICON[level] || '•'}</span>
        <span>{warning.headline}</span>
      </div>

      <div className="banner-body">{warning.body}</div>

      {warning.immediate_actions?.length > 0 && (
        <div className="banner-actions">
          {warning.immediate_actions.map((a, i) => (
            <div key={i} className="banner-action">
              <span className="num"><b>{i + 1}</b></span>
              <span className="atext">{a}</span>
            </div>
          ))}
        </div>
      )}

      {warning.citations?.length > 0 && (
        <div className="banner-cite">
          <span>Grounded in:</span>
          {warning.citations.map((c) => (
            <span key={c.advisory_id} className="chip" title={c.title}>{c.advisory_id}</span>
          ))}
        </div>
      )}
    </div>
  );
}
