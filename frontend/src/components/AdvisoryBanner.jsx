// The warning the person being targeted would actually see. This is the payload
// of the whole system — everything else is instrumentation.

const URGENCY_ICON = {
  critical: '🛑',
  warning: '⚠️',
  caution: '⚡',
  info: '✓',
  safe: '✓',
};

export default function AdvisoryBanner({ warning }) {
  if (!warning) return null;
  const level = warning.urgency || 'info';

  return (
    <div className={`banner ${level}`}>
      <div className="banner-head">
        <span>{URGENCY_ICON[level] || '•'}</span>
        <span>{warning.headline}</span>
      </div>
      <div className="banner-body">{warning.body}</div>

      {warning.immediate_actions?.length > 0 && (
        <div className="banner-actions">
          {warning.immediate_actions.map((a, i) => (
            <div key={i} className="banner-action">{a}</div>
          ))}
        </div>
      )}

      {warning.citations?.length > 0 && (
        <div className="banner-cite">
          Sources: {warning.citations.map((c) => c.advisory_id).join(', ')}
        </div>
      )}
    </div>
  );
}
