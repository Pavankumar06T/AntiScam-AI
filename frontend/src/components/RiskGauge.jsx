import { LineChart, Line, XAxis, YAxis, ReferenceLine, ResponsiveContainer, Tooltip } from 'recharts';
import { riskColor, riskLabel, WARN_THRESHOLD, URGENT_THRESHOLD } from '../lib/risk';

// Live risk gauge: a big number, a coloured bar, and a timeline of how the score
// evolved turn by turn. The timeline is what makes "the risk climbed as the call
// progressed" legible — the core visual claim of the live monitor.
export default function RiskGauge({ score, history, degraded }) {
  const color = riskColor(score);

  return (
    <div>
      <div className="gauge-wrap">
        <div className="gauge-score" style={{ color }}>
          {score}
          <span style={{ fontSize: 20, color: 'var(--text-faint)' }}>/100</span>
        </div>
        <div className="gauge-label" style={{ color }}>{riskLabel(score)}</div>
        {degraded && (
          <div className="subtle" style={{ marginTop: 6 }} title="LLM unavailable — scored by the deterministic rule layer only.">
            ⚠ rule-only (LLM unavailable)
          </div>
        )}
        <div className="gauge-bar">
          <div className="gauge-fill" style={{ width: `${score}%`, background: color }} />
        </div>
      </div>

      {history.length > 1 && (
        <div style={{ height: 130, marginBottom: 8 }}>
          <div className="section-title">Risk timeline</div>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history} margin={{ top: 8, right: 8, bottom: 0, left: -20 }}>
              <XAxis dataKey="turn" tick={{ fill: 'var(--text-faint)', fontSize: 10 }} stroke="var(--border)" />
              <YAxis domain={[0, 100]} tick={{ fill: 'var(--text-faint)', fontSize: 10 }} stroke="var(--border)" />
              <Tooltip
                contentStyle={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
                labelStyle={{ color: 'var(--text-dim)' }}
              />
              <ReferenceLine y={WARN_THRESHOLD} stroke="var(--risk-warn)" strokeDasharray="3 3" />
              <ReferenceLine y={URGENT_THRESHOLD} stroke="var(--risk-critical)" strokeDasharray="3 3" />
              <Line
                type="monotone" dataKey="score" stroke={color} strokeWidth={2}
                dot={{ r: 3, fill: color }} isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
