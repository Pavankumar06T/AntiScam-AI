import { LineChart, Line, XAxis, YAxis, ReferenceLine, ResponsiveContainer, Tooltip } from 'recharts';
import { riskLabel, riskLevel, WARN_THRESHOLD, URGENT_THRESHOLD } from '../lib/risk';
import { useCountUp } from '../lib/hooks';

// Radial risk gauge with an animated count-up, plus a turn-by-turn timeline.
//
// The gauge is a 270° SVG arc so it reads as an instrument, not a progress bar.
// The timeline is what makes "the risk climbed as the call progressed" legible —
// the core visual claim of the live monitor — with the interception threshold
// marked so you can *see* the warning fire before the extraction turn.

const RADIUS = 78;
const STROKE = 13;
const SWEEP = 270; // degrees
const CIRC = 2 * Math.PI * RADIUS;
const ARC_LEN = (SWEEP / 360) * CIRC;

// Resolve a CSS var to its hex so SVG stroke + Recharts can use a concrete colour.
const RISK_HEX = {
  critical: '#ef4444',
  warning: '#f97316',
  caution: '#eab308',
  low: '#84cc16',
  safe: '#22c55e',
};

export default function RiskGauge({ score, history, degraded }) {
  const animated = useCountUp(score, 700);
  const level = riskLevel(score);
  const hex = RISK_HEX[level];
  const frac = Math.max(0, Math.min(1, animated / 100));

  // Rotate so the 270° arc opens at the bottom (gap centered at bottom).
  const startAngle = 135;
  const dash = ARC_LEN * frac;

  return (
    <div>
      <div className="gauge">
        <div className="gauge-svg-wrap">
          <svg width="190" height="190" viewBox="0 0 190 190">
            <defs>
              <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor={hex} stopOpacity="0.6" />
                <stop offset="100%" stopColor={hex} />
              </linearGradient>
              <filter id="gaugeGlow">
                <feGaussianBlur stdDeviation="3.5" result="b" />
                <feMerge>
                  <feMergeNode in="b" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Track */}
            <circle
              cx="95" cy="95" r={RADIUS} fill="none"
              stroke="var(--panel-2)" strokeWidth={STROKE} strokeLinecap="round"
              strokeDasharray={`${ARC_LEN} ${CIRC}`}
              transform={`rotate(${startAngle} 95 95)`}
            />
            {/* Threshold ticks on the track */}
            {[WARN_THRESHOLD, URGENT_THRESHOLD].map((t) => {
              const a = (startAngle + (t / 100) * SWEEP) * (Math.PI / 180);
              const x1 = 95 + (RADIUS - STROKE / 2 - 1) * Math.cos(a);
              const y1 = 95 + (RADIUS - STROKE / 2 - 1) * Math.sin(a);
              const x2 = 95 + (RADIUS + STROKE / 2 + 1) * Math.cos(a);
              const y2 = 95 + (RADIUS + STROKE / 2 + 1) * Math.sin(a);
              return <line key={t} x1={x1} y1={y1} x2={x2} y2={y2} stroke="var(--text-ghost)" strokeWidth="2" />;
            })}
            {/* Value arc */}
            <circle
              cx="95" cy="95" r={RADIUS} fill="none"
              stroke="url(#gaugeGrad)" strokeWidth={STROKE} strokeLinecap="round"
              strokeDasharray={`${dash} ${CIRC}`}
              transform={`rotate(${startAngle} 95 95)`}
              filter={level === 'critical' || level === 'warning' ? 'url(#gaugeGlow)' : undefined}
              style={{ transition: 'stroke 0.4s' }}
            />
          </svg>

          <div className="gauge-center">
            <div className="gauge-num" style={{ color: hex }}>
              {Math.round(animated)}<span className="gauge-max">/100</span>
            </div>
          </div>
        </div>

        <div className="gauge-label" style={{ color: hex }}>
          <span>{riskLabel(score)}</span>
        </div>

        {degraded && (
          <div className="gauge-degraded" title="LLM unavailable — scored by the deterministic rule layer only. The score is a floor, not a considered judgement.">
            ⚠ rule-only mode (LLM offline)
          </div>
        )}
      </div>

      {history.length > 1 && (
        <div style={{ marginTop: 6 }}>
          <div className="section-title">Risk Timeline · turn by turn</div>
          <div style={{ height: 128 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history} margin={{ top: 8, right: 10, bottom: 0, left: -22 }}>
                <XAxis dataKey="turn" tick={{ fill: 'var(--text-faint)', fontSize: 10 }} stroke="var(--border)" tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: 'var(--text-faint)', fontSize: 10 }} stroke="var(--border)" tickLine={false} />
                <Tooltip
                  contentStyle={{ background: 'var(--elevated)', border: '1px solid var(--border-bright)', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: 'var(--text-dim)' }}
                  labelFormatter={(t) => `Turn ${t}`}
                  formatter={(v) => [`${v}/100`, 'Risk']}
                />
                <ReferenceLine y={WARN_THRESHOLD} stroke="var(--risk-warn)" strokeDasharray="4 4" strokeOpacity={0.6} />
                <ReferenceLine y={URGENT_THRESHOLD} stroke="var(--risk-critical)" strokeDasharray="4 4" strokeOpacity={0.6} />
                <Line
                  type="monotone" dataKey="score" stroke={hex} strokeWidth={2.5}
                  dot={{ r: 3, fill: hex, strokeWidth: 0 }}
                  activeDot={{ r: 5, fill: hex }}
                  isAnimationActive
                  animationDuration={400}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  );
}
