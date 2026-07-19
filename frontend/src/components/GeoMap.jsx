import { useState, useEffect, useCallback, useMemo } from 'react';
import { api } from '../api';
import { riskColor, scamTypeLabel } from '../lib/risk';

// Geographic command-centre map.
//
// Plots victim sessions on a map of India and draws arcs between co-victims, so a
// single operation spanning multiple cities (the digital-arrest cluster runs across
// Mumbai, Delhi and Bengaluru) reads as one cross-jurisdiction campaign — the
// geospatial crime-pattern intelligence the problem statement asks for.
//
// The India outline and the markers share one equirectangular projection, so every
// city sits in its true relative position. Self-contained (inline SVG, no map tiles,
// no network) — it works offline and matches the console aesthetic.

const W = 520;
const H = 580;
const LON0 = 67, LON1 = 99, LAT0 = 5.5, LAT1 = 37.8;
const px = (lon) => ((lon - LON0) / (LON1 - LON0)) * W;
const py = (lat) => ((LAT1 - lat) / (LAT1 - LAT0)) * H;

// Simplified India boundary (lat, lon), clockwise from north Kashmir. Projected
// with the same transform as the markers, so the two always align.
const INDIA = [
  [34.5, 74.4], [32.8, 74.3], [30.4, 74.5], [28.0, 70.0], [24.3, 68.8],
  [22.3, 69.1], [20.7, 70.9], [19.0, 72.8], [15.3, 73.9], [12.9, 74.8],
  [10.0, 76.2], [8.1, 77.5], [9.3, 79.3], [11.2, 79.8], [13.1, 80.3],
  [15.9, 80.5], [17.7, 83.3], [19.3, 84.8], [20.3, 86.7], [21.6, 87.9],
  [22.3, 88.4], [24.5, 88.1], [25.2, 89.8], [26.6, 89.9], [25.9, 92.5],
  [24.0, 92.6], [25.5, 94.5], [27.0, 95.3], [28.1, 96.6], [27.9, 92.5],
  [27.6, 88.8], [28.6, 84.0], [30.0, 81.0], [30.3, 79.0], [32.5, 78.5],
  [34.0, 78.2], [35.3, 76.8], [34.7, 74.4],
];

const INDIA_PATH =
  INDIA.map(([lat, lon], i) => `${i === 0 ? 'M' : 'L'}${px(lon).toFixed(1)},${py(lat).toFixed(1)}`).join(' ') + ' Z';

function arcPath(a, b) {
  const x1 = px(a.lon), y1 = py(a.lat), x2 = px(b.lon), y2 = py(b.lat);
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
  const dx = x2 - x1, dy = y2 - y1;
  const len = Math.hypot(dx, dy) || 1;
  // Bow the arc perpendicular to the chord.
  const off = Math.min(60, len * 0.28);
  const cx = mx - (dy / len) * off, cy = my + (dx / len) * off;
  return `M${x1},${y1} Q${cx},${cy} ${x2},${y2}`;
}

export default function GeoMap({ refreshKey }) {
  const [data, setData] = useState({ points: [], links: [], cities: 0, clusters: 0 });
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const g = await api.graphGeo();
      setData(g);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load, refreshKey]);

  const bySession = useMemo(() => {
    const m = {};
    data.points.forEach((p) => { m[p.session_id] = p; });
    return m;
  }, [data.points]);

  // The cluster spanning the most cities — the cross-jurisdiction headline.
  const spread = useMemo(() => {
    const byCluster = {};
    data.points.forEach((p) => {
      if (!p.cluster_id) return;
      (byCluster[p.cluster_id] ||= new Set()).add(p.city);
    });
    let best = null;
    for (const [cid, cities] of Object.entries(byCluster)) {
      if (!best || cities.size > best.cities.length) best = { cid, cities: [...cities] };
    }
    return best;
  }, [data.points]);

  const linkedCities = useMemo(() => {
    if (!selected) return [];
    const out = new Set();
    data.links.forEach((l) => {
      if (l.from_session === selected.session_id) out.add(bySession[l.to_session]?.city);
      if (l.to_session === selected.session_id) out.add(bySession[l.from_session]?.city);
    });
    return [...out].filter(Boolean);
  }, [selected, data.links, bySession]);

  if (loading) return <div className="loading"><div className="spinner" /></div>;

  return (
    <div className="network">
      <div className="graph-canvas geo-canvas">
        <div className="graph-overlay-title">
          <h2>Geographic Threat Map</h2>
          <p>Victims plotted by city. Arcs are cross-victim links — one operation working multiple jurisdictions.</p>
        </div>

        <svg viewBox={`0 0 ${W} ${H}`} className="geo-svg" preserveAspectRatio="xMidYMid meet">
          <defs>
            <filter id="geoGlow" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="3" result="b" />
              <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <radialGradient id="landGrad" cx="50%" cy="40%">
              <stop offset="0%" stopColor="#141c30" />
              <stop offset="100%" stopColor="#0d1322" />
            </radialGradient>
          </defs>

          {/* Landmass */}
          <path d={INDIA_PATH} fill="url(#landGrad)" stroke="#2c3958" strokeWidth="1.5"
            strokeLinejoin="round" style={{ filter: 'drop-shadow(0 0 12px rgba(59,130,246,0.15))' }} />

          {/* Cross-victim arcs */}
          {data.links.map((l, i) => {
            const a = bySession[l.from_session], b = bySession[l.to_session];
            if (!a || !b) return null;
            const hot = a.scam_probability >= 75 || b.scam_probability >= 75;
            return (
              <path key={i} d={arcPath(a, b)} fill="none"
                stroke={hot ? 'rgba(239,68,68,0.7)' : 'rgba(249,115,22,0.6)'}
                strokeWidth="1.6" strokeDasharray="4 4" className="geo-arc" />
            );
          })}

          {/* City markers. Labels drop below when a nearby marker sits to the
              left, so horizontally-close cities (Bengaluru/Chennai) don't collide. */}
          {data.points.map((p) => {
            const x = px(p.lon), y = py(p.lat);
            const color = riskColor(p.scam_probability);
            const r = 4 + Math.min(6, p.scam_probability / 14);
            const isSel = selected?.session_id === p.session_id;
            const below = data.points.some(
              (o) => o.session_id !== p.session_id &&
                Math.abs(px(o.lon) - x) < 60 && Math.abs(py(o.lat) - y) < 24 && px(o.lon) < x
            );
            const ly = below ? y + r + 16 : y - r - 7;
            return (
              <g key={p.session_id} className="geo-marker" onClick={() => setSelected(p)} style={{ cursor: 'pointer' }}>
                <circle cx={x} cy={y} r={r + 6} fill={color} opacity="0.12" className={p.scam_probability >= 75 ? 'geo-pulse' : ''} />
                <circle cx={x} cy={y} r={r} fill={color} filter="url(#geoGlow)"
                  stroke={isSel ? '#fff' : 'rgba(255,255,255,0.55)'} strokeWidth={isSel ? 2 : 1} />
                <text x={x} y={ly} textAnchor="middle" className="geo-city-label">{p.city}</text>
              </g>
            );
          })}
        </svg>

        <div className="graph-legend geo-legend">
          <div className="lt">Risk level</div>
          <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--risk-critical)' }} /> Critical (75+)</div>
          <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--risk-warn)' }} /> High (50–74)</div>
          <div className="legend-row"><span className="legend-dot" style={{ background: 'var(--risk-caution)' }} /> Suspicious</div>
          <div className="legend-row" style={{ marginTop: 6 }}><span style={{ width: 18, height: 0, borderTop: '2px dashed rgba(239,68,68,0.7)' }} /> Cross-victim link</div>
        </div>
      </div>

      <div className="graph-side">
        <div className="section-title">Geographic Intelligence</div>
        <div className="tiles">
          <div className="tile"><div className="tile-val">{data.cities}</div><div className="tile-lbl">Cities hit</div></div>
          <div className="tile alarm"><div className="tile-val">{data.clusters}</div><div className="tile-lbl">Operations</div></div>
          <div className="tile"><div className="tile-val">{data.points.length}</div><div className="tile-lbl">Victims</div></div>
          <div className="tile"><div className="tile-val">{data.links.length}</div><div className="tile-lbl">Cross-city links</div></div>
        </div>

        {spread && spread.cities.length > 1 && (
          <div className="geo-headline">
            <div className="geo-headline-title">⚠ Cross-jurisdiction operation</div>
            <div className="geo-headline-body">
              <strong>{spread.cid.replace('CLUSTER-', 'Cluster #')}</strong> is working{' '}
              <strong>{spread.cities.length} cities</strong> with the same identifiers:{' '}
              {spread.cities.join(', ')}. A single coordinated campaign, not isolated local incidents —
              actionable for inter-district intelligence sharing.
            </div>
          </div>
        )}

        <div className="divider" />

        {selected ? (
          <div className="node-detail">
            <div className="nd-type" style={{ color: riskColor(selected.scam_probability) }}>
              <span className="nd-dot" style={{ background: riskColor(selected.scam_probability) }} />
              {selected.city}
            </div>
            <h4>{selected.session_id}</h4>
            <div className="nd-list">
              <div className="nd-list-item">Scam type · {scamTypeLabel(selected.scam_type)}</div>
              <div className="nd-list-item">Risk · {selected.scam_probability}/100</div>
              <div className="nd-list-item">Operation · {selected.cluster_id}</div>
            </div>
            {linkedCities.length > 0 && (
              <div className="nd-shared">
                🔗 Same operation as victims in {linkedCities.join(', ')} — linked by shared identifiers.
              </div>
            )}
          </div>
        ) : (
          <p className="subtle">
            Click a city to inspect the victim there. Cities joined by a dashed arc were
            hit by the same operation — the fingerprint of an organised, cross-jurisdiction
            campaign.
          </p>
        )}
      </div>

      {error && <div className="err-toast" onClick={() => setError(null)}>Backend error: {error}</div>}
    </div>
  );
}
