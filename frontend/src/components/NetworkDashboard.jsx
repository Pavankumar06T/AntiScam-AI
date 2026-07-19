import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { api } from '../api';
import { nodeColor, NODE_TYPE_LABELS, LINKABLE_TYPES, scamTypeLabel } from '../lib/risk';

// Fraud Network Dashboard.
//
// Renders the backend fraud graph. Session nodes (victims) are the hubs; identifier
// nodes hang off them. An identifier shared between two sessions is a cross-victim
// link — the signal that this is one operation working many people. Shared
// identifiers glow and carry flowing particles so the cross-victim links read at a
// glance; that connection is the entire differentiator of the project.

export default function NetworkDashboard({ refreshKey }) {
  const [data, setData] = useState({ nodes: [], edges: [] });
  const [stats, setStats] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dims, setDims] = useState({ w: 800, h: 600 });
  const wrapRef = useRef(null);
  const fgRef = useRef(null);

  const load = useCallback(async () => {
    try {
      const [view, s] = await Promise.all([api.graphEntities(), api.graphStats()]);
      setData({ nodes: view.nodes, edges: view.edges });
      setStats(s);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load, refreshKey]);

  // Spread the layout so distinct operations read as distinct clusters rather than
  // one central blob. Stronger repulsion + longer links = more separation.
  useEffect(() => {
    const fg = fgRef.current;
    if (!fg || data.nodes.length === 0) return;
    fg.d3Force('charge')?.strength(-180);
    fg.d3Force('link')?.distance(50);
    fg.d3ReheatSimulation?.();
  }, [data]);

  useEffect(() => {
    const measure = () => {
      if (wrapRef.current) setDims({ w: wrapRef.current.clientWidth, h: wrapRef.current.clientHeight });
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [loading]);

  // react-force-graph mutates the objects it's given; hand it fresh copies.
  const graphData = useMemo(
    () => ({
      nodes: data.nodes.map((n) => ({ ...n })),
      links: data.edges.map((e) => ({ ...e })),
    }),
    [data]
  );

  const reseed = useCallback(async () => {
    setLoading(true);
    setSelected(null);
    try {
      await api.reseedGraph();
      await load();
    } catch (e) {
      setError(e.message);
    }
  }, [load]);

  const linkedSessions = useMemo(() => {
    if (!selected || selected.type === 'session') return [];
    return graphData.links
      .filter((l) => (l.source.id || l.source) === selected.id || (l.target.id || l.target) === selected.id)
      .map((l) => {
        const other = (l.source.id || l.source) === selected.id ? l.target : l.source;
        return (other.id || other);
      });
  }, [selected, graphData]);

  // A link is a cross-victim link if either endpoint is a shared identifier.
  const isCrossLink = useCallback((link) => {
    const s = typeof link.source === 'object' ? link.source : null;
    const t = typeof link.target === 'object' ? link.target : null;
    const shared = (n) => n && n.type !== 'session' && (n.session_count || 0) > 1;
    return shared(s) || shared(t);
  }, []);

  if (loading) {
    return <div className="loading"><div className="spinner" /></div>;
  }

  return (
    <div className="network">
      <div className="graph-canvas" ref={wrapRef}>
        <div className="graph-overlay-title">
          <h2>Fraud Network Intelligence</h2>
          <p>Nodes shared between victim sessions are cross-victim links — the fingerprint of one organised operation.</p>
        </div>

        {graphData.nodes.length > 0 ? (
          <ForceGraph2D
            ref={fgRef}
            width={dims.w}
            height={dims.h}
            graphData={graphData}
            backgroundColor="rgba(0,0,0,0)"
            nodeRelSize={5}
            cooldownTicks={120}
            linkColor={(l) => (isCrossLink(l) ? 'rgba(239, 68, 68, 0.45)' : 'rgba(120, 135, 165, 0.22)')}
            linkWidth={(l) => (isCrossLink(l) ? 2 : 1)}
            linkDirectionalParticles={(l) => (isCrossLink(l) ? 3 : 0)}
            linkDirectionalParticleWidth={2.2}
            linkDirectionalParticleColor={() => 'rgba(252, 165, 165, 0.9)'}
            onNodeClick={(n) => setSelected(n)}
            onBackgroundClick={() => setSelected(null)}
            nodeCanvasObject={(node, ctx, scale) => {
              const isSession = node.type === 'session';
              const shared = !isSession && (node.session_count || 0) > 1;
              const isSel = selected?.id === node.id;
              const r = isSession ? 8 : shared ? 5 + Math.min(node.session_count, 4) : 4;
              const color = nodeColor(node.type);

              // Glow: sessions and shared identifiers stand out.
              if (isSession || shared || isSel) {
                ctx.shadowColor = shared ? '#ef4444' : color;
                ctx.shadowBlur = (shared ? 16 : 10) / Math.max(scale, 0.6);
              }
              ctx.beginPath();
              ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
              ctx.fillStyle = color;
              ctx.fill();
              ctx.shadowBlur = 0;

              // Session hubs get a ring; shared identifiers get a danger ring.
              if (isSession) {
                ctx.strokeStyle = 'rgba(255,255,255,0.35)';
                ctx.lineWidth = 1.5 / scale;
                ctx.stroke();
              } else if (shared) {
                ctx.strokeStyle = 'rgba(239, 68, 68, 0.9)';
                ctx.lineWidth = 2 / scale;
                ctx.stroke();
              }
              if (isSel) {
                ctx.beginPath();
                ctx.arc(node.x, node.y, r + 3 / scale, 0, 2 * Math.PI);
                ctx.strokeStyle = '#fff';
                ctx.lineWidth = 1.5 / scale;
                ctx.stroke();
              }

              // Label sessions and shared/zoomed identifiers.
              if (scale > 1.6 || isSession || shared) {
                const label = node.label.length > 18 ? node.label.slice(0, 16) + '…' : node.label;
                ctx.font = `${isSession ? 700 : 500} ${10.5 / scale}px 'JetBrains Mono', monospace`;
                ctx.fillStyle = isSession ? 'rgba(235, 240, 248, 0.95)' : 'rgba(210, 218, 232, 0.8)';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'top';
                ctx.fillText(label, node.x, node.y + r + 3 / scale);
              }
            }}
            nodePointerAreaPaint={(node, color, ctx) => {
              const isSession = node.type === 'session';
              const shared = !isSession && (node.session_count || 0) > 1;
              const r = isSession ? 8 : shared ? 5 + Math.min(node.session_count, 4) : 4;
              ctx.fillStyle = color;
              ctx.beginPath();
              ctx.arc(node.x, node.y, r + 3, 0, 2 * Math.PI);
              ctx.fill();
            }}
          />
        ) : (
          <div className="feed-empty">Graph is empty. Seed it or run a session.</div>
        )}

        <div className="graph-legend">
          <div className="lt">Node types</div>
          <div className="legend-row"><span className="legend-dot hub" /> Victim session <span className="lk" style={{ background: 'transparent', color: 'var(--text-faint)' }}>hub</span></div>
          {['phone', 'upi', 'bank_account', 'case_number', 'url'].map((type) => (
            <div key={type} className="legend-row">
              <span className="legend-dot" style={{ background: nodeColor(type) }} />
              {NODE_TYPE_LABELS[type]}
              {LINKABLE_TYPES.has(type) && <span className="lk">links</span>}
            </div>
          ))}
          {['claimed_name', 'claimed_department'].map((type) => (
            <div key={type} className="legend-row" style={{ opacity: 0.65 }}>
              <span className="legend-dot" style={{ background: nodeColor(type) }} />
              {NODE_TYPE_LABELS[type]}
            </div>
          ))}
        </div>
      </div>

      <div className="graph-side">
        <div className="section-title">Network Overview</div>
        {stats && (
          <div className="tiles">
            <div className="tile"><div className="tile-val">{stats.total_sessions}</div><div className="tile-lbl">Victim sessions</div></div>
            <div className="tile alarm"><div className="tile-val">{stats.clusters}</div><div className="tile-lbl">Operations</div></div>
            <div className="tile"><div className="tile-val">{stats.total_entities}</div><div className="tile-lbl">Identifiers</div></div>
            <div className="tile"><div className="tile-val">{stats.total_links}</div><div className="tile-lbl">Links</div></div>
          </div>
        )}

        <button className="btn btn-ghost" style={{ width: '100%' }} onClick={reseed}>
          ↻ Reset to seed data
        </button>

        <div className="divider" />

        {selected ? (
          <div className="node-detail">
            <div className="nd-type" style={{ color: nodeColor(selected.type) }}>
              <span className="nd-dot" style={{ background: nodeColor(selected.type) }} />
              {NODE_TYPE_LABELS[selected.type] || selected.type}
            </div>
            <h4>{selected.label}</h4>

            {selected.type === 'session' ? (
              <div className="nd-list">
                <div className="nd-list-item">Scam type · {scamTypeLabel(selected.scam_type)}</div>
                <div className="nd-list-item">Risk score · {selected.scam_probability ?? '—'}/100</div>
              </div>
            ) : (
              <>
                <div className="nd-list-item">Appears in {linkedSessions.length} session{linkedSessions.length === 1 ? '' : 's'}</div>
                {linkedSessions.length > 1 && (
                  <div className="nd-shared">
                    ⚠ Shared across {linkedSessions.length} victim sessions — a cross-victim link tying these cases to one operation.
                  </div>
                )}
                <div className="nd-list">
                  {linkedSessions.map((s) => (
                    <div key={s} className="nd-list-item">{String(s).replace('session:', '')}</div>
                  ))}
                </div>
              </>
            )}
          </div>
        ) : (
          <p className="subtle">
            Click a node to inspect it. The red, glowing nodes are identifiers shared
            between multiple victims — the cross-victim links that expose an organised
            operation rather than isolated incidents.
          </p>
        )}
      </div>

      {error && <div className="err-toast" onClick={() => setError(null)}>Backend error: {error}</div>}
    </div>
  );
}
