import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { api } from '../api';
import { nodeColor, NODE_TYPE_LABELS } from '../lib/risk';

// Fraud Network Dashboard.
//
// Renders the backend fraud graph. Session nodes and identifier nodes share one
// force layout; a cluster of connected nodes is one fraud operation across
// multiple victims. Clicking a node shows its details and, for identifiers,
// how many sessions it links.

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

  // Spread the layout so distinct operations read as distinct clusters rather
  // than one central blob. Stronger repulsion + longer links = more separation.
  useEffect(() => {
    const fg = fgRef.current;
    if (!fg || data.nodes.length === 0) return;
    fg.d3Force('charge')?.strength(-140);
    fg.d3Force('link')?.distance(45);
    fg.d3ReheatSimulation?.();
  }, [data]);

  useEffect(() => {
    const measure = () => {
      if (wrapRef.current) {
        setDims({ w: wrapRef.current.clientWidth, h: wrapRef.current.clientHeight });
      }
    };
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, [loading]);

  // react-force-graph mutates the objects it's given; hand it fresh copies so
  // React state stays clean across reloads.
  const graphData = useMemo(
    () => ({
      nodes: data.nodes.map((n) => ({ ...n })),
      links: data.edges.map((e) => ({ ...e })),
    }),
    [data]
  );

  const reseed = useCallback(async () => {
    setLoading(true);
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
        return other.id || other;
      });
  }, [selected, graphData]);

  if (loading) {
    return <div className="loading"><div className="spinner" /></div>;
  }

  return (
    <div className="network">
      <div className="graph-canvas" ref={wrapRef}>
        {graphData.nodes.length > 0 ? (
          <ForceGraph2D
            ref={fgRef}
            width={dims.w}
            height={dims.h}
            graphData={graphData}
            backgroundColor="rgba(0,0,0,0)"
            nodeRelSize={5}
            linkColor={() => 'rgba(120, 135, 165, 0.25)'}
            linkWidth={1}
            onNodeClick={(n) => setSelected(n)}
            nodeCanvasObject={(node, ctx, scale) => {
              const isSession = node.type === 'session';
              const r = isSession ? 7 : 4 + Math.min(node.session_count || 1, 4);
              ctx.beginPath();
              ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
              ctx.fillStyle = nodeColor(node.type);
              ctx.fill();
              if (selected?.id === node.id) {
                ctx.strokeStyle = '#fff';
                ctx.lineWidth = 2 / scale;
                ctx.stroke();
              }
              // Label sessions and highly-shared identifiers only, to avoid clutter.
              if (scale > 1.5 || isSession || (node.session_count || 0) > 1) {
                const label = node.label.length > 18 ? node.label.slice(0, 16) + '…' : node.label;
                ctx.font = `${11 / scale}px 'JetBrains Mono', monospace`;
                ctx.fillStyle = 'rgba(230, 236, 245, 0.75)';
                ctx.textAlign = 'center';
                ctx.fillText(label, node.x, node.y + r + 9 / scale);
              }
            }}
          />
        ) : (
          <div className="feed-empty">Graph is empty. Seed it or run a session.</div>
        )}

        <div className="graph-legend">
          {Object.entries(NODE_TYPE_LABELS).map(([type, label]) => (
            <div key={type} className="legend-row">
              <span className="legend-dot" style={{ background: nodeColor(type) }} />
              {label}
            </div>
          ))}
        </div>
      </div>

      <div className="graph-side">
        <div className="section-title">Fraud Network</div>
        {stats && (
          <div className="tiles">
            <div className="tile"><div className="tile-val">{stats.total_sessions}</div><div className="tile-lbl">Victim sessions</div></div>
            <div className="tile"><div className="tile-val">{stats.clusters}</div><div className="tile-lbl">Operations</div></div>
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
            <div className="section-title" style={{ color: nodeColor(selected.type) }}>
              {NODE_TYPE_LABELS[selected.type] || selected.type}
            </div>
            <h4>{selected.label}</h4>
            {selected.type === 'session' ? (
              <div className="stack">
                <div className="match-stat"><span>Scam type</span><span>{selected.scam_type || '—'}</span></div>
                <div className="match-stat"><span>Risk score</span><span>{selected.scam_probability ?? '—'}</span></div>
              </div>
            ) : (
              <>
                <div className="match-stat"><span>Appears in</span><span>{linkedSessions.length} session(s)</span></div>
                {linkedSessions.length > 1 && (
                  <p className="subtle" style={{ marginTop: 8, color: 'var(--risk-warn)' }}>
                    ⚠ Shared across multiple sessions — a cross-victim link.
                  </p>
                )}
                <div className="stack" style={{ marginTop: 8 }}>
                  {linkedSessions.map((s) => (
                    <div key={s} className="subtle" style={{ fontFamily: 'var(--mono)' }}>
                      {String(s).replace('session:', '')}
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        ) : (
          <p className="subtle">Click a node to inspect it. Nodes shared between sessions are the cross-victim links that reveal an organised operation.</p>
        )}
      </div>

      {error && <div className="err-toast" onClick={() => setError(null)}>Backend error: {error}</div>}
    </div>
  );
}
