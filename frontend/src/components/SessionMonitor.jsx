import { useState, useRef, useEffect, useCallback } from 'react';
import { api } from '../api';
import { SAMPLE_TRANSCRIPTS } from '../sampleTranscripts';
import { riskColor, prettyCategory } from '../lib/risk';
import RiskGauge from './RiskGauge';
import AdvisoryBanner from './AdvisoryBanner';

// Live Session Monitor.
//
// "Plays" a transcript one turn at a time. After each caller turn it calls the
// backend with the conversation *so far* (is_full_conversation=false), so the
// risk score climbs as the scam unfolds — the point being to intercept before the
// extraction step, not to judge a completed call in hindsight.
//
// The final turn is sent as a full conversation and, if confirmed, produces the
// complaint draft. Only the last analysis is ingested into the graph, so replaying
// the demo doesn't create a pile of duplicate sessions.

const PLAY_INTERVAL_MS = 1400;

export default function SessionMonitor({ language, onGraphChanged }) {
  const [selected, setSelected] = useState(SAMPLE_TRANSCRIPTS[0]);
  const [shownTurns, setShownTurns] = useState([]);
  const [playing, setPlaying] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState(null);

  const feedRef = useRef(null);
  const cancelRef = useRef(false);

  const reset = useCallback(() => {
    cancelRef.current = true;
    setShownTurns([]);
    setResult(null);
    setHistory([]);
    setConfirmed(false);
    setPlaying(false);
    setAnalyzing(false);
  }, []);

  useEffect(() => { reset(); }, [selected, reset]);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [shownTurns]);

  const analyze = useCallback(
    async (turnsSoFar, isFull, doConfirm) => {
      const sessionId = `LIVE-${selected.id}`;
      const payload = {
        session_id: sessionId,
        turns: turnsSoFar.map((t, i) => ({ ...t, turn_index: i })),
        is_full_conversation: isFull,
        language,
        user_confirmed_fraud: doConfirm,
        // Only the final, complete analysis writes to the graph.
        ingest_into_graph: isFull,
      };
      const res = await api.processSession(payload);
      return res;
    },
    [selected, language]
  );

  const play = useCallback(async () => {
    reset();
    await new Promise((r) => setTimeout(r, 30));
    cancelRef.current = false;
    setPlaying(true);

    const turns = selected.turns;
    const shown = [];

    for (let i = 0; i < turns.length; i++) {
      if (cancelRef.current) return;
      shown.push(turns[i]);
      setShownTurns([...shown]);

      // Analyze after caller turns (and always on the last turn).
      const isLast = i === turns.length - 1;
      if (turns[i].speaker === 'caller' || isLast) {
        setAnalyzing(true);
        try {
          const res = await analyze(shown, isLast, false);
          if (cancelRef.current) return;
          setResult(res);
          setHistory((h) => [
            ...h,
            { turn: i + 1, score: res.detection.scam_probability },
          ]);
          if (isLast && res.graph_match?.is_repeat_scammer) onGraphChanged?.();
        } catch (e) {
          setError(e.message);
          setPlaying(false);
          setAnalyzing(false);
          return;
        }
        setAnalyzing(false);
      }

      if (!isLast) await new Promise((r) => setTimeout(r, PLAY_INTERVAL_MS));
    }
    setPlaying(false);
  }, [selected, analyze, reset, onGraphChanged]);

  const confirmFraud = useCallback(async () => {
    setAnalyzing(true);
    try {
      const res = await analyze(selected.turns, true, true);
      setResult(res);
      setConfirmed(true);
      onGraphChanged?.();
    } catch (e) {
      setError(e.message);
    }
    setAnalyzing(false);
  }, [selected, analyze, onGraphChanged]);

  const detection = result?.detection;
  const score = detection?.scam_probability ?? 0;
  const flaggedTurns = new Set((detection?.red_flags || []).map((f) => f.turn_index));

  return (
    <div className="monitor">
      {/* LEFT: transcript picker + controls */}
      <div className="col col-left">
        <div className="section-title">Session Simulator</div>
        <p className="subtle" style={{ marginBottom: 14 }}>
          Pick a transcript and play it through the live pipeline. Risk is scored
          after each turn, as it would be on a real call.
        </p>

        {SAMPLE_TRANSCRIPTS.map((t) => (
          <button
            key={t.id}
            className={`sample ${selected.id === t.id ? 'selected' : ''}`}
            onClick={() => setSelected(t)}
            disabled={playing}
          >
            <div className="sample-label">{t.label}</div>
            <div className="sample-note">{t.note}</div>
            <span className={`sample-tag ${t.expectation}`}>{t.expectation}</span>
          </button>
        ))}

        <div className="controls">
          <button className="btn btn-primary" onClick={play} disabled={playing}>
            {playing ? 'Playing…' : '▶ Play session'}
          </button>
          <button className="btn btn-ghost" onClick={reset} disabled={playing}>
            Reset
          </button>
        </div>
      </div>

      {/* MIDDLE: conversation feed */}
      <div className="col col-mid" ref={feedRef}>
        <div className="section-title">Live Conversation</div>
        {shownTurns.length === 0 ? (
          <div className="feed-empty">
            <div>
              <div style={{ fontSize: 32, marginBottom: 8 }}>🎧</div>
              Press <strong>Play session</strong> to begin monitoring.
            </div>
          </div>
        ) : (
          <div className="feed">
            {shownTurns.map((t, i) => (
              <div
                key={i}
                className={`turn ${t.speaker} ${flaggedTurns.has(i) ? 'flagged' : ''}`}
              >
                <div className="turn-meta">
                  {t.speaker === 'caller' ? '📞 Caller' : '👤 You'} · {t.timestamp}
                </div>
                <div className="bubble">{t.text}</div>
              </div>
            ))}
            {analyzing && (
              <div className="turn caller">
                <div className="bubble pulse subtle">Analyzing…</div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* RIGHT: risk + advisory + flags */}
      <div className="col col-right">
        <div className="section-title">Threat Assessment</div>
        <RiskGauge score={score} history={history} degraded={detection?.degraded} />

        {result?.warning && score >= 30 && (
          <>
            <div className="divider" />
            <AdvisoryBanner warning={result.warning} />
          </>
        )}

        {result?.graph_match?.is_repeat_scammer && (
          <div className="match-card">
            <div className="match-head">🕸 REPEAT SCAMMER DETECTED</div>
            <div className="banner-body" style={{ marginBottom: 8 }}>
              {result.graph_match.summary}
            </div>
            <div className="match-stat">
              <span>Cluster</span><span>{result.graph_match.cluster_id}</span>
            </div>
            <div className="match-stat">
              <span>Linked victims</span><span>{result.graph_match.total_victims_in_cluster}</span>
            </div>
            <div className="match-stat">
              <span>Confidence</span><span>{Math.round(result.graph_match.confidence * 100)}%</span>
            </div>
          </div>
        )}

        {detection?.red_flags?.length > 0 && (
          <>
            <div className="divider" />
            <div className="section-title">Red Flags ({detection.red_flags.length})</div>
            {detection.red_flags.map((f, i) => (
              <div key={i} className={`flag ${f.severity}`}>
                <div className="flag-cat">{prettyCategory(f.category)}</div>
                <div className="flag-quote">“{f.quote}”</div>
                <div className="flag-why">{f.explanation}</div>
              </div>
            ))}
          </>
        )}

        {detection && !playing && score >= 50 && !confirmed && (
          <>
            <div className="divider" />
            <button className="btn btn-primary" style={{ width: '100%' }} onClick={confirmFraud} disabled={analyzing}>
              ⚠ Confirm this was fraud → draft complaint
            </button>
          </>
        )}

        {confirmed && result?.complaint_text && (
          <>
            <div className="divider" />
            <div className="section-title">Complaint Draft — {result.complaint.complaint_id}</div>
            <p className="subtle" style={{ marginBottom: 8 }}>
              Auto-generated NCRB-style draft. Review before filing.
            </p>
            <pre className="complaint-box">{result.complaint_text}</pre>
          </>
        )}
      </div>

      {error && (
        <div className="err-toast" onClick={() => setError(null)}>
          Backend error: {error} · is the API running on {api.base}?
        </div>
      )}
    </div>
  );
}
