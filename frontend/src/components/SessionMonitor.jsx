import { useState, useRef, useEffect, useCallback } from 'react';
import { api } from '../api';
import { SAMPLE_TRANSCRIPTS } from '../sampleTranscripts';
import { prettyCategory, riskLevel, scamTypeLabel, WARN_THRESHOLD } from '../lib/risk';
import RiskGauge from './RiskGauge';
import AdvisoryBanner from './AdvisoryBanner';
import EscalationTracker from './EscalationTracker';
import DetectorBreakdown from './DetectorBreakdown';
import DisruptionCard from './DisruptionCard';

// Live Session Monitor.
//
// Two input modes share one analysis surface (the feed + threat assessment):
//   • Demo samples — "plays" a scripted transcript turn by turn.
//   • Live input   — records the mic → Groq Whisper → transcript, or accepts pasted
//                    text, and analyses each caller line as it arrives.
//
// Both stream the conversation to the backend with the call *so far*, so the risk
// score climbs as the scam unfolds — the point being to intercept before the
// extraction step. We record the interception moment (first turn the score crosses
// the warn threshold) and the extraction moment, so we can show the lead time — the
// warning fired before the money was demanded, which is the whole product thesis.

const PLAY_INTERVAL_MS = 1500;
const fmtClock = (sec) =>
  `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(Math.floor(sec % 60)).padStart(2, '0')}`;

export default function SessionMonitor({ language, onGraphChanged, onThreat }) {
  const [mode, setMode] = useState('samples'); // 'samples' | 'live'
  const [selected, setSelected] = useState(SAMPLE_TRANSCRIPTS[0]);
  const [liveTurns, setLiveTurns] = useState([]);
  const [shownTurns, setShownTurns] = useState([]);
  const [playing, setPlaying] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [recording, setRecording] = useState(false);
  const [transcribing, setTranscribing] = useState(false);
  const [pasteText, setPasteText] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [confirmed, setConfirmed] = useState(false);
  const [interceptAt, setInterceptAt] = useState(null);
  const [extractionAt, setExtractionAt] = useState(null);
  const [error, setError] = useState(null);

  const feedRef = useRef(null);
  const cancelRef = useRef(false);
  const liveTurnsRef = useRef([]);
  const callStartRef = useRef(0);
  const interceptRef = useRef(null);
  const extractionRef = useRef(null);
  const recorderRef = useRef(null);
  const streamRef = useRef(null);
  const chunksRef = useRef([]);

  const reset = useCallback(() => {
    cancelRef.current = true;
    if (recorderRef.current?.state && recorderRef.current.state !== 'inactive') recorderRef.current.stop();
    streamRef.current?.getTracks().forEach((t) => t.stop());
    liveTurnsRef.current = [];
    callStartRef.current = 0;
    interceptRef.current = null;
    extractionRef.current = null;
    setLiveTurns([]);
    setShownTurns([]);
    setResult(null);
    setHistory([]);
    setConfirmed(false);
    setInterceptAt(null);
    setExtractionAt(null);
    setPlaying(false);
    setAnalyzing(false);
    setRecording(false);
    setTranscribing(false);
    onThreat?.('safe');
  }, [onThreat]);

  useEffect(() => { reset(); }, [selected, mode, reset]);
  useEffect(() => () => onThreat?.('safe'), [onThreat]);
  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [shownTurns, analyzing, transcribing]);

  const runPipeline = useCallback(
    (sessionId, turns, isFull, confirm, ingest) =>
      api.processSession({
        session_id: sessionId,
        turns: turns.map((t, i) => ({ ...t, turn_index: i })),
        is_full_conversation: isFull,
        language,
        user_confirmed_fraud: confirm,
        ingest_into_graph: ingest,
      }),
    [language]
  );

  // Shared: fold one analysis result into the UI state + lead-time tracking.
  const recordAnalysis = useCallback((res, turnNo, ts) => {
    const s = res.detection.scam_probability;
    setResult(res);
    setHistory((h) => [...h, { turn: turnNo, score: s }]);
    onThreat?.(riskLevel(s));
    if (!interceptRef.current && s >= WARN_THRESHOLD) {
      interceptRef.current = { turn: turnNo, ts };
      setInterceptAt(interceptRef.current);
    }
    if (!extractionRef.current && res.detection.escalation_stage === 'extraction_attempted') {
      extractionRef.current = { turn: turnNo, ts };
      setExtractionAt(extractionRef.current);
    }
    if (res.graph_match?.is_repeat_scammer) onGraphChanged?.();
  }, [onThreat, onGraphChanged]);

  // --- Demo sample playback ---
  const play = useCallback(async () => {
    reset();
    await new Promise((r) => setTimeout(r, 40));
    cancelRef.current = false;
    setPlaying(true);

    const turns = selected.turns;
    const shown = [];
    for (let i = 0; i < turns.length; i++) {
      if (cancelRef.current) return;
      shown.push(turns[i]);
      setShownTurns([...shown]);

      const isLast = i === turns.length - 1;
      if (turns[i].speaker === 'caller' || isLast) {
        setAnalyzing(true);
        try {
          const res = await runPipeline(`LIVE-${selected.id}`, shown, isLast, false, isLast);
          if (cancelRef.current) return;
          recordAnalysis(res, i + 1, turns[i].timestamp);
        } catch (e) {
          setError(e.message); setPlaying(false); setAnalyzing(false); return;
        }
        setAnalyzing(false);
      }
      if (!isLast) await new Promise((r) => setTimeout(r, PLAY_INTERVAL_MS));
    }
    setPlaying(false);
  }, [selected, runPipeline, recordAnalysis, reset]);

  // --- Live input (voice / paste) ---
  const addLine = useCallback(async (text) => {
    const clean = (text || '').trim();
    if (!clean) return;
    if (!callStartRef.current) callStartRef.current = Date.now();
    const ts = fmtClock((Date.now() - callStartRef.current) / 1000);
    const next = [...liveTurnsRef.current, { speaker: 'caller', text: clean, timestamp: ts }];
    liveTurnsRef.current = next;
    setLiveTurns(next);
    setShownTurns(next);
    setConfirmed(false);
    setAnalyzing(true);
    try {
      const res = await runPipeline('LIVE-VOICE', next, true, false, true);
      recordAnalysis(res, next.length, ts);
    } catch (e) {
      setError(e.message);
    }
    setAnalyzing(false);
  }, [runPipeline, recordAnalysis]);

  const handleBlob = useCallback(async (blob) => {
    setTranscribing(true);
    try {
      const { transcript } = await api.transcribe(blob);
      if (transcript) await addLine(transcript);
      else setError('No speech detected — try recording again, a little louder.');
    } catch (e) {
      setError(`Transcription failed: ${e.message}`);
    }
    setTranscribing(false);
  }, [addLine]);

  const startRec = useCallback(async () => {
    setError(null);
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
      setError('Mic recording is not supported here — use the paste box below.');
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      streamRef.current = stream;
      const mr = new MediaRecorder(stream);
      chunksRef.current = [];
      mr.ondataavailable = (e) => { if (e.data.size) chunksRef.current.push(e.data); };
      mr.onstop = async () => {
        streamRef.current?.getTracks().forEach((t) => t.stop());
        await handleBlob(new Blob(chunksRef.current, { type: mr.mimeType || 'audio/webm' }));
      };
      mr.start();
      recorderRef.current = mr;
      setRecording(true);
    } catch {
      setError('Microphone access was denied. Allow mic permission, or use the paste box.');
    }
  }, [handleBlob]);

  const stopRec = useCallback(() => {
    if (recorderRef.current?.state && recorderRef.current.state !== 'inactive') recorderRef.current.stop();
    setRecording(false);
  }, []);

  const submitPaste = useCallback(async () => {
    const t = pasteText.trim();
    if (!t) return;
    setPasteText('');
    await addLine(t);
  }, [pasteText, addLine]);

  const confirmFraud = useCallback(async () => {
    setAnalyzing(true);
    try {
      const sessionId = mode === 'live' ? 'LIVE-VOICE' : `LIVE-${selected.id}`;
      const turns = mode === 'live' ? liveTurnsRef.current : selected.turns;
      const res = await runPipeline(sessionId, turns, true, true, true);
      setResult(res); setConfirmed(true); onGraphChanged?.();
    } catch (e) { setError(e.message); }
    setAnalyzing(false);
  }, [mode, selected, runPipeline, onGraphChanged]);

  const copyComplaint = useCallback(() => {
    if (result?.complaint_text) navigator.clipboard?.writeText(result.complaint_text);
  }, [result]);

  const detection = result?.detection;
  const score = detection?.scam_probability ?? 0;
  const flaggedTurns = new Set((detection?.red_flags || []).map((f) => f.turn_index));
  const lastTs = shownTurns.length ? shownTurns[shownTurns.length - 1].timestamp : '00:00';
  const busy = playing || recording || transcribing || analyzing;
  const showIntercept = interceptAt && (!extractionAt || interceptAt.turn <= extractionAt.turn);

  return (
    <div className="monitor">
      {/* LEFT: input source */}
      <div className="col col-left">
        <div className="mode-toggle">
          <button className={mode === 'samples' ? 'active' : ''} onClick={() => setMode('samples')} disabled={busy}>
            Demo samples
          </button>
          <button className={mode === 'live' ? 'active' : ''} onClick={() => setMode('live')} disabled={busy}>
            🎤 Live input
          </button>
        </div>

        {mode === 'samples' ? (
          <>
            <p className="sim-intro">
              Pick a transcript and play it through the live pipeline. Risk is scored after
              each turn, exactly as it would be on a real call.
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
                {playing ? '● Monitoring…' : '▶ Play session'}
              </button>
              <button className="btn btn-ghost" onClick={reset} disabled={playing}>Reset</button>
            </div>
            <div className="briefing">
              <div className="brief-row"><span className="k">Expected</span><span className="v">{selected.scamType === 'none' ? 'legitimate' : scamTypeLabel(selected.scamType)}</span></div>
              <div className="brief-row"><span className="k">Turns</span><span className="v">{selected.turns.length}</span></div>
              <div className="brief-row"><span className="k">Verdict so far</span><span className="v" style={{ color: score >= 50 ? 'var(--risk-critical)' : score >= 30 ? 'var(--risk-caution)' : 'var(--risk-safe)' }}>{detection ? `${score}/100` : '—'}</span></div>
            </div>
          </>
        ) : (
          <>
            <p className="sim-intro">
              Speak a suspicious call into the mic — Groq Whisper transcribes it and the
              same engine scores it live. This is the system working on <strong>real audio</strong>,
              not a script.
            </p>

            <button
              className={`rec-btn ${recording ? 'recording' : ''}`}
              onClick={recording ? stopRec : startRec}
              disabled={transcribing || playing}
            >
              <span className="rec-ring" />
              {recording ? 'Stop & analyse' : transcribing ? 'Transcribing…' : 'Hold a line? Tap to record'}
            </button>
            <p className="subtle" style={{ margin: '4px 2px 14px' }}>
              Tap record, say one caller line, tap stop. Repeat to build the call up turn by turn.
            </p>

            <div className="paste-box">
              <div className="section-title" style={{ marginBottom: 8 }}>or paste / type a line</div>
              <textarea
                className="paste-area"
                rows={3}
                placeholder="e.g. This is CBI. You are under digital arrest. Transfer money to the verification account now."
                value={pasteText}
                onChange={(e) => setPasteText(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) submitPaste(); }}
                disabled={transcribing}
              />
              <div className="controls" style={{ margin: '10px 0 0' }}>
                <button className="btn btn-primary" onClick={submitPaste} disabled={!pasteText.trim() || transcribing}>
                  Add line →
                </button>
                <button className="btn btn-ghost" onClick={reset}>Reset call</button>
              </div>
            </div>

            {liveTurns.length > 0 && (
              <div className="briefing">
                <div className="brief-row"><span className="k">Lines captured</span><span className="v">{liveTurns.length}</span></div>
                <div className="brief-row"><span className="k">Current risk</span><span className="v" style={{ color: score >= 50 ? 'var(--risk-critical)' : score >= 30 ? 'var(--risk-caution)' : 'var(--risk-safe)' }}>{detection ? `${score}/100` : '—'}</span></div>
              </div>
            )}
          </>
        )}
      </div>

      {/* MIDDLE: conversation feed */}
      <div className="col-mid">
        <div className="feed-header">
          <div className="feed-header-top">
            <span className={`live-badge ${busy ? '' : 'idle'}`}>
              <span className="rec" /> {recording ? 'RECORDING' : playing ? 'LIVE' : transcribing ? 'TRANSCRIBING' : 'STANDBY'}
            </span>
            <span className="feed-clock">⏱ {lastTs}</span>
          </div>
          <EscalationTracker stage={detection?.escalation_stage} />
        </div>

        <div className="feed-scroll" ref={feedRef}>
          {shownTurns.length === 0 ? (
            <div className="feed-empty">
              <div>
                <div className="big">{mode === 'live' ? '🎤' : '🎧'}</div>
                {mode === 'live'
                  ? <>Record or paste a caller line to begin analysing a real call.</>
                  : <>Press <strong>Play session</strong> to begin monitoring the call.</>}
              </div>
            </div>
          ) : (
            <div className="feed">
              {shownTurns.map((t, i) => (
                <div key={i} className={`turn ${t.speaker} ${flaggedTurns.has(i) ? 'flagged' : ''}`}>
                  <div className="turn-meta">
                    {t.speaker === 'caller' ? '📞 Caller' : '👤 You'} · {t.timestamp}
                  </div>
                  <div className="bubble">{t.text}</div>
                </div>
              ))}
              {(analyzing || transcribing) && (
                <div className="analyzing-row">
                  <span className="spinner-sm" /> {transcribing ? 'Transcribing audio…' : 'Analysing conversation…'}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* RIGHT: threat assessment */}
      <div className="col-right assess-scroll">
        <div className="section-title">
          Threat Assessment
          {detection && <span className="count" style={{ marginLeft: 'auto' }}>{scamTypeLabel(detection.scam_type)}</span>}
        </div>

        <RiskGauge score={score} history={history} degraded={detection?.degraded} />

        {detection?.breakdown && <DetectorBreakdown breakdown={detection.breakdown} />}

        {showIntercept && (
          <div className="intercept">
            <span className="intercept-icon">🛡️</span>
            <div>
              <div className="intercept-title">Intercepted before extraction</div>
              <div className="intercept-body">
                Warning issued at turn <strong>{interceptAt.turn}</strong> (<strong>{interceptAt.ts}</strong>)
                {extractionAt
                  ? <> — {extractionAt.turn > interceptAt.turn ? <><strong>{extractionAt.turn - interceptAt.turn}</strong> turn(s)</> : 'right as'} before the money was demanded at <strong>{extractionAt.ts}</strong>.</>
                  : ', before any money was demanded.'}
              </div>
            </div>
          </div>
        )}

        {result?.graph_match?.is_repeat_scammer && (
          <>
            <div className="divider" />
            <div className="match-card">
              <div className="match-head"><span className="pulse-ring" /> REPEAT SCAMMER DETECTED</div>
              <div className="match-body">{result.graph_match.summary}</div>
              <div className="match-stats">
                <div className="match-stat"><div className="msv">{result.graph_match.total_victims_in_cluster}</div><div className="msl">Victims</div></div>
                <div className="match-stat"><div className="msv">{result.graph_match.cluster_id?.replace('CLUSTER-', '#')}</div><div className="msl">Cluster</div></div>
                <div className="match-stat"><div className="msv">{Math.round(result.graph_match.confidence * 100)}%</div><div className="msl">Confidence</div></div>
              </div>
            </div>
          </>
        )}

        {result?.warning && score >= 30 && (
          <>
            <div className="divider" />
            <div className="section-title">🔔 Warning Delivered to User</div>
            <AdvisoryBanner warning={result.warning} />
          </>
        )}

        {result?.disruption && (
          <>
            <div className="divider" />
            <div className="section-title">🚨 Disrupt · Dispatch to Banks & Telecom</div>
            <DisruptionCard disruption={result.disruption} />
          </>
        )}

        {detection?.red_flags?.length > 0 && (
          <>
            <div className="divider" />
            <div className="section-title">Red Flags <span className="count">{detection.red_flags.length}</span></div>
            {detection.red_flags.map((f, i) => (
              <div key={i} className={`flag ${f.severity}`}>
                <div className="flag-top">
                  <span className="flag-cat">{prettyCategory(f.category)}</span>
                  <span className={`flag-sev ${f.severity}`}>{f.severity}</span>
                </div>
                <div className="flag-quote">"{f.quote}"</div>
                <div className="flag-why">{f.explanation}</div>
              </div>
            ))}
          </>
        )}

        {detection && !busy && score >= 50 && !confirmed && (
          <>
            <div className="divider" />
            <button className="btn btn-danger" style={{ width: '100%' }} onClick={confirmFraud} disabled={analyzing}>
              ⚠ Confirm this was fraud → draft complaint
            </button>
          </>
        )}

        {confirmed && result?.complaint_text && (
          <>
            <div className="divider" />
            <div className="section-title">📄 Complaint Draft <span className="count">{result.complaint.complaint_id}</span></div>
            <div className="complaint-actions">
              <button className="btn btn-ghost" onClick={copyComplaint}>⧉ Copy</button>
            </div>
            <p className="subtle" style={{ marginBottom: 10 }}>
              Auto-generated NCRB-style draft. Review before filing at cybercrime.gov.in.
            </p>
            <pre className="complaint-box">{result.complaint_text}</pre>
          </>
        )}
      </div>

      {error && (
        <div className="err-toast" onClick={() => setError(null)}>
          {error} · API: {api.base}
        </div>
      )}
    </div>
  );
}
