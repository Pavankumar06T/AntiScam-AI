import { useState, useEffect } from 'react';
import { api } from './api';
import SessionMonitor from './components/SessionMonitor';
import NetworkDashboard from './components/NetworkDashboard';
import { LogoMark } from './components/Logo';

const LANGUAGES = [
  { code: 'en', label: 'EN' },
  { code: 'hi', label: 'हि' },
  { code: 'ta', label: 'த' },
];

export default function App() {
  const [tab, setTab] = useState(
    new URLSearchParams(window.location.search).get('tab') || 'monitor'
  );
  const [language, setLanguage] = useState('en');
  const [health, setHealth] = useState(null);
  const [graphKey, setGraphKey] = useState(0);
  // Ambient threat level drives the screen-edge glow, so the whole console
  // "responds" as a monitored call escalates.
  const [threat, setThreat] = useState('safe');

  useEffect(() => {
    let alive = true;
    const check = () =>
      api.health().then((h) => alive && setHealth(h)).catch(() => alive && setHealth({ status: 'down' }));
    check();
    const id = setInterval(check, 15000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  const statusClass =
    health?.status === 'ok' ? 'ok' : health?.status === 'degraded' ? 'degraded' : 'down';
  const statusText =
    !health ? 'connecting…'
      : health.status === 'ok' ? 'online'
      : health.status === 'degraded' ? 'rule-only'
      : 'offline';

  const ambientClass = tab === 'monitor' ? threat : 'safe';

  return (
    <div className="app">
      <div className={`ambient ${ambientClass}`} />

      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><LogoMark /></div>
          <div>
            <div className="brand-name">AntiScam<span> AI</span></div>
            <div className="brand-sub">Fraud Interception Console</div>
          </div>
        </div>

        <div className="nav-tabs">
          <button className={`nav-tab ${tab === 'monitor' ? 'active' : ''}`} onClick={() => setTab('monitor')}>
            <span className="tab-dot" /> Live Monitor
          </button>
          <button className={`nav-tab ${tab === 'network' ? 'active' : ''}`} onClick={() => setTab('network')}>
            <span className="tab-dot" /> Fraud Network
          </button>
        </div>

        <div className="topbar-right">
          <div className="lang-switch" title="Advisory language">
            {LANGUAGES.map((l) => (
              <button
                key={l.code}
                className={`lang-btn ${language === l.code ? 'active' : ''}`}
                onClick={() => setLanguage(l.code)}
              >
                {l.label}
              </button>
            ))}
          </div>
          <div className="status-pill" title={health?.model ? `Model: ${health.model}` : ''}>
            <span className={`dot ${statusClass}`} />
            {statusText}
            {health?.model && statusClass === 'ok' && <span className="mono">· {health.model.split('-')[0]}</span>}
          </div>
        </div>
      </header>

      <main className="main">
        {tab === 'monitor' ? (
          <SessionMonitor
            language={language}
            onGraphChanged={() => setGraphKey((k) => k + 1)}
            onThreat={setThreat}
          />
        ) : (
          <NetworkDashboard refreshKey={graphKey} />
        )}
      </main>
    </div>
  );
}
