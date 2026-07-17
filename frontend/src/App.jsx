import { useState, useEffect } from 'react';
import { api } from './api';
import SessionMonitor from './components/SessionMonitor';
import NetworkDashboard from './components/NetworkDashboard';

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
      : health.status === 'ok' ? `online · ${health.model}`
      : health.status === 'degraded' ? 'rule-only (no LLM key)'
      : 'backend offline';

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">🛡</div>
          <div>
            <div className="brand-name">AntiScam AI</div>
            <div className="brand-sub">Fraud Interception Console</div>
          </div>
        </div>

        <div className="tabs">
          <button className={`tab ${tab === 'monitor' ? 'active' : ''}`} onClick={() => setTab('monitor')}>
            Live Monitor
          </button>
          <button className={`tab ${tab === 'network' ? 'active' : ''}`} onClick={() => setTab('network')}>
            Fraud Network
          </button>
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 12, alignItems: 'center' }}>
          <div className="tabs" style={{ margin: 0 }}>
            {LANGUAGES.map((l) => (
              <button
                key={l.code}
                className={`tab ${language === l.code ? 'active' : ''}`}
                onClick={() => setLanguage(l.code)}
                title={`Advisory language: ${l.code}`}
              >
                {l.label}
              </button>
            ))}
          </div>
          <div className="status-pill">
            <span className={`dot ${statusClass}`} />
            {statusText}
          </div>
        </div>
      </header>

      <main className="main">
        {tab === 'monitor' ? (
          <SessionMonitor language={language} onGraphChanged={() => setGraphKey((k) => k + 1)} />
        ) : (
          <NetworkDashboard refreshKey={graphKey} />
        )}
      </main>
    </div>
  );
}
