// Thin API client for the AntiScam AI backend.
//
// The backend base URL is configurable so the same build works locally and
// against a deployed backend (set VITE_API_BASE at build time on Vercel).

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch {
      // non-JSON error body; keep the status line
    }
    throw new Error(detail);
  }
  return res.json();
}

export const api = {
  base: API_BASE,

  health: () => request('/api/health'),

  classify: (payload) =>
    request('/api/classify', { method: 'POST', body: JSON.stringify(payload) }),

  processSession: (payload) =>
    request('/api/session/process', { method: 'POST', body: JSON.stringify(payload) }),

  // Transcribe a recorded audio blob via Groq Whisper. Uses multipart, so it
  // bypasses the JSON request() helper.
  transcribe: async (blob, filename = 'clip.webm') => {
    const form = new FormData();
    form.append('audio', blob, filename);
    const res = await fetch(`${API_BASE}/api/transcribe`, { method: 'POST', body: form });
    if (!res.ok) {
      let detail = `${res.status} ${res.statusText}`;
      try { const b = await res.json(); if (b.detail) detail = b.detail; } catch { /* keep status */ }
      throw new Error(detail);
    }
    return res.json();
  },

  graphEntities: () => request('/api/graph/entities'),

  graphStats: () => request('/api/graph/stats'),

  reseedGraph: () => request('/api/graph/seed', { method: 'POST' }),
};
