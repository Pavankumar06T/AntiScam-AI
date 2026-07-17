# AntiScam AI — Backend

**Phase 1: Foundation & Core Detection Agent**

Real-time interception of *conversational* fraud — digital arrest, KYC, prize,
loan, job and investment scams — scored from live call/chat transcripts.

This is not transaction-fraud detection. It judges **language and dialogue
dynamics**: impersonated authority, manufactured fear, isolation, and extraction.

---

## Detection architecture

The Detection Agent is **two layers, fused** — not a bare LLM call:

```
transcript ─┬─> deterministic tripwires (rules.py) ──> rule_score ─┐
            │        microseconds, no network                      ├─> fused score
            └─> Groq LLM (JSON mode, few-shot)     ──> llm_score  ─┘
                     ~2s, llama-3.3-70b-versatile
```

Fusion is `(1 - RULE_WEIGHT) * llm_score + RULE_WEIGHT * rule_score`, LLM-dominant
by default (`RULE_WEIGHT=0.25`). The rule layer exists for four reasons:

1. **Latency floor** — the UI can move the risk score before the LLM round-trip lands.
2. **Graceful degradation** — if Groq is down or rate-limited, an obvious scam still
   scores ~97 instead of the system failing open. Verified by test.
3. **Explainability** — "matched these named coercion patterns" is auditable in a way
   "the model said 82" is not. For a public-safety tool, that matters.
4. **Drift guard** — a prompt edit cannot silently erase a hard signal like "share your OTP".

**Fail-fast on rate limits.** The Groq client is constructed with `max_retries=0`
deliberately: the SDK's default retry sleeps ~25s inside a 429, and a silent 25-second
stall in a real-time interception system is worse than an honest rule-only score.
Batch jobs opt back into waiting via `classify(allow_backoff=True)`.

Entity extraction (phone / UPI / account / claimed officer / case number) is
**deterministic on purpose** — these become graph nodes in Phase 2, and a
hallucinated phone number would poison cross-victim linking.

---

## ⚠️ Groq free tier: 100,000 tokens per DAY

The binding constraint on this project. Measured, not assumed:

| Metric | Value |
|---|---|
| Prompt tokens / detection call | 3,355 (≈2,500 is the few-shot block) |
| Completion tokens / call | ~550 |
| **Total / call** | **~3,900** |
| Free tier TPM (llama-3.3-70b) | 12,000 |
| **Free tier TPD** | **100,000 → ~25 detection calls/day** |
| Measured detection latency | **1.8–2.5s** |

Consequences: a 60-sample metrics run costs ~234k tokens (**2.3 days** of free
budget) and dataset generation costs ~150k (**1.5 days**). **Groq Dev Tier**
(pay-as-you-go, ~$0.59/M in, ~$0.79/M out) puts the whole project at roughly
**$1–3** and is the intended fix: <https://console.groq.com/settings/billing>

Note the failure mode is confusing: the TPM headers read *full* while TPD is
exhausted, so a daily-cap 429 looks like a per-minute problem. Read the error body.

---

## Setup

### 1. Get a Groq API key
Sign up at [console.groq.com/keys](https://console.groq.com/keys).

### 2. Install

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS/Linux
pip install -r requirements.txt

copy .env.example .env         # then paste your GROQ_API_KEY into .env
```

`.env` is gitignored. No key is ever hardcoded.

### 3. Run

```bash
uvicorn app.main:app --reload
```

- API: <http://localhost:8000>
- Interactive docs: <http://localhost:8000/docs>
- Health: <http://localhost:8000/api/health>

Without a key the server still starts and runs in **degraded (rule-only) mode**,
which is useful for frontend work that shouldn't burn token budget.

### 4. Try it

```bash
curl -X POST http://localhost:8000/api/classify \
  -H "Content-Type: application/json" \
  -d '{"conversation_id":"demo1","transcript":"caller: This is Inspector Sharma from CBI. A money laundering case is registered against your Aadhaar. You are under digital arrest, do not tell your family. Transfer Rs 50,000 to the RBI verification account 50100294471882 immediately or a non-bailable warrant will be issued."}'
```

### 5. Generate the dataset

```bash
python scripts/generate_dataset.py            # skips if the file exists
python scripts/generate_dataset.py --force    # regenerate
python scripts/generate_dataset.py --per-cell 2   # smaller/cheaper run
```

60 labeled transcripts (30 scam across 5 types, 30 legitimate) → `data/synthetic_transcripts.json`.
Roughly half the legitimate half are deliberate **hard negatives** — calls that look
scam-like (urgency, account numbers, an OTP, identity checks) but are genuinely
benign. A benchmark of easy negatives would report a flattering false-positive rate
that means nothing.

> Costs ~150k tokens — exceeds one day of free-tier budget. Use `--per-cell 2` on
> free tier, or upgrade to Dev Tier.

### 6. Test

```bash
pytest                # offline + live; live auto-skips with no key
pytest -m "not live"  # offline only, zero tokens
pytest -m stress      # opt-in burst test (~23k tokens)
```

Live tests are auto-paced (`LIVE_TEST_SPACING`, default 21s) to stay inside the
token budget, and skip rather than fail when the LLM layer is unavailable — a
rate limit measures Groq's queue, not our detector.

---

## Project structure

```
backend/
├── app/
│   ├── main.py                  # FastAPI app, CORS, latency logging
│   ├── config.py                # env config + live Groq model resolution
│   ├── agents/
│   │   ├── scam_detector.py     # Detection Agent: fusion, retry, degradation
│   │   ├── rules.py             # deterministic tripwires + entity extraction
│   │   └── prompts.py           # system prompt + few-shot examples
│   ├── models/schemas.py        # Pydantic contracts
│   └── routers/classify.py      # /api/classify, /api/health
├── scripts/generate_dataset.py
├── tests/
│   ├── test_rules.py            # offline: tripwires + entity extraction
│   ├── test_scam_detector.py    # offline: fusion, degradation (LLM stubbed)
│   └── test_api.py              # contract + live Groq tests
├── requirements.txt
├── .env.example
└── pytest.ini
```

## Configuration

| Variable | Default | Description |
|---|---|---|
| `GROQ_API_KEY` | *(required)* | Key from console.groq.com/keys |
| `MODEL_NAME` | `llama-3.3-70b-versatile` | Resolved against the live catalogue at startup; falls back automatically if retired |
| `TEMPERATURE` | `0.2` | Low, for score consistency |
| `WARN_THRESHOLD` | `50` | Score at which the user is warned |
| `URGENT_THRESHOLD` | `75` | Score at which we intervene urgently |
| `RULE_WEIGHT` | `0.25` | Rule layer's share of the fused score |
| `CORS_ORIGINS` | `localhost:5173,localhost:3000` | Comma-separated |

Thresholds live in config, not scattered across code, so the API, orchestrator, and
dashboard cannot disagree about what "warning" means.

## API

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health + whether Groq is configured + resolved model |
| `POST` | `/api/classify` | Score a transcript (full or partial chunk) |

`/api/classify` accepts either a raw `transcript` string (parses `speaker: text`
lines) or structured `turns[]`. Structured turns are preferred — they let red flags
carry a turn index and timestamp, which the Phase 2 evidence packet needs.

## Model substitution

Groq rotates its catalogue. `app/config.py` checks the configured model against the
live `client.models.list()` at startup and falls back through an ordered list,
logging any substitution loudly, rather than hard-failing mid-demo.

*Verified 2026-07-17: `llama-3.3-70b-versatile` is available; no substitution needed.*

## Limitations

- **Synthetic data only.** No real call transcripts. Metrics measure behaviour on
  machine-generated dialogue, which is cleaner and more stereotyped than reality.
- **English-dominant.** Patterns cover common Hindi/Hinglish transliterations, but
  the prompt and rules are English-first. Multilingual output lands in Phase 2.
- **No live telecom integration.** Transcripts are replayed, not tapped.
- **Rule lexicon is hand-built**, not learned — it will miss novel phrasings by
  construction. That's why it's a minority vote and not the primary judge.

---

Built for **ET AI Hackathon 2026** — AI for Digital Public Safety.
