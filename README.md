# CINDER — AI-Powered SOC Analyst Copilot

A professional SOC dashboard for a Tier-1 analyst investigating alerts, built
with a reliable **deterministic detection engine** at its core and an optional
AI layer (Gemini) that only *phrases* the narrative — it never decides the
verdict.

Built for the GOMYCODE × NVIDIA Hackathon 2026. **This is a defensive analysis
tool.** It never executes logs or AI output, and its recommended actions are
advisory and non-destructive.

## Stack

| Layer | Tech |
|---|---|
| Frontend | React + TypeScript + Tailwind CSS (Vite) |
| Backend | Python FastAPI + pydantic |
| Data | SQLite (stdlib `sqlite3`) |
| AI | Gemini REST API via `urllib` (no SDK) with a labeled fallback mode |

## Quick start

Requires Python 3.11+ (`fastapi`, `uvicorn`, `pydantic`) and Node 20+.

```bash
cd backend && pip install -r requirements.txt && cd ..
./run.sh            # keep existing alert data
./run.sh --reset    # wipe the demo DB for a pristine 5-alert state
./run.sh --lan      # bind to 0.0.0.0 so other devices on the same WiFi can connect
```

Then open **http://localhost:5173** (dashboard). In `--lan` mode the runner prints
the network URL to share, e.g. `http://192.168.1.25:5173` — just allow ports
5173/8000 in any local firewall (Kali ships without one by default).

**Outside your LAN** (remote judges): tunnel the dev server, e.g.
`cloudflared tunnel --url http://localhost:5173` or `ngrok http 5173`, and share
that HTTPS URL.

If Node isn't on PATH but lives in `~/.local/bin`, the runner adds it
automatically. If Node is missing entirely, the backend still runs — the
frontend dev server is skipped and the API is browsable at
`http://127.0.0.1:8000/docs`.

## AI setup (optional)

CINDER prefers an AI provider in this order: **NVIDIA NIM** (build.nvidia.com)
→ **Gemini** → honest deterministic fallback. Set whichever key you have in
`backend/.env` (copy from `backend/.env.example`):

```
NVIDIA_API_KEY=...
NVIDIA_MODEL=nvidia/llama-3.1-nemotron-nano-8b-v1
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-3.5-flash-lite
```

- With a key: responses are labeled `Live AI analysis` and show the exact model
  that ran (e.g. `nvidia/llama-3.1-nemotron-nano-8b-v1`).
- The NVIDIA provider calls an OpenAI-compatible NIM endpoint
  (`https://integrate.api.nvidia.com/v1/chat/completions`); upgrade the model
  whenever you like without touching the pipeline.
- Without a key (or if calls fail): the deterministic engine answers and
  results are clearly labeled `Fallback mode` / `Deterministic engine`.
- The AI is never allowed to change the severity/verdict — it only improves the
  wording of the summary, actions, false-positive indicators, and report.

## Demo flow (90 seconds)

1. Dashboard auto-analyzes all alerts — each row shows an **AI verdict chip**
   (threat type, mode, confidence).
2. Click a row → investigation: raw evidence, **Analyze with CINDER** for the
   full structured verdict (severity, MITRE, actions, FP indicators, report).
3. Move it through the **status workflow** (NEW → INVESTIGATING → CONFIRMED).
4. **Ask CINDER** follow-ups ("Should I block this IP?", "Draft a report for
   management") — answers are labeled live-AI or fallback.
5. **Simulate alert** (header) to inject a fresh fabricated alert live, or
   **Triage a raw log** to paste any SSH/WAF/EDR text and get an instant verdict.
6. **Export case** to copy the whole investigation as Markdown.

## What it does

1. Seeds 5 realistic simulated alerts on first boot (all clearly simulated demo
   data using RFC 5737 TEST-NET IPs — no real infrastructure).
2. Lists alerts with severity/status filtering, relative timestamps, live
   auto-refresh, and dashboard KPIs.
3. Auto-scans every alert with the AI layer so the dashboard is instantly
   actionable.
4. Per-alert investigation shows raw evidence and an **Analyze with CINDER**
   button that returns structured output:

   - severity, threat type, confidence
   - evidence lines from the raw log
   - MITRE ATT&CK technique (small, verified local map)
   - recommended actions (defensive only)
   - false-positive indicators
   - a copyable incident report and a full Markdown case export

## Demo alerts

| ID | Type | Severity | MITRE |
|---|---|---|---|
| AL-2024-0001 | SSH brute force | HIGH | T1110 |
| AL-2024-0002 | PowerShell activity | MEDIUM | T1059.001 |
| AL-2024-0003 | Web attack (SQLi + admin scan) | HIGH | T1190 |
| AL-2024-0004 | Phishing email | MEDIUM | T1566.002 |
| AL-2024-0005 | Suspicious outbound connection | LOW | T1071.001 |

## Architecture

```
backend/app/
  main.py          FastAPI app, startup seeding, CORS
  routes/          health, alerts (list/detail/analyze/stats/simulate)
  services/        engine (deterministic), mitre map, analyzer, simulator
  ai/              provider.py (Gemini + fallback), prompts.py
  schemas/         pydantic models (Alert, AnalysisResult, Stats...)
  data/            SQLite store + demo seed
frontend/src/
  api.ts           typed API client
  components/      Logo, AlertTable, Investigation, TriageModal,
                   HowItWorks, Cards, Badges
  App.tsx          layout, KPI + navigation (hash-based routes)
```

## API

| Method | Path | Description |
|---|---|---|
| GET | `/health` | status + AI config |
| GET | `/alerts` | list (filters: `?severity=&status=`) |
| GET | `/alerts/{id}` | full alert incl. raw log |
| POST | `/alerts/{id}/analyze` | full structured analysis |
| GET | `/alerts/stats` | KPI aggregates |
| GET | `/alerts/analyze-all` | analyze every alert (cached) for AI chips |
| POST | `/alerts/analyze-raw` | triage freeform raw log text |
| PATCH | `/alerts/{id}/status` | update workflow status |
| POST | `/alerts/{id}/ask` | free-text questions about an alert |
| POST | `/alerts/simulate` | inject a fresh fabricated alert (demo) |

Interactive docs: http://127.0.0.1:8000/docs

## Deploy to the public web (Render, free)

The whole app is one service: FastAPI serves the built React site. No laptop,
no tunnel, no localhost — a permanent URL reachable from everywhere.

1. Push this repo to GitHub (done — `github.com/oussamasaidguerni-cyber/cinder`).
2. Sign in at https://render.com (free, no card).
3. **New + → Blueprint → Public Repo** → pick this repo → **Apply**.
   `render.yaml` handles the rest (installs deps, builds the frontend,
   `GEMINI_MODEL` preloaded).
4. In the service's **Environment** tab, set `GEMINI_API_KEY` to your key and
   save — until then the app runs in honest fallback mode.
5. Done: you get a permanent URL like `https://cinder.onrender.com`.

Notes:

- Free tier sleeps after ~15 min idle; the first load after sleep takes ~30-60s
  to wake, then it's fast. A free uptime ping keeps it warm.
- Ephemeral disk: the demo DB reseeds to the 5 alerts on each fresh boot.
- Verify live status at `<your-url>/health` (`ai_configured` shows if the key
  is set).

## Security notes

- Binds to `127.0.0.1` by default; CORS locked to the Vite origin.
- API keys live only in backend env vars, never in frontend code.
- Logs and AI output are displayed as text and escaped — never executed.
- No destructive/offensive recommended actions.