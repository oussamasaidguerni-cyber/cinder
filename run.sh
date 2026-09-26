#!/usr/bin/env bash
# CINDER - AI-Powered SOC Analyst Copilot
# One-command local runner. Requires: python3 (with fastapi/uvicorn/pydantic)
# and Node.js >= 20 (from PATH or ~/.local/bin, else dev server is skipped).
#   ./run.sh          start backend + frontend (keeps existing alert data)
#   ./run.sh --reset  delete demo DB first for a pristine demo state
#   ./run.sh --lan    bind to 0.0.0.0 so other devices on the LAN can connect

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PATH="$HOME/.local/bin:$PATH"

BIND="127.0.0.1"
RESET=0
for arg in "$@"; do
  case "$arg" in
    --lan) BIND="0.0.0.0" ;;
    --reset) RESET=1 ;;
  esac
done

if [ "$RESET" = "1" ]; then
  rm -f "$ROOT/backend/data/cinder.db"
  echo "[cinder] wiped demo database (fresh seed on next boot)."
fi

# Load optional .env (if set -a; env -f; ...). Simple inline parser.
if [ -f "$ROOT/backend/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/backend/.env"
  set +a
fi

PY="${PYTHON:-python3}"

echo "[cinder] starting backend on $BIND:8000 ..."
(cd "$ROOT/backend" && exec "$PY" -m uvicorn app.main:app --host "$BIND" --port 8000) &
BACK_PID=$!

trap 'kill $BACK_PID 2>/dev/null || true' EXIT INT TERM

if command -v node >/dev/null 2>&1 || [ -x "$HOME/.local/bin/node" ]; then
  echo "[cinder] starting frontend on http://localhost:5173 ..."
  (cd "$ROOT/frontend" && exec npm run dev -- --host "$BIND") &
  FRONT_PID=$!
  trap 'kill $BACK_PID $FRONT_PID 2>/dev/null || true' EXIT INT TERM
else
  echo "[cinder] node not found - frontend SKIPPED. Backend API only. Install Node or run: npm run dev"
fi

if [ "$BIND" = "0.0.0.0" ]; then
  LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "[cinder] ready (LAN mode — same WiFi only)."
  echo "  Dashboard: http://${LAN_IP:-<this-machine-ip>}:5173"
  echo "  API docs:  http://${LAN_IP:-<this-machine-ip>}:8000/docs"
  echo "  Note: allow ports 5173/8000 in any local firewall (Kali usually has none)."
else
  echo "[cinder] ready."
  echo "  Dashboard: http://localhost:5173  (requires frontend server)"
  echo "  API docs:  http://127.0.0.1:8000/docs"
fi

echo "  Tip: for access outside this machine/LAN, tunnel it — see README."

wait