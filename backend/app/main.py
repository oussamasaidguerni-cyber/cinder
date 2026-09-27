import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .data.seed_alerts import seed_alerts
from .data.store import AlertStore
from .routes.alerts import router as alerts_router
from .routes.audit import router as audit_router
from .routes.health import router as health_router

app = FastAPI(
    title="CINDER — AI-Powered SOC Analyst Copilot",
    description="Defensive, AI-assisted SOC alert analysis. Built for a hackathon demo.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(alerts_router)
app.include_router(audit_router)

# Serve the built React frontend so the whole app is ONE service (cloud deploy).
# In local dev the frontend is served by Vite at :5173 instead; both keep working.
_PROJECT = Path(__file__).resolve().parent.parent.parent
_STATIC = Path(os.getenv("APP_STATIC_DIR", str(_PROJECT / "frontend" / "dist")))

if (_STATIC / "index.html").exists():
    app.mount(
        "/assets",
        StaticFiles(directory=str(_STATIC / "assets")),
        name="assets",
    )

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC / "index.html")


@app.on_event("startup")
def startup_seed() -> None:
    store = AlertStore("data/cinder.db")
    try:
        if store.count() == 0:
            store.replace_all(seed_alerts())
        # Seed the agent-run trail so the Auditor demo has transcript on first load.
        store.ensure_audit_seeded()
    finally:
        store.close()