from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse

from .models import Alert, Device, KillSwitchRequest, KillSwitchResponse, RiskScore
from .store import STORE


app = FastAPI(title="Cyber-Sentinel API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> Dict[str, str]:
    return {"ok": "true"}


@app.get("/api/devices", response_model=List[Device])
def get_devices() -> List[Device]:
    return STORE.devices()


@app.get("/api/alerts", response_model=List[Alert])
def get_alerts(limit: int = 100) -> List[Alert]:
    return STORE.alerts(limit=limit)


@app.get("/api/risk", response_model=RiskScore)
def get_risk() -> RiskScore:
    return STORE.risk()


@app.post("/api/kill-switch", response_model=KillSwitchResponse)
def kill_switch(req: KillSwitchRequest) -> KillSwitchResponse:
    ok, action = STORE.block_ip(req.ip)
    return KillSwitchResponse(ok=ok, ip=req.ip, action=action)


def snapshot_payload() -> Dict[str, Any]:
    devices = STORE.devices()
    risk = STORE.risk()
    alerts = STORE.alerts(limit=50)
    blocked = STORE.blocked_ips()
    return {
        "ts": asyncio.get_event_loop().time(),
        "devices": [d.model_dump() for d in devices],
        "risk": risk.model_dump(),
        "alerts": [a.model_dump() for a in alerts],
        "blocked_ips": blocked,
    }


@app.websocket("/ws")
async def ws_stream(ws: WebSocket) -> None:
    await ws.accept()
    try:
        await ws.send_json({"type": "snapshot", "data": snapshot_payload()})
        while True:
            STORE.tick()
            await ws.send_json({"type": "snapshot", "data": snapshot_payload()})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return


# Serve the built React dashboard (for LAN users) when available.
#
# In Docker we run from:
# - backend code:   /app/app/main.py
# - frontend build: /app/frontend/dist
_APP_ROOT = Path(__file__).resolve().parents[1]  # /app
_FRONTEND_DIST = _APP_ROOT / "frontend" / "dist"

if _FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIST), html=True), name="frontend")

    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str) -> FileResponse:  # noqa: ARG001
        index = _FRONTEND_DIST / "index.html"
        return FileResponse(str(index))

