from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import FileResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .auth import authenticate_user, create_access_token, current_user, get_db, jwt_secret, token_from_ws_query
from .db import Base, ENGINE, session_scope
import uuid
from datetime import datetime, timezone

from .models import (
    Alert,
    Device,
    KillSwitchRequest,
    KillSwitchResponse,
    Packet,
    RiskScore,
    TokenResponse,
    UserMe,
    Vulnerability,
)
from .orm import AlertRow, DeviceRow, PacketRow, UserRow, VulnerabilityRow
from .store import STORE, sync_to_db


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

@app.on_event("startup")
def _startup() -> None:
    Base.metadata.create_all(bind=ENGINE)

    # Lightweight schema upgrades (no Alembic for hackathon deployment)
    with ENGINE.begin() as conn:
        # Add new device metadata columns if table existed before
        conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS vendor VARCHAR(255)"))
        conn.execute(text("ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_type VARCHAR(64)"))

    # Seed admin user if missing
    admin_email = os.getenv("ADMIN_EMAIL", "daniel.cocu4@gmail.com")
    admin_password = os.getenv("ADMIN_PASSWORD", "123456789")
    from .auth import hash_password
    from .db import session_scope

    with session_scope() as db:
        existing = db.scalar(select(UserRow).where(UserRow.email == admin_email))
        if not existing:
            db.add(
                UserRow(
                    email=admin_email,
                    password_hash=hash_password(admin_password),
                    is_admin=True,
                )
            )
        # Ensure DB has an initial snapshot of the simulated twin
        sync_to_db(db)


@app.post("/api/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)) -> TokenResponse:
    # OAuth2PasswordRequestForm uses "username" field; we treat it as email
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token(subject=user.email)
    return TokenResponse(access_token=token)


@app.get("/api/auth/me", response_model=UserMe)
def me(user: UserRow = Depends(current_user)) -> UserMe:
    return UserMe(email=user.email, is_admin=user.is_admin)


@app.get("/api/devices", response_model=List[Device])
def get_devices(_: UserRow = Depends(current_user), db: Session = Depends(get_db)) -> List[Device]:
    rows = db.scalars(select(DeviceRow)).all()
    return [
        Device(
            id=r.id,
            ip=r.ip,
            mac=r.mac,
            hostname=r.hostname,
            vendor=r.vendor,
            device_type=r.device_type,
            state=r.state,  # pydantic will coerce to enum
            vulnerability_status=r.vulnerability_status,  # type: ignore[arg-type]
            last_seen=r.last_seen,
        )
        for r in rows
    ]


@app.get("/api/alerts", response_model=List[Alert])
def get_alerts(limit: int = 100, _: UserRow = Depends(current_user), db: Session = Depends(get_db)) -> List[Alert]:
    rows = db.scalars(select(AlertRow).order_by(AlertRow.ts.desc()).limit(limit)).all()
    return [
        Alert(
            id=r.id,
            ts=r.ts,
            level=r.level,  # type: ignore[arg-type]
            message=r.message,
            src_ip=r.src_ip,
            device_id=r.device_id,
        )
        for r in rows
    ]


@app.get("/api/risk", response_model=RiskScore)
def get_risk(_: UserRow = Depends(current_user), db: Session = Depends(get_db)) -> RiskScore:
    rows = db.scalars(select(DeviceRow)).all()
    danger = sum(1 for d in rows if d.state == "danger")
    unknown = sum(1 for d in rows if d.state == "unknown")
    vulnerable = sum(1 for d in rows if d.vulnerability_status == "vulnerable")
    score = min(100, danger * 35 + unknown * 10 + vulnerable * 8)
    label = "LOW"
    if score >= 70:
        label = "CRITICAL"
    elif score >= 40:
        label = "ELEVATED"
    elif score >= 20:
        label = "GUARDED"
    return RiskScore(score=score, label=label)


@app.post("/api/kill-switch", response_model=KillSwitchResponse)
def kill_switch(req: KillSwitchRequest, _: UserRow = Depends(current_user)) -> KillSwitchResponse:
    ok, action = STORE.block_ip(req.ip)
    return KillSwitchResponse(ok=ok, ip=req.ip, action=action)


@app.get("/api/devices/{device_id}/packets", response_model=List[Packet])
def get_device_packets(
    device_id: str,
    limit: int = 50,
    _: UserRow = Depends(current_user),
    db: Session = Depends(get_db),
) -> List[Packet]:
    rows = db.scalars(
        select(PacketRow).where(PacketRow.device_id == device_id).order_by(PacketRow.ts.desc()).limit(limit)
    ).all()
    return [
        Packet(
            id=r.id,
            ts=r.ts,
            device_id=r.device_id,
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            proto=r.proto,
            src_port=r.src_port,
            dst_port=r.dst_port,
            flags=r.flags,
            bytes=r.bytes,
        )
        for r in rows
    ]


@app.get("/api/devices/{device_id}/vulnerabilities", response_model=List[Vulnerability])
def get_device_vulns(
    device_id: str,
    _: UserRow = Depends(current_user),
    db: Session = Depends(get_db),
) -> List[Vulnerability]:
    rows = db.scalars(
        select(VulnerabilityRow).where(VulnerabilityRow.device_id == device_id).order_by(VulnerabilityRow.detected_at.desc())
    ).all()
    return [
        Vulnerability(
            id=r.id,
            detected_at=r.detected_at,
            device_id=r.device_id,
            cve=r.cve,
            severity=r.severity,  # type: ignore[arg-type]
            title=r.title,
            description=r.description,
            remediation=r.remediation,
        )
        for r in rows
    ]


@app.post("/api/devices/{device_id}/scan-vulnerabilities", response_model=List[Vulnerability])
def scan_device_vulns(
    device_id: str,
    _: UserRow = Depends(current_user),
    db: Session = Depends(get_db),
) -> List[Vulnerability]:
    dev = db.get(DeviceRow, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    # Demo scanner: derive findings from device type/vendor + recent packet ports
    ports = set()
    recent = db.scalars(select(PacketRow).where(PacketRow.device_id == device_id).order_by(PacketRow.ts.desc()).limit(200)).all()
    for p in recent:
        if p.dst_port:
            ports.add(int(p.dst_port))
        if p.src_port:
            ports.add(int(p.src_port))

    findings: list[tuple[str, str, str, str, str]] = []  # (cve, sev, title, desc, fix)
    v = (dev.vendor or "").lower()
    t = (dev.device_type or "unknown").lower()

    if 22 in ports:
        findings.append(
            (
                "CVE-2018-15473",
                "medium",
                "OpenSSH User Enumeration",
                "SSH service may allow username enumeration if misconfigured/outdated.",
                "Update OpenSSH and disable verbose auth errors; restrict SSH to trusted IPs.",
            )
        )
    if 80 in ports:
        findings.append(
            (
                "CVE-2021-41773",
                "high",
                "Apache Path Traversal",
                "HTTP service may be vulnerable to path traversal when running certain Apache versions.",
                "Patch Apache to a fixed version; place behind reverse proxy/WAF.",
            )
        )
    if 1883 in ports:
        findings.append(
            (
                "CVE-2020-13849",
                "high",
                "MQTT Broker Exposure",
                "MQTT on 1883 is often unauthenticated; can leak telemetry or allow publish/subscribe abuse.",
                "Enable authentication/TLS; restrict broker to LAN/VPN; rotate credentials.",
            )
        )

    if "tuya" in v or t == "iot":
        findings.append(
            (
                "CVE-2023-45866",
                "high",
                "IoT BLE/Pairing Weakness (class)",
                "Many IoT devices ship with weak pairing/default credentials or insecure BLE pairing flows.",
                "Change defaults; update firmware; isolate IoT VLAN; disable UPnP.",
            )
        )
    if "apple" in v and t == "phone":
        findings.append(
            (
                "CVE-2023-41064",
                "critical",
                "Potential mobile RCE chain (class)",
                "Mobile devices require prompt security updates; older OS versions are high-risk targets.",
                "Update iOS to latest; enforce MDM policies if available.",
            )
        )

    # Upsert: clear old scan results then insert new ones
    db.execute(text("DELETE FROM vulnerabilities WHERE device_id = :d"), {"d": device_id})
    now = datetime.now(timezone.utc)
    for cve, sev, title, desc, fix in findings:
        db.add(
            VulnerabilityRow(
                id=str(uuid.uuid4()),
                detected_at=now,
                device_id=device_id,
                cve=cve,
                severity=sev,
                title=title,
                description=desc,
                remediation=fix,
            )
        )

    dev.vulnerability_status = "vulnerable" if findings else "patched"

    db.flush()
    return get_device_vulns(device_id=device_id, db=db, _=_)  # type: ignore[arg-type]


def snapshot_payload() -> Dict[str, Any]:
    with session_scope() as db:
        # Ensure DB mirrors simulated state
        sync_to_db(db)

        device_rows = db.scalars(select(DeviceRow)).all()
        alert_rows = db.scalars(select(AlertRow).order_by(AlertRow.ts.desc()).limit(50)).all()

        danger = sum(1 for d in device_rows if d.state == "danger")
        unknown = sum(1 for d in device_rows if d.state == "unknown")
        vulnerable = sum(1 for d in device_rows if d.vulnerability_status == "vulnerable")
        score = min(100, danger * 35 + unknown * 10 + vulnerable * 8)
        label = "LOW"
        if score >= 70:
            label = "CRITICAL"
        elif score >= 40:
            label = "ELEVATED"
        elif score >= 20:
            label = "GUARDED"

        return {
            "ts": asyncio.get_event_loop().time(),
            "devices": [
                Device(
                    id=r.id,
                    ip=r.ip,
                    mac=r.mac,
                    hostname=r.hostname,
                    state=r.state,
                    vulnerability_status=r.vulnerability_status,  # type: ignore[arg-type]
                    last_seen=r.last_seen,
                ).model_dump()
                for r in device_rows
            ],
            "risk": RiskScore(score=score, label=label).model_dump(),
            "alerts": [
                Alert(
                    id=r.id,
                    ts=r.ts,
                    level=r.level,  # type: ignore[arg-type]
                    message=r.message,
                    src_ip=r.src_ip,
                    device_id=r.device_id,
                ).model_dump()
                for r in alert_rows
            ],
            "blocked_ips": STORE.blocked_ips(),
        }


@app.websocket("/ws")
async def ws_stream(ws: WebSocket) -> None:
    # authenticate via query param token (browser WebSocket can't easily set headers)
    token = token_from_ws_query(ws)
    if not token:
        await ws.close(code=4401)
        return
    try:
        from jose import jwt as _jwt

        payload = _jwt.decode(token, jwt_secret(), algorithms=["HS256"])
        if not payload.get("sub"):
            raise ValueError("no sub")
    except Exception:
        await ws.close(code=4401)
        return

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

