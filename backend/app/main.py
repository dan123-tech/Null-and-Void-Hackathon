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

import re
import subprocess

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
    OpenPort,
    MonitorEvent,
    MonitorHost,
    MonitorService,
    ServiceState,
)
from .orm import AlertRow, DeviceRow, PacketRow, UserRow, VulnerabilityRow, PortRow, MonitorEventRow, MonitorStatusRow
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
        conn.execute(text("CREATE TABLE IF NOT EXISTS ports (id VARCHAR(64) PRIMARY KEY, scanned_at TIMESTAMPTZ NOT NULL, device_id VARCHAR(64) NOT NULL, port INTEGER NOT NULL, proto VARCHAR(8) NOT NULL, service VARCHAR(64))"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_ports_device_id ON ports(device_id)"))

        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS monitor_status (id VARCHAR(128) PRIMARY KEY, object_type VARCHAR(16) NOT NULL, host_id VARCHAR(64) NOT NULL, service_name VARCHAR(64), state VARCHAR(16) NOT NULL, output TEXT NOT NULL, last_check TIMESTAMPTZ NOT NULL, last_state_change TIMESTAMPTZ NOT NULL, acknowledged BOOLEAN NOT NULL DEFAULT FALSE)"
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_monitor_status_object_type ON monitor_status(object_type)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_monitor_status_host_id ON monitor_status(host_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_monitor_status_state ON monitor_status(state)"))

        conn.execute(
            text(
                "CREATE TABLE IF NOT EXISTS monitor_events (id VARCHAR(64) PRIMARY KEY, ts TIMESTAMPTZ NOT NULL, object_type VARCHAR(16) NOT NULL, object_id VARCHAR(128) NOT NULL, host_id VARCHAR(64), service_name VARCHAR(64), state VARCHAR(16) NOT NULL, message TEXT NOT NULL)"
            )
        )
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_monitor_events_ts ON monitor_events(ts)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_monitor_events_object_id ON monitor_events(object_id)"))

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

    # Start a small check scheduler to keep an Icinga-like status model updated.
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(_monitor_loop())
    except Exception:
        # If we can't start the background loop (e.g. during sync startup), the UI can still work via snapshot endpoints.
        pass


def _svc_id(host_id: str, name: str | None = None) -> str:
    return f"host:{host_id}" if not name else f"svc:{host_id}:{name}"


def _state_rank(s: str) -> int:
    if s == ServiceState.critical.value:
        return 3
    if s == ServiceState.warning.value:
        return 2
    if s == ServiceState.ok.value:
        return 1
    return 0


def _upsert_status(
    db: Session,
    object_type: str,
    host_id: str,
    service_name: str | None,
    state: ServiceState,
    output: str,
    now: datetime,
) -> None:
    oid = _svc_id(host_id, service_name)
    row = db.get(MonitorStatusRow, oid)
    if not row:
        db.add(
            MonitorStatusRow(
                id=oid,
                object_type=object_type,
                host_id=host_id,
                service_name=service_name,
                state=state.value,
                output=output,
                last_check=now,
                last_state_change=now,
                acknowledged=False,
            )
        )
        db.add(
            MonitorEventRow(
                id=str(uuid.uuid4()),
                ts=now,
                object_type=object_type,
                object_id=oid,
                host_id=host_id,
                service_name=service_name,
                state=state.value,
                message=output,
            )
        )
        return

    prev_state = row.state
    row.state = state.value
    row.output = output
    row.last_check = now
    if prev_state != state.value:
        row.last_state_change = now
        row.acknowledged = False
        db.add(
            MonitorEventRow(
                id=str(uuid.uuid4()),
                ts=now,
                object_type=object_type,
                object_id=oid,
                host_id=host_id,
                service_name=service_name,
                state=state.value,
                message=f"{prev_state} -> {state.value}: {output}",
            )
        )


def _evaluate_host(dev: DeviceRow, now: datetime) -> tuple[ServiceState, str]:
    # Freshness as a ping-like proxy: OK if seen recently; otherwise CRITICAL.
    age_s = max(0.0, (now - dev.last_seen).total_seconds())
    if age_s <= 15:
        return (ServiceState.ok, f"Reachable (last_seen {int(age_s)}s ago)")
    if age_s <= 60:
        return (ServiceState.warning, f"Stale (last_seen {int(age_s)}s ago)")
    return (ServiceState.critical, f"Unreachable (last_seen {int(age_s)}s ago)")


def _evaluate_service_ports(dev: DeviceRow, ports: list[PortRow]) -> tuple[ServiceState, str]:
    if not ports:
        return (ServiceState.unknown, "No port scan results")
    risky = {23, 2323, 445, 3389, 5900}
    open_ports = sorted({p.port for p in ports})
    risky_open = [p for p in open_ports if p in risky]
    if risky_open:
        return (ServiceState.warning, f"Risky ports open: {', '.join(map(str, risky_open))}")
    return (ServiceState.ok, f"Open ports: {', '.join(map(str, open_ports[:15]))}{'…' if len(open_ports) > 15 else ''}")


def _evaluate_service_vulns(dev: DeviceRow, vulns: list[VulnerabilityRow]) -> tuple[ServiceState, str]:
    if not vulns:
        if dev.vulnerability_status == "patched":
            return (ServiceState.ok, "No findings")
        return (ServiceState.unknown, "No vulnerability scan results")
    # Treat any critical/high as CRITICAL; medium as WARNING; otherwise WARNING.
    sev = {v.severity for v in vulns}
    if "critical" in sev or "high" in sev:
        return (ServiceState.critical, f"{len(vulns)} findings (high/critical present)")
    if "medium" in sev:
        return (ServiceState.warning, f"{len(vulns)} findings (medium)")
    return (ServiceState.warning, f"{len(vulns)} findings")


async def _monitor_loop() -> None:
    # Keep monitoring state updated every 10s. (Snapshot/websocket remains 2s.)
    await asyncio.sleep(1)
    while True:
        try:
            now = datetime.now(timezone.utc)
            with session_scope() as db:
                # Ensure DB mirrors simulated state so checks have fresh inputs.
                sync_to_db(db)

                devices = db.scalars(select(DeviceRow)).all()
                for dev in devices:
                    host_state, host_out = _evaluate_host(dev, now)
                    _upsert_status(db, "host", dev.id, None, host_state, host_out, now)

                    port_rows = db.scalars(select(PortRow).where(PortRow.device_id == dev.id)).all()
                    ports_state, ports_out = _evaluate_service_ports(dev, list(port_rows))
                    _upsert_status(db, "service", dev.id, "ports", ports_state, ports_out, now)

                    vuln_rows = db.scalars(select(VulnerabilityRow).where(VulnerabilityRow.device_id == dev.id)).all()
                    vulns_state, vulns_out = _evaluate_service_vulns(dev, list(vuln_rows))
                    _upsert_status(db, "service", dev.id, "vulns", vulns_state, vulns_out, now)
        except Exception:
            # Keep the loop resilient; errors will self-heal next tick.
            pass

        await asyncio.sleep(10)


@app.get("/api/monitor/hosts", response_model=List[MonitorHost])
def monitor_hosts(_: UserRow = Depends(current_user), db: Session = Depends(get_db)) -> List[MonitorHost]:
    # Join device rows with host status
    devices = {d.id: d for d in db.scalars(select(DeviceRow)).all()}
    rows = db.scalars(select(MonitorStatusRow).where(MonitorStatusRow.object_type == "host")).all()
    out: list[MonitorHost] = []
    for r in rows:
        d = devices.get(r.host_id)
        if not d:
            continue
        out.append(
            MonitorHost(
                id=r.host_id,
                name=d.hostname or d.ip,
                ip=d.ip,
                mac=d.mac,
                state=ServiceState(r.state),
                output=r.output,
                last_check=r.last_check,
                last_state_change=r.last_state_change,
                acknowledged=r.acknowledged,
            )
        )
    out.sort(key=lambda h: (-_state_rank(h.state.value), h.name))
    return out


@app.get("/api/monitor/services", response_model=List[MonitorService])
def monitor_services(_: UserRow = Depends(current_user), db: Session = Depends(get_db)) -> List[MonitorService]:
    devices = {d.id: d for d in db.scalars(select(DeviceRow)).all()}
    rows = db.scalars(select(MonitorStatusRow).where(MonitorStatusRow.object_type == "service")).all()
    out: list[MonitorService] = []
    for r in rows:
        d = devices.get(r.host_id)
        if not d or not r.service_name:
            continue
        out.append(
            MonitorService(
                id=r.id,
                host_id=r.host_id,
                host_name=d.hostname or d.ip,
                name=r.service_name,
                state=ServiceState(r.state),
                output=r.output,
                last_check=r.last_check,
                last_state_change=r.last_state_change,
                acknowledged=r.acknowledged,
            )
        )
    out.sort(key=lambda s: (-_state_rank(s.state.value), s.host_name, s.name))
    return out


@app.get("/api/monitor/problems", response_model=List[MonitorService])
def monitor_problems(_: UserRow = Depends(current_user), db: Session = Depends(get_db)) -> List[MonitorService]:
    # Problems = non-OK hosts/services, excluding acknowledged
    devices = {d.id: d for d in db.scalars(select(DeviceRow)).all()}
    rows = db.scalars(select(MonitorStatusRow).where(MonitorStatusRow.state != ServiceState.ok.value)).all()
    out: list[MonitorService] = []
    for r in rows:
        if r.acknowledged:
            continue
        d = devices.get(r.host_id)
        if not d:
            continue
        name = r.service_name or "host"
        out.append(
            MonitorService(
                id=r.id,
                host_id=r.host_id,
                host_name=d.hostname or d.ip,
                name=name,
                state=ServiceState(r.state),
                output=r.output,
                last_check=r.last_check,
                last_state_change=r.last_state_change,
                acknowledged=r.acknowledged,
            )
        )
    out.sort(key=lambda s: (-_state_rank(s.state.value), s.host_name, s.name))
    return out


@app.get("/api/monitor/history", response_model=List[MonitorEvent])
def monitor_history(limit: int = 200, _: UserRow = Depends(current_user), db: Session = Depends(get_db)) -> List[MonitorEvent]:
    rows = db.scalars(select(MonitorEventRow).order_by(MonitorEventRow.ts.desc()).limit(limit)).all()
    return [
        MonitorEvent(
            id=r.id,
            ts=r.ts,
            object_type=r.object_type,  # type: ignore[arg-type]
            object_id=r.object_id,
            host_id=r.host_id,
            service_name=r.service_name,
            state=ServiceState(r.state),
            message=r.message,
        )
        for r in rows
    ]


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


@app.get("/api/devices/{device_id}/ports", response_model=List[OpenPort])
def get_device_ports(
    device_id: str,
    _: UserRow = Depends(current_user),
    db: Session = Depends(get_db),
) -> List[OpenPort]:
    rows = db.scalars(select(PortRow).where(PortRow.device_id == device_id).order_by(PortRow.port.asc())).all()
    return [OpenPort(port=r.port, proto=r.proto, service=r.service, scanned_at=r.scanned_at) for r in rows]


def _run_nmap_ports(ip: str) -> list[tuple[int, str | None]]:
    """
    Fast scan: top 1000 TCP ports, parse open ports.
    """
    cmd = ["nmap", "-Pn", "--top-ports", "1000", "-sS", "-T4", ip]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    out = (p.stdout or "") + ("\n" + p.stderr if p.stderr else "")
    found: list[tuple[int, str | None]] = []
    for line in out.splitlines():
        # Example: 22/tcp open  ssh
        m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line.strip())
        if m:
            found.append((int(m.group(1)), m.group(2)))
    return found


@app.post("/api/devices/{device_id}/scan-ports", response_model=List[OpenPort])
def scan_device_ports(
    device_id: str,
    _: UserRow = Depends(current_user),
    db: Session = Depends(get_db),
) -> List[OpenPort]:
    dev = db.get(DeviceRow, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    if not dev.ip or dev.ip == "unknown":
        raise HTTPException(status_code=400, detail="Device has no IP")

    now = datetime.now(timezone.utc)
    results = _run_nmap_ports(dev.ip)

    db.execute(text("DELETE FROM ports WHERE device_id = :d"), {"d": device_id})
    for port, service in results:
        db.add(
            PortRow(
                id=str(uuid.uuid4()),
                scanned_at=now,
                device_id=device_id,
                port=port,
                proto="tcp",
                service=service,
            )
        )

    # Update device vulnerability status heuristically if risky ports exposed
    risky = {23, 2323, 3389, 5900, 445}
    if any(p in risky for p, _ in results):
        dev.vulnerability_status = "vulnerable"

    db.flush()
    return get_device_ports(device_id=device_id, db=db, _=_)  # type: ignore[arg-type]


@app.post("/api/devices/{device_id}/isolate")
def isolate_device(
    device_id: str,
    _: UserRow = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    dev = db.get(DeviceRow, device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")

    ip = dev.ip
    mac = dev.mac

    # NOTE: In Docker this affects the container network namespace unless run with host networking/privileged setup.
    rules = []
    if ip and ip != "unknown":
        rules.append(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        rules.append(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    if mac and mac != "unknown":
        rules.append(["iptables", "-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"])
        rules.append(["iptables", "-I", "FORWARD", "-m", "mac", "--mac-source", mac, "-j", "DROP"])

    for r in rules:
        subprocess.run(r, check=False, capture_output=True, text=True)

    return {"ok": "true", "device_id": device_id, "action": "isolate", "ip": ip, "mac": mac}


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


# Serve the built Next.js (static export) dashboard (for LAN users) when available.
#
# Next export (App Router) produces `<route>.html` files (e.g. `login.html`) at the export root,
# so we implement a small resolver that maps `/login` -> `login.html`.
#
# In Docker we run from:
# - backend code:    /app/app/main.py
# - frontend export: /app/frontend/out
_APP_ROOT = Path(__file__).resolve().parents[1]  # /app
_FRONTEND_DIST = _APP_ROOT / "frontend" / "out"

if _FRONTEND_DIST.exists():
    # Serve Next static assets.
    _NEXT_ASSETS = _FRONTEND_DIST / "_next"
    if _NEXT_ASSETS.exists():
        app.mount("/_next", StaticFiles(directory=str(_NEXT_ASSETS)), name="next-assets")  # type: ignore[name-defined]

    def _frontend_file(full_path: str) -> Path:
        p = (full_path or "").lstrip("/")
        if not p:
            return _FRONTEND_DIST / "index.html"

        direct = _FRONTEND_DIST / p
        if direct.exists() and direct.is_file():
            return direct

        # Map route-style paths to exported `<route>.html`
        if Path(p).suffix == "":
            html = _FRONTEND_DIST / f"{p}.html"
            if html.exists():
                return html

        # Fallback to root index (client-side redirect handles / -> /dashboard).
        return _FRONTEND_DIST / "index.html"

    @app.get("/{full_path:path}")
    def frontend(full_path: str) -> FileResponse:
        f = _frontend_file(full_path)
        return FileResponse(str(f))

