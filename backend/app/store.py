from __future__ import annotations

import random
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .models import Alert, Device, DeviceState, RiskScore
from .orm import AlertRow, DeviceRow


class InMemoryTwinStore:
    """
    Demo store for hackathon use.
    Replace with InfluxDB queries + your IDS pipeline later.
    """

    def __init__(self) -> None:
        self.guardian_id = "guardian"
        self._devices: Dict[str, Device] = {}
        self._alerts: List[Alert] = []
        self._blocked_ips: Dict[str, datetime] = {}
        self._seed()

    def _seed(self) -> None:
        now = datetime.utcnow()
        self._devices[self.guardian_id] = Device(
            id=self.guardian_id,
            ip="192.168.1.10",
            mac="B8:27:EB:AA:BB:CC",
            hostname="RaspberryPi5-Guardian",
            state=DeviceState.healthy,
            vulnerability_status="patched",
            last_seen=now,
        )
        for i in range(3, 8):
            dev_id = f"dev-{i}"
            self._devices[dev_id] = Device(
                id=dev_id,
                ip=f"192.168.1.{i}",
                mac=f"AA:BB:CC:DD:EE:{i:02d}",
                hostname=f"device-{i}",
                state=random.choice([DeviceState.healthy, DeviceState.unknown]),
                vulnerability_status=random.choice(["unknown", "patched", "vulnerable"]),
                last_seen=now - timedelta(seconds=random.randint(1, 40)),
            )

    def devices(self) -> List[Device]:
        return list(self._devices.values())

    def alerts(self, limit: int = 100) -> List[Alert]:
        return list(reversed(self._alerts[-limit:]))

    def blocked_ips(self) -> Dict[str, str]:
        return {ip: ts.isoformat() for ip, ts in self._blocked_ips.items()}

    def risk(self) -> RiskScore:
        danger = sum(1 for d in self._devices.values() if d.state == DeviceState.danger)
        unknown = sum(1 for d in self._devices.values() if d.state == DeviceState.unknown)
        vulnerable = sum(1 for d in self._devices.values() if d.vulnerability_status == "vulnerable")
        score = min(100, danger * 35 + unknown * 10 + vulnerable * 8)
        label = "LOW"
        if score >= 70:
            label = "CRITICAL"
        elif score >= 40:
            label = "ELEVATED"
        elif score >= 20:
            label = "GUARDED"
        return RiskScore(score=score, label=label)

    def upsert_alert(self, level: str, message: str, src_ip: str | None = None, device_id: str | None = None) -> Alert:
        alert = Alert(id=str(uuid.uuid4()), level=level, message=message, src_ip=src_ip, device_id=device_id)
        self._alerts.append(alert)
        return alert

    def block_ip(self, ip: str) -> Tuple[bool, str]:
        self._blocked_ips[ip] = datetime.utcnow()
        for d in self._devices.values():
            if d.ip == ip:
                d.state = DeviceState.danger
        self.upsert_alert("warning", f"Kill Switch activated: blocked {ip}", src_ip=ip)
        return True, "blocked_ip_demo"

    def tick(self) -> None:
        """
        Simulates network changes + IDS events for UI development.
        """
        now = datetime.utcnow()
        for d in self._devices.values():
            d.last_seen = now

        # Occasionally add a new device
        if random.random() < 0.08:
            last_octet = random.randint(20, 80)
            dev_id = f"new-{last_octet}"
            if dev_id not in self._devices:
                ip = f"192.168.1.{last_octet}"
                self._devices[dev_id] = Device(
                    id=dev_id,
                    ip=ip,
                    mac=f"DE:AD:BE:EF:{last_octet:02d}:01",
                    hostname=None,
                    state=DeviceState.unknown,
                    vulnerability_status="unknown",
                    last_seen=now,
                )
                self.upsert_alert("info", f"New Device Joined: {ip}", src_ip=ip, device_id=dev_id)

        # Occasionally mark a device as scanning/suspicious
        if random.random() < 0.12:
            candidates = [d for d in self._devices.values() if d.id != self.guardian_id]
            if candidates:
                d = random.choice(candidates)
                d.state = DeviceState.danger
                self.upsert_alert(
                    "critical",
                    f"Suspicious SYN scan detected from {d.ip}",
                    src_ip=d.ip,
                    device_id=d.id,
                )

        # Drift some danger devices back to unknown/healthy
        for d in self._devices.values():
            if d.state == DeviceState.danger and random.random() < 0.25:
                d.state = random.choice([DeviceState.unknown, DeviceState.healthy])

        # Keep alert list bounded
        if len(self._alerts) > 500:
            self._alerts = self._alerts[-400:]

        # Slow down the simulation slightly if called in tight loops
        time.sleep(0.01)


STORE = InMemoryTwinStore()


def sync_to_db(db: Session) -> None:
    """
    Mirror the in-memory demo state into Postgres so the UI reads from the DB.
    """
    now = datetime.now(timezone.utc)

    # Upsert devices
    for d in STORE.devices():
        row = db.get(DeviceRow, d.id)
        if not row:
            row = DeviceRow(
                id=d.id,
                ip=d.ip,
                mac=d.mac,
                hostname=d.hostname,
                state=d.state.value if isinstance(d.state, DeviceState) else str(d.state),
                vulnerability_status=d.vulnerability_status,
                last_seen=now,
            )
            db.add(row)
        else:
            row.ip = d.ip
            row.mac = d.mac
            row.hostname = d.hostname
            row.state = d.state.value if isinstance(d.state, DeviceState) else str(d.state)
            row.vulnerability_status = d.vulnerability_status
            row.last_seen = now

    # Append new alerts since last sync (bounded)
    existing_ids = set(db.scalars(select(AlertRow.id)).all())
    for a in STORE.alerts(limit=200):
        if a.id in existing_ids:
            continue
        db.add(
            AlertRow(
                id=a.id,
                ts=a.ts.replace(tzinfo=timezone.utc) if a.ts.tzinfo is None else a.ts,
                level=a.level,
                message=a.message,
                src_ip=a.src_ip,
                device_id=a.device_id,
            )
        )

    # Keep alerts bounded in DB
    alert_rows = db.scalars(select(AlertRow).order_by(AlertRow.ts.desc())).all()
    if len(alert_rows) > 600:
        to_delete = alert_rows[600:]
        for r in to_delete:
            db.delete(r)

