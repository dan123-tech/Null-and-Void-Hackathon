from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class DeviceState(str, Enum):
    healthy = "healthy"
    unknown = "unknown"
    danger = "danger"


class Device(BaseModel):
    id: str
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    state: DeviceState = DeviceState.unknown
    vulnerability_status: Literal["unknown", "patched", "vulnerable"] = "unknown"
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class Alert(BaseModel):
    id: str
    ts: datetime = Field(default_factory=datetime.utcnow)
    level: Literal["info", "warning", "critical"] = "info"
    message: str
    src_ip: Optional[str] = None
    device_id: Optional[str] = None


class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    label: str


class KillSwitchRequest(BaseModel):
    ip: str


class KillSwitchResponse(BaseModel):
    ok: bool
    ip: str
    action: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserMe(BaseModel):
    email: str
    is_admin: bool


class Packet(BaseModel):
    id: str
    ts: datetime
    device_id: str
    src_ip: str
    dst_ip: str
    proto: str
    src_port: int | None = None
    dst_port: int | None = None
    flags: str | None = None
    bytes: int

