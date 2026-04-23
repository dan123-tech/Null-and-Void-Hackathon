import type { Alert, Device, Packet, RiskScore, Snapshot, Vulnerability } from './types'
import { getToken } from './auth'

function authHeaders() {
  const t = getToken()
  return t ? ({ Authorization: `Bearer ${t}` } as Record<string, string>) : ({} as Record<string, string>)
}

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

export async function fetchDevices(): Promise<Device[]> {
  const r = await fetch('/api/devices', { headers: authHeaders() })
  if (!r.ok) throw new ApiError(`devices: ${r.status}`, r.status)
  return (await r.json()) as Device[]
}

export async function fetchAlerts(limit = 100): Promise<Alert[]> {
  const r = await fetch(`/api/alerts?limit=${encodeURIComponent(String(limit))}`, { headers: authHeaders() })
  if (!r.ok) throw new ApiError(`alerts: ${r.status}`, r.status)
  return (await r.json()) as Alert[]
}

export async function fetchRisk(): Promise<RiskScore> {
  const r = await fetch('/api/risk', { headers: authHeaders() })
  if (!r.ok) throw new ApiError(`risk: ${r.status}`, r.status)
  return (await r.json()) as RiskScore
}

export async function killSwitch(ip: string): Promise<{ ok: boolean; ip: string; action: string }> {
  const r = await fetch('/api/kill-switch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify({ ip }),
  })
  if (!r.ok) throw new ApiError(`kill-switch: ${r.status}`, r.status)
  return (await r.json()) as { ok: boolean; ip: string; action: string }
}

export async function fetchDevicePackets(deviceId: string, limit = 50): Promise<Packet[]> {
  const r = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/packets?limit=${encodeURIComponent(String(limit))}`, {
    headers: authHeaders(),
  })
  if (!r.ok) throw new ApiError(`packets: ${r.status}`, r.status)
  return (await r.json()) as Packet[]
}

export async function fetchDeviceVulnerabilities(deviceId: string): Promise<Vulnerability[]> {
  const r = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/vulnerabilities`, { headers: authHeaders() })
  if (!r.ok) throw new ApiError(`vulns: ${r.status}`, r.status)
  return (await r.json()) as Vulnerability[]
}

export async function scanDeviceVulnerabilities(deviceId: string): Promise<Vulnerability[]> {
  const r = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/scan-vulnerabilities`, {
    method: 'POST',
    headers: authHeaders(),
  })
  if (!r.ok) throw new ApiError(`scan-vulns: ${r.status}`, r.status)
  return (await r.json()) as Vulnerability[]
}

export async function fetchDevicePorts(deviceId: string) {
  const r = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/ports`, { headers: authHeaders() })
  if (!r.ok) throw new ApiError(`ports: ${r.status}`, r.status)
  return (await r.json()) as { port: number; proto: string; service?: string | null; scanned_at: string }[]
}

export async function scanDevicePorts(deviceId: string) {
  const r = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/scan-ports`, { method: 'POST', headers: authHeaders() })
  if (!r.ok) throw new ApiError(`scan-ports: ${r.status}`, r.status)
  return (await r.json()) as { port: number; proto: string; service?: string | null; scanned_at: string }[]
}

export async function isolateDevice(deviceId: string) {
  const r = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/isolate`, { method: 'POST', headers: authHeaders() })
  if (!r.ok) throw new ApiError(`isolate: ${r.status}`, r.status)
  return (await r.json()) as { ok: string; device_id: string; action: string; ip: string; mac: string }
}

export function connectSnapshotWS(onSnapshot: (s: Snapshot) => void, onError?: (e: Event) => void) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const wsUrl = `${proto}://${window.location.host}/ws${token ? `?token=${encodeURIComponent(token)}` : ''}`
  const ws = new WebSocket(wsUrl)

  ws.onmessage = (ev) => {
    try {
      const msg = JSON.parse(ev.data as string) as { type: string; data: Snapshot }
      if (msg?.type === 'snapshot' && msg.data) onSnapshot(msg.data)
    } catch {
      // ignore malformed messages
    }
  }

  ws.onerror = (e) => onError?.(e)
  return ws
}

