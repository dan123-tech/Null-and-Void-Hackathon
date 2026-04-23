import type { Alert, Device, RiskScore, Snapshot } from './types'

export async function fetchDevices(): Promise<Device[]> {
  const r = await fetch('/api/devices')
  if (!r.ok) throw new Error(`devices: ${r.status}`)
  return (await r.json()) as Device[]
}

export async function fetchAlerts(limit = 100): Promise<Alert[]> {
  const r = await fetch(`/api/alerts?limit=${encodeURIComponent(String(limit))}`)
  if (!r.ok) throw new Error(`alerts: ${r.status}`)
  return (await r.json()) as Alert[]
}

export async function fetchRisk(): Promise<RiskScore> {
  const r = await fetch('/api/risk')
  if (!r.ok) throw new Error(`risk: ${r.status}`)
  return (await r.json()) as RiskScore
}

export async function killSwitch(ip: string): Promise<{ ok: boolean; ip: string; action: string }> {
  const r = await fetch('/api/kill-switch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip }),
  })
  if (!r.ok) throw new Error(`kill-switch: ${r.status}`)
  return (await r.json()) as { ok: boolean; ip: string; action: string }
}

export function connectSnapshotWS(onSnapshot: (s: Snapshot) => void, onError?: (e: Event) => void) {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  const wsUrl = `${proto}://${window.location.host}/ws`
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

