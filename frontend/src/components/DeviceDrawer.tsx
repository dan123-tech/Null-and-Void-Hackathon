'use client'

import { useEffect, useMemo, useState } from 'react'

import { fetchDevicePorts, fetchDeviceVulnerabilities, isolateDevice, scanDevicePorts, scanDeviceVulnerabilities } from '../lib/api'
import type { Device, Vulnerability } from '../lib/types'

function severityWeight(s: Vulnerability['severity']) {
  if (s === 'critical') return 30
  if (s === 'high') return 18
  if (s === 'medium') return 10
  return 4
}

function healthFromVulns(vulns: Vulnerability[]) {
  const penalty = vulns.reduce((acc, v) => acc + severityWeight(v.severity), 0)
  return Math.max(0, Math.min(100, 100 - penalty))
}

export function DeviceDrawer({
  device,
  open,
  onClose,
}: {
  device: Device | null
  open: boolean
  onClose: () => void
}) {
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [ports, setPorts] = useState<{ port: number; proto: string; service?: string | null; scanned_at: string }[]>([])
  const [busy, setBusy] = useState<'scanV' | 'scanP' | 'iso' | null>(null)

  useEffect(() => {
    if (!device || !open) return
    fetchDeviceVulnerabilities(device.id).then(setVulns).catch(() => setVulns([]))
    fetchDevicePorts(device.id).then(setPorts).catch(() => setPorts([]))
  }, [device?.id, open])

  const health = useMemo(() => healthFromVulns(vulns), [vulns])
  const healthColor = health > 70 ? 'var(--cyan)' : health > 35 ? 'var(--amber)' : 'var(--red)'

  if (!device) return null

  return (
    <div className={`drawerOverlay ${open ? 'open' : ''}`} onMouseDown={onClose}>
      <div className={`drawer ${open ? 'open' : ''}`} onMouseDown={(e) => e.stopPropagation()}>
        <div className="drawerHeader">
          <div>
            <div className="panelTitle">DEVICE</div>
            <div className="drawerTitle">{device.hostname || device.ip}</div>
            <div className="muted small">
              {device.vendor || 'Unknown vendor'} · {(device.device_type || 'unknown').toUpperCase()}
            </div>
          </div>
          <button className="iconBtn" onClick={onClose} aria-label="Close drawer">
            ✕
          </button>
        </div>

        <div className="drawerBody">
          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panelHeader">
              <div className="panelTitle">IDENTITY</div>
            </div>
            <div className="kv">
              <div className="k">IP</div>
              <div className="v mono">{device.ip}</div>
              <div className="k">MAC</div>
              <div className="v mono">{device.mac}</div>
            </div>
          </div>

          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panelHeader">
              <div className="panelTitle">HEALTH</div>
              <div className="panelHint mono">{health}/100</div>
            </div>
            <div style={{ padding: 14 }}>
              <div className="healthTrack">
                <div className="healthFill" style={{ width: `${health}%`, background: healthColor }} />
              </div>
              <div className="muted small" style={{ marginTop: 8 }}>
                Based on vulnerability severity findings.
              </div>
            </div>
          </div>

          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panelHeader">
              <div className="panelTitle">ACTIVE PORTS</div>
              <button
                className="iconBtn"
                style={{ width: 120 }}
                disabled={busy !== null}
                onClick={async () => {
                  setBusy('scanP')
                  try {
                    const r = await scanDevicePorts(device.id)
                    setPorts(r)
                  } finally {
                    setBusy(null)
                  }
                }}
              >
                {busy === 'scanP' ? 'Scanning…' : 'Scan (Nmap)'}
              </button>
            </div>
            <div style={{ padding: '10px 14px' }}>
              {ports.length === 0 ? (
                <div className="muted">No port scan results yet.</div>
              ) : (
                <div className="portsGrid">
                  {ports.map((p) => (
                    <div key={`${p.proto}-${p.port}`} className="pill mono">
                      {p.port}/{p.proto}
                      {p.service ? ` · ${p.service}` : ''}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="panelHeader">
              <div className="panelTitle">SECURITY ACTIONS</div>
            </div>
            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <button
                className="dangerBtn"
                disabled={busy !== null}
                onClick={async () => {
                  setBusy('iso')
                  try {
                    await isolateDevice(device.id)
                  } finally {
                    setBusy(null)
                  }
                }}
              >
                {busy === 'iso' ? 'Isolating…' : 'Isolate Device'}
              </button>
              <div className="muted small">
                Applies iptables rules on the Raspberry Pi to block this device (requires NET_ADMIN and host networking/privileged configuration).
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panelHeader">
              <div className="panelTitle">VULNERABILITIES</div>
              <button
                className="iconBtn"
                style={{ width: 160 }}
                disabled={busy !== null}
                onClick={async () => {
                  setBusy('scanV')
                  try {
                    const r = await scanDeviceVulnerabilities(device.id)
                    setVulns(r)
                  } finally {
                    setBusy(null)
                  }
                }}
              >
                {busy === 'scanV' ? 'Scanning…' : 'Scan vulnerabilities'}
              </button>
            </div>
            <div style={{ padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {vulns.length === 0 ? (
                <div className="muted">No findings yet.</div>
              ) : (
                vulns.map((v) => (
                  <div
                    key={v.id}
                    className={`alertItem alert-${
                      v.severity === 'critical' || v.severity === 'high'
                        ? 'critical'
                        : v.severity === 'medium'
                          ? 'warning'
                          : 'info'
                    }`}
                  >
                    <div className="alertMeta">
                      <span className="alertTs mono">{v.cve}</span>
                      <span className="alertLvl">{v.severity.toUpperCase()}</span>
                    </div>
                    <div className="alertMsg">
                      <div style={{ fontWeight: 600, marginBottom: 6 }}>{v.title}</div>
                      <div className="muted small" style={{ marginBottom: 6 }}>
                        {v.description}
                      </div>
                      <div className="small">
                        <span className="mono">Fix:</span> {v.remediation}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

