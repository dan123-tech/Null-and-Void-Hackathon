import { useEffect, useMemo, useState } from 'react'

import { AlertLog } from '../components/AlertLog'
import { DeviceDrawer } from '../components/DeviceDrawer'
import { DeviceTable } from '../components/DeviceTable'
import { RiskGauge } from '../components/RiskGauge'
import { Topology } from '../components/Topology'
import { ApiError, connectSnapshotWS, fetchAlerts, fetchDevices, fetchRisk } from '../lib/api'
import { clearToken, getToken } from '../lib/auth'
import { useNavigate } from 'react-router-dom'
import type { Device, Snapshot } from '../lib/types'

export function DashboardPage() {
  const nav = useNavigate()
  const [devices, setDevices] = useState<Device[]>([])
  const [alerts, setAlerts] = useState<Snapshot['alerts']>([])
  const [risk, setRisk] = useState<Snapshot['risk']>({ score: 0, label: 'LOW' })
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [mode, setMode] = useState<'ws' | 'poll'>('ws')
  const [connectionState, setConnectionState] = useState<'connecting' | 'live' | 'degraded'>('connecting')

  const selectedDevice = useMemo(
    () => (selectedId ? devices.find((d) => d.id === selectedId) ?? null : null),
    [devices, selectedId],
  )

  const forceReauth = () => {
    clearToken()
    nav('/login', { replace: true })
  }

  useEffect(() => {
    if (!getToken()) return
    setConnectionState('connecting')
    const ws = connectSnapshotWS(
      (snap) => {
        setDevices(snap.devices)
        setAlerts(snap.alerts)
        setRisk(snap.risk)
        setMode('ws')
        setConnectionState('live')
      },
      () => setConnectionState('degraded'),
    )

    ws.onclose = (ev) => {
      // 4401 used by backend for WS auth failure
      if (ev.code === 4401) forceReauth()
      setConnectionState('degraded')
      setMode('poll')
    }

    const failover = window.setTimeout(() => {
      try {
        if (ws.readyState !== WebSocket.OPEN) ws.close()
      } catch {
        // ignore
      }
      setMode('poll')
      setConnectionState('degraded')
    }, 2500)

    return () => {
      window.clearTimeout(failover)
      try {
        ws.close()
      } catch {
        // ignore
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (mode !== 'poll') return
    let cancelled = false

    const tick = async () => {
      try {
        const [d, a, r] = await Promise.all([fetchDevices(), fetchAlerts(50), fetchRisk()])
        if (cancelled) return
        setDevices(d)
        setAlerts(a)
        setRisk(r)
      } catch (e) {
        // keep trying, but if auth fails, force re-login
        if (e instanceof ApiError && e.status === 401) forceReauth()
      }
    }

    tick()
    const id = window.setInterval(tick, 2000)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [mode])

  // Always do an immediate fetch to avoid "blank" UI if WS is slow.
  useEffect(() => {
    ;(async () => {
      try {
        const [d, a, r] = await Promise.all([fetchDevices(), fetchAlerts(50), fetchRisk()])
        setDevices(d)
        setAlerts(a)
        setRisk(r)
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) forceReauth()
      }
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <>
      <header className="topbar">
        <div className="status">
          <span className={`dot dot-${connectionState}`} />
          <span className="mono small">
            {connectionState === 'live' ? 'LIVE' : connectionState === 'degraded' ? 'DEGRADED' : 'CONNECTING'} ·{' '}
            {mode.toUpperCase()}
          </span>
        </div>
      </header>

      <main className="bento">
        <section className="bentoGraph panel system">
          <div className="panelHeader">
            <div className="panelTitle">DIGITAL TWIN</div>
            <div className="panelHint">Click a device node to inspect.</div>
          </div>
          <div className="bentoGraphCanvas">
            <Topology devices={devices} selectedId={selectedId} onSelect={setSelectedId} />
          </div>
        </section>

        <aside className="bentoAlerts panel alert">
          <AlertLog alerts={alerts} />
        </aside>

        <section className="bentoAnalytics panel system">
          <div className="bentoAnalyticsGrid">
            <div className="panel system" style={{ overflow: 'hidden' }}>
              <RiskGauge score={risk.score} label={risk.label} />
            </div>
            <div className="panel system" style={{ overflow: 'hidden' }}>
              <DeviceTable devices={devices} onSelect={(id) => setSelectedId(id)} />
            </div>
          </div>
        </section>
      </main>

      <DeviceDrawer device={selectedDevice} open={Boolean(selectedDevice)} onClose={() => setSelectedId(null)} />
    </>
  )
}

