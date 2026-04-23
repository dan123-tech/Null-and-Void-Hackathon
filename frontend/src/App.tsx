import './App.css'
import { useEffect, useMemo, useState } from 'react'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { AlertLog } from './components/AlertLog'
import { DeviceSidebar } from './components/DeviceSidebar'
import { RiskGauge } from './components/RiskGauge'
import { Topology } from './components/Topology'
import { connectSnapshotWS, fetchAlerts, fetchDevices, fetchRisk, killSwitch } from './lib/api'
import { clearToken, getToken } from './lib/auth'
import { LoginPage } from './pages/Login'
import type { Device, Snapshot } from './lib/types'

function App() {
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

  // Prefer WebSockets; fall back to 2s polling if WS fails.
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
      () => {
        setConnectionState('degraded')
      },
    )
    const failover = window.setTimeout(() => {
      if (connectionState !== 'live') {
        try {
          ws.close()
        } catch {
          // ignore
        }
        setMode('poll')
        setConnectionState('degraded')
      }
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
      } catch {
        // keep trying
      }
    }

    tick()
    const id = window.setInterval(tick, 2000)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [mode])

  const onKillSwitch = async (ip: string) => {
    await killSwitch(ip)
  }

  const Dashboard = (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brandMark" aria-hidden="true" />
          <div>
            <div className="brandTitle">CYBER-SENTINEL</div>
            <div className="brandSub">Digital Twin Cybersecurity Command Center</div>
          </div>
        </div>
        <div className="status">
          <button
            className="iconBtn"
            onClick={() => {
              clearToken()
              nav('/login')
            }}
          >
            Logout
          </button>
          <span className={`dot dot-${connectionState}`} />
          <span className="mono small">
            {connectionState === 'live' ? 'LIVE' : connectionState === 'degraded' ? 'DEGRADED' : 'CONNECTING'} ·{' '}
            {mode.toUpperCase()}
          </span>
        </div>
      </header>

      <main className="grid">
        <section className="leftRail">
          <RiskGauge score={risk.score} label={risk.label} />
          <AlertLog alerts={alerts} />
        </section>

        <section className="center">
          <Topology devices={devices} selectedId={selectedId} onSelect={setSelectedId} />
        </section>

        <section className="rightRail">
          {selectedDevice ? (
            <DeviceSidebar
              device={selectedDevice}
              onClose={() => setSelectedId(null)}
              onKillSwitch={onKillSwitch}
              killSwitchEnabled={selectedDevice.state === 'danger'}
            />
          ) : (
            <div className="panel emptyState">
              <div className="panelHeader">
                <div className="panelTitle">INSPECTOR</div>
              </div>
              <div className="muted">Select a node to view IP/MAC and vulnerability status.</div>
            </div>
          )}
        </section>
      </main>
    </div>
  )

  const RequireAuth = ({ children }: { children: React.ReactNode }) => {
    return getToken() ? <>{children}</> : <Navigate to="/login" replace />
  }

  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/dashboard"
        element={
          <RequireAuth>
            {Dashboard}
          </RequireAuth>
        }
      />
    </Routes>
  )
}

export default App
