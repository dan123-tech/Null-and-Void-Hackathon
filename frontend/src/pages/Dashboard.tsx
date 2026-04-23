import { useEffect, useMemo, useState } from 'react'

import { AlertLog } from '../components/AlertLog'
import { DeviceSidebar } from '../components/DeviceSidebar'
import { DeviceTable } from '../components/DeviceTable'
import { RiskGauge } from '../components/RiskGauge'
import { Topology } from '../components/Topology'
import { connectSnapshotWS, fetchAlerts, fetchDevices, fetchRisk, killSwitch } from '../lib/api'
import { getToken } from '../lib/auth'
import type { Device, Snapshot } from '../lib/types'

export function DashboardPage() {
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

      <main className="grid">
        <section className="leftRail">
          <RiskGauge score={risk.score} label={risk.label} />
          <AlertLog alerts={alerts} />
        </section>

        <section className="center">
          <Topology devices={devices} selectedId={selectedId} onSelect={setSelectedId} />
          <DeviceTable devices={devices} onSelect={(id) => setSelectedId(id)} />
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
              <div className="muted">
                Select a node to view IP/MAC, type/vendor, vulnerability status, and packets.
              </div>
            </div>
          )}
        </section>
      </main>
    </>
  )
}

