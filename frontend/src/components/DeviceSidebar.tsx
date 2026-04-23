import { useEffect, useState } from 'react'
import { fetchDevicePackets } from '../lib/api'
import type { Device, Packet } from '../lib/types'

function fmtTs(iso: string) {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString()
}

export function DeviceSidebar({
  device,
  onClose,
  onKillSwitch,
  killSwitchEnabled,
}: {
  device: Device
  onClose: () => void
  onKillSwitch: (ip: string) => void
  killSwitchEnabled: boolean
}) {
  const [packets, setPackets] = useState<Packet[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    fetchDevicePackets(device.id, 50)
      .then((p) => {
        if (!cancelled) setPackets(p)
      })
      .catch(() => {
        if (!cancelled) setPackets([])
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [device.id])

  return (
    <aside className="sidebar">
      <div className="sidebarHeader">
        <div>
          <div className="sidebarTitle">DEVICE DETAILS</div>
          <div className="sidebarSub">{device.hostname || device.ip}</div>
        </div>
        <button className="iconBtn" onClick={onClose} aria-label="Close sidebar">
          ✕
        </button>
      </div>

      <div className="kv">
        <div className="k">IP</div>
        <div className="v mono">{device.ip}</div>
        <div className="k">MAC</div>
        <div className="v mono">{device.mac}</div>
        <div className="k">STATE</div>
        <div className={`v pill pill-${device.state}`}>{device.state.toUpperCase()}</div>
        <div className="k">VULNERABILITY</div>
        <div className={`v pill pill-vuln-${device.vulnerability_status}`}>
          {device.vulnerability_status.toUpperCase()}
        </div>
      </div>

      <div className="panel" style={{ margin: '0 14px 14px' }}>
        <div className="panelHeader">
          <div className="panelTitle">RECENT PACKETS</div>
          <div className="panelHint">{loading ? 'Loading…' : `${packets.length}`}</div>
        </div>
        <div className="tableWrap">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Proto</th>
                <th>Src</th>
                <th>Dst</th>
                <th>Bytes</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((p) => (
                <tr key={p.id}>
                  <td className="mono">{fmtTs(p.ts)}</td>
                  <td className="mono">
                    {p.proto}
                    {p.flags ? ` ${p.flags}` : ''}
                  </td>
                  <td className="mono">
                    {p.src_ip}
                    {p.src_port ? `:${p.src_port}` : ''}
                  </td>
                  <td className="mono">
                    {p.dst_ip}
                    {p.dst_port ? `:${p.dst_port}` : ''}
                  </td>
                  <td className="mono">{p.bytes}</td>
                </tr>
              ))}
              {!loading && packets.length === 0 ? (
                <tr>
                  <td colSpan={5} className="muted" style={{ padding: 12 }}>
                    No packets captured yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      {device.state === 'danger' ? (
        <div className="sidebarActions">
          <button
            className="dangerBtn"
            onClick={() => onKillSwitch(device.ip)}
            disabled={!killSwitchEnabled}
          >
            Kill Switch: Block IP
          </button>
          <div className="muted small">
            Sends a backend command to block this IP (demo action for now).
          </div>
        </div>
      ) : (
        <div className="muted small">Kill Switch is available only for flagged devices.</div>
      )}
    </aside>
  )
}

