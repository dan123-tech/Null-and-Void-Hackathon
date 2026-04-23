import type { Device } from '../lib/types'

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

