import type { Device } from '../lib/types'

export function DeviceTable({
  devices,
  onSelect,
}: {
  devices: Device[]
  onSelect: (id: string) => void
}) {
  return (
    <div className="panel">
      <div className="panelHeader">
        <div className="panelTitle">DEVICES</div>
        <div className="panelHint">{devices.length} discovered</div>
      </div>
      <div className="tableWrap">
        <table className="table">
          <thead>
            <tr>
              <th>State</th>
              <th>IP</th>
              <th>MAC</th>
              <th>Type</th>
              <th>Vendor</th>
              <th>Vuln</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.id} onClick={() => onSelect(d.id)} className="row">
                <td>
                  <span className={`pill pill-${d.state}`}>{d.state.toUpperCase()}</span>
                </td>
                <td className="mono">{d.ip}</td>
                <td className="mono">{d.mac}</td>
                <td className="mono">{(d.device_type || 'unknown').toUpperCase()}</td>
                <td>{d.vendor || '—'}</td>
                <td>
                  <span className={`pill pill-vuln-${d.vulnerability_status}`}>
                    {d.vulnerability_status.toUpperCase()}
                  </span>
                </td>
              </tr>
            ))}
            {devices.length === 0 ? (
              <tr>
                <td colSpan={6} className="muted" style={{ padding: 12 }}>
                  No devices yet.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>
    </div>
  )
}

