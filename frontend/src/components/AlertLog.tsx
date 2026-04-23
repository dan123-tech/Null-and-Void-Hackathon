import type { Alert } from '../lib/types'

function formatTs(iso: string) {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleTimeString()
}

export function AlertLog({ alerts }: { alerts: Alert[] }) {
  return (
    <div className="panel">
      <div className="panelHeader">
        <div className="panelTitle">ALERT LOG</div>
      </div>
      <div className="alertList" role="log" aria-label="Alert log">
        {alerts.length === 0 ? (
          <div className="muted">No events yet.</div>
        ) : (
          alerts.map((a) => (
            <div key={a.id} className={`alertItem alert-${a.level}`}>
              <div className="alertMeta">
                <span className="alertTs">{formatTs(a.ts)}</span>
                <span className="alertLvl">{a.level.toUpperCase()}</span>
              </div>
              <div className="alertMsg">{a.message}</div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

