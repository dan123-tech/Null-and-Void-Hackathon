'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'

import { SideMenu } from '../../components/SideMenu'
import { StateBadge } from '../../components/StateBadge'
import { ApiError, fetchMonitorServices } from '../../lib/api'
import { getToken } from '../../lib/auth'
import type { MonitorService } from '../../lib/types'

export default function ServicesPage() {
  const router = useRouter()
  const [items, setItems] = useState<MonitorService[]>([])
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (!getToken()) router.replace('/login')
  }, [router])

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const r = await fetchMonitorServices()
        if (!cancelled) {
          setItems(r)
          setErr(null)
        }
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) router.replace('/login')
        if (!cancelled) setErr(e instanceof Error ? e.message : 'Failed to load services')
      }
    }
    tick()
    const id = window.setInterval(tick, 3000)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [router])

  return (
    <div className="shell">
      <SideMenu />
      <div style={{ minWidth: 0, padding: 18 }}>
        <div className="panel system">
          <div className="panelHeader">
            <div className="panelTitle">SERVICES</div>
            <div className="panelHint">{items.length} total</div>
          </div>
          {err ? (
            <div style={{ padding: 14 }} className="muted">
              {err}
            </div>
          ) : (
            <div className="tableWrap" style={{ maxHeight: 'calc(100svh - 140px)' }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>State</th>
                    <th>Host</th>
                    <th>Service</th>
                    <th>Output</th>
                    <th>Last check</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((s) => (
                    <tr key={s.id} className="row">
                      <td>
                        <StateBadge state={s.state} />
                      </td>
                      <td>{s.host_name}</td>
                      <td className="mono">{s.name}</td>
                      <td className="muted">{s.output}</td>
                      <td className="mono small">{new Date(s.last_check).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                  {items.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="muted" style={{ padding: 12 }}>
                        No services yet.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

