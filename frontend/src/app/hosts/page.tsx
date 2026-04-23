'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'

import { SideMenu } from '../../components/SideMenu'
import { StateBadge } from '../../components/StateBadge'
import { ApiError, fetchMonitorHosts } from '../../lib/api'
import { getToken } from '../../lib/auth'
import type { MonitorHost } from '../../lib/types'

export default function HostsPage() {
  const router = useRouter()
  const [items, setItems] = useState<MonitorHost[]>([])
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (!getToken()) router.replace('/login')
  }, [router])

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const r = await fetchMonitorHosts()
        if (!cancelled) {
          setItems(r)
          setErr(null)
        }
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) router.replace('/login')
        if (!cancelled) setErr(e instanceof Error ? e.message : 'Failed to load hosts')
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
            <div className="panelTitle">HOSTS</div>
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
                    <th>Name</th>
                    <th>IP</th>
                    <th>MAC</th>
                    <th>Output</th>
                    <th>Last check</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((h) => (
                    <tr key={h.id} className="row">
                      <td>
                        <StateBadge state={h.state} />
                      </td>
                      <td>{h.name}</td>
                      <td className="mono">{h.ip}</td>
                      <td className="mono">{h.mac}</td>
                      <td className="muted">{h.output}</td>
                      <td className="mono small">{new Date(h.last_check).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                  {items.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="muted" style={{ padding: 12 }}>
                        No hosts yet.
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

