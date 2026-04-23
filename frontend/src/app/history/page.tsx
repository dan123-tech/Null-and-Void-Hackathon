'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'

import { SideMenu } from '../../components/SideMenu'
import { StateBadge } from '../../components/StateBadge'
import { ApiError, fetchMonitorHistory } from '../../lib/api'
import { getToken } from '../../lib/auth'
import type { MonitorEvent } from '../../lib/types'

export default function HistoryPage() {
  const router = useRouter()
  const [items, setItems] = useState<MonitorEvent[]>([])
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (!getToken()) router.replace('/login')
  }, [router])

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const r = await fetchMonitorHistory(200)
        if (!cancelled) {
          setItems(r)
          setErr(null)
        }
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) router.replace('/login')
        if (!cancelled) setErr(e instanceof Error ? e.message : 'Failed to load history')
      }
    }
    tick()
    const id = window.setInterval(tick, 5000)
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
            <div className="panelTitle">HISTORY</div>
            <div className="panelHint">{items.length} recent events</div>
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
                    <th>Time</th>
                    <th>Type</th>
                    <th>Host</th>
                    <th>Service</th>
                    <th>State</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((e) => (
                    <tr key={e.id} className="row">
                      <td className="mono small">{new Date(e.ts).toLocaleString()}</td>
                      <td className="mono">{e.object_type.toUpperCase()}</td>
                      <td>{e.host_id || '—'}</td>
                      <td className="mono">{e.service_name || '—'}</td>
                      <td>
                        <StateBadge state={e.state} />
                      </td>
                      <td className="muted">{e.message}</td>
                    </tr>
                  ))}
                  {items.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="muted" style={{ padding: 12 }}>
                        No events yet.
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

