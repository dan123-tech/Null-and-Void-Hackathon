'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

import { SideMenu } from '../../components/SideMenu'
import { getToken } from '../../lib/auth'

export default function TrafficPage() {
  const router = useRouter()

  useEffect(() => {
    if (!getToken()) router.replace('/login')
  }, [router])

  return (
    <div className="shell">
      <SideMenu />
      <div style={{ minWidth: 0, padding: 18 }}>
        <div className="panel">
          <div className="panelHeader">
            <div className="panelTitle">TRAFFIC</div>
            <div className="panelHint">Placeholder (coming soon)</div>
          </div>
          <div style={{ padding: 14 }} className="muted">
            This page will become a traffic analytics view in Next.js.
          </div>
        </div>
      </div>
    </div>
  )
}

