'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

import { getToken } from '../../lib/auth'
import { SideMenu } from '../../components/SideMenu'

export default function DevicesPage() {
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
            <div className="panelTitle">DEVICES</div>
            <div className="panelHint">Placeholder (coming soon)</div>
          </div>
          <div style={{ padding: 14 }} className="muted">
            This page will become a full devices inventory view in Next.js.
          </div>
        </div>
      </div>
    </div>
  )
}

