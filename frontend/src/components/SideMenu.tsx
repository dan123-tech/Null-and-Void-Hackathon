'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'

const items = [
  { to: '/problems', label: 'Problems' },
  { to: '/hosts', label: 'Hosts' },
  { to: '/services', label: 'Services' },
  { to: '/history', label: 'History' },
  { to: '/dashboard', label: 'Digital Twin' },
  { to: '/settings', label: 'Settings' },
]

export function SideMenu() {
  const pathname = usePathname()

  return (
    <aside className="sideNav">
      <div className="sideNavTop">
        <div className="brand">
          <div className="brandMark" aria-hidden="true" />
          <div>
            <div className="brandTitle">CYBER-SENTINEL</div>
            <div className="brandSub">Command Center</div>
          </div>
        </div>
      </div>

      <nav className="sideNavList" aria-label="Main navigation">
        {items.map((it) => {
          const isActive = pathname === it.to || (it.to !== '/dashboard' && pathname?.startsWith(it.to))
          return (
            <Link key={it.to} href={it.to} className={`sideNavItem ${isActive ? 'active' : ''}`}>
              <span className="sideNavDot" aria-hidden="true" />
              <span>{it.label}</span>
            </Link>
          )
        })}
      </nav>

      <div className="sideNavFoot muted small">Tip: topology updates only on join/leave.</div>
    </aside>
  )
}

