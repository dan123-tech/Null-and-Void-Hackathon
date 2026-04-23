import { NavLink } from 'react-router-dom'

const items = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/devices', label: 'Devices' },
  { to: '/traffic', label: 'Traffic' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/response', label: 'Response' },
  { to: '/settings', label: 'Settings' },
]

export function SideMenu() {
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
        {items.map((it) => (
          <NavLink
            key={it.to}
            to={it.to}
            className={({ isActive }) => `sideNavItem ${isActive ? 'active' : ''}`}
          >
            <span className="sideNavDot" aria-hidden="true" />
            <span>{it.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sideNavFoot muted small">
        Tip: topology updates only on join/leave.
      </div>
    </aside>
  )
}

