import './App.css'
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { clearToken, getToken } from './lib/auth'
import { SideMenu } from './components/SideMenu'
import { DashboardPage } from './pages/Dashboard'
import { LoginPage } from './pages/Login'
import { PlaceholderPage } from './pages/Placeholder'

function App() {
  const nav = useNavigate()

  const RequireAuth = ({ children }: { children: React.ReactNode }) => {
    return getToken() ? <>{children}</> : <Navigate to="/login" replace />
  }

  const Shell = ({ children }: { children: React.ReactNode }) => (
    <div className="shell">
      <SideMenu />
      <div>
        <div className="status" style={{ padding: '10px 14px', justifyContent: 'flex-end' }}>
          <button
            className="iconBtn"
            onClick={() => {
              clearToken()
              nav('/login')
            }}
          >
            Logout
          </button>
        </div>
        {children}
      </div>
    </div>
  )

  return (
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/dashboard"
        element={
          <RequireAuth>
            <Shell>
              <DashboardPage />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/devices"
        element={
          <RequireAuth>
            <Shell>
              <PlaceholderPage title="Devices" subtitle="Device inventory, tags, and posture." />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/traffic"
        element={
          <RequireAuth>
            <Shell>
              <PlaceholderPage title="Traffic" subtitle="Packet timeline, protocol/port filters, and flows." />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/alerts"
        element={
          <RequireAuth>
            <Shell>
              <PlaceholderPage title="Alerts" subtitle="Severity filters, ACK/resolve, and export." />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/response"
        element={
          <RequireAuth>
            <Shell>
              <PlaceholderPage title="Response" subtitle="Kill switch history, quarantine, allow/deny lists." />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/settings"
        element={
          <RequireAuth>
            <Shell>
              <PlaceholderPage title="Settings" subtitle="Users, roles, notifications, retention." />
            </Shell>
          </RequireAuth>
        }
      />
    </Routes>
  )
}

export default App
