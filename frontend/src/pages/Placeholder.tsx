export function PlaceholderPage({ title, subtitle }: { title: string; subtitle: string }) {
  return (
    <div className="app">
      <header className="topbar">
        <div className="brandTitle">{title}</div>
      </header>
      <div style={{ padding: 14 }}>
        <div className="panel" style={{ padding: 14 }}>
          <div className="muted">{subtitle}</div>
        </div>
      </div>
    </div>
  )
}

