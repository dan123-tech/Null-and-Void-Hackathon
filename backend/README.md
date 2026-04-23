# Cyber-Sentinel Backend (FastAPI)

## Run (Windows / PowerShell)

From `backend/`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API

- `GET /api/devices`
- `GET /api/alerts?limit=100`
- `GET /api/risk`
- `POST /api/kill-switch` body: `{ "ip": "192.168.1.5" }`
- `WS /ws` sends snapshots every 2 seconds

This backend currently uses an in-memory demo store that simulates IDS events; swap `app/store.py` for InfluxDB-backed queries later.

