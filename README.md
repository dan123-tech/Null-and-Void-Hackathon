# Cyber-Sentinel (Digital Twin Cybersecurity Platform)

## Quick start (2 terminals)

### Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open the dashboard at the URL printed by Vite (typically `http://localhost:5173`).

## Visible to everyone on your LAN

- **Dev mode (fastest for demos)**: run the commands above, then other devices on the same network open:
  - `http://<YOUR_PI_OR_PC_LAN_IP>:5173`
- **Single-server mode (recommended)**: serve the built React UI directly from FastAPI:

```powershell
cd frontend
npm run build

cd ..\backend
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Then everyone opens:

- `http://<YOUR_PI_OR_PC_LAN_IP>:8000`

If other devices can’t connect, allow inbound connections in your OS firewall for the chosen port (5173 or 8000).

## Run on Raspberry Pi 5 with Docker (recommended)

On the Pi, from the project folder:

```bash
docker compose up --build
```

Then on any device on the same network, open:

- `http://<RASPBERRY_PI_LAN_IP>:8000`

## What you get

- **Digital Twin visualizer**: real-time network topology graph (Guardian center node + peripherals)
- **Node states**:
  - Healthy → cyan/green neon
  - Unknown/new → amber
  - Suspicious → red + pulsing effect
- **Global risk gauge**
- **Device details sidebar** on node click
- **Alert log**
- **Kill switch** for red nodes (demo backend action)

## Notes

The backend currently simulates devices + IDS events in memory (`backend/app/store.py`). Swap it for InfluxDB queries and your IDS pipeline when ready.

