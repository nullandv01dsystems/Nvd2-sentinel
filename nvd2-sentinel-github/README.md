# NVD² Sentinel

A lightweight threat telemetry pipeline built around:

- **Cowrie** as the internet-facing SSH honeypot
- **Sensor** to tail Cowrie JSON logs and forward events
- **Collector API** to ingest and expose enriched events
- **LLM API** to classify and score attacks
- **Forwarder** to enrich, classify, and write results back to PostgreSQL
- **React dashboard** for live visualization

## Architecture

```text
[ Internet Attackers ]
        ↓
[ Cowrie Honeypot ]
        ↓
[ Sensor ]
        ↓  POST /api/ingest
[ Collector API ]
        ↓
[ PostgreSQL ]
        ↓
[ LLM Forwarder ] → [ LLM API ] → Ollama model
        ↓
[ React Dashboard ]
```

## Repository layout

- `collector/api.py` — Flask API for ingest, attacks, and summary
- `collector/llm_forwarder.py` — processes unprocessed attacks, enriches IP data, calls LLM, writes back to DB
- `llm/llm_api.py` — Flask API wrapper around Ollama
- `sensor/sensor.py` — tails Cowrie JSON logs and sends normalized events to the collector
- `frontend/src/App.jsx` — dashboard UI
- `frontend/src/App.css` — dashboard styles
- `services/*.service` — systemd unit examples
- `docs/SETUP.md` — setup notes and run order

## Environment assumptions

### Collector
- Host: `10.10.30.102`
- PostgreSQL database: `sentinel`
- PostgreSQL user: `sentinel_user`
- API listening on port `8000`

### LLM server
- Host: `10.10.30.114`
- Ollama model: `qwen3b-honeypot`
- LLM API listening on port `5000`

### Sensor
- Cowrie JSON log path:
  `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`

## Quick start

1. Start PostgreSQL and create the `attacks` table.
2. Start `collector/api.py`.
3. Start `llm/llm_api.py`.
4. Start `collector/llm_forwarder.py`.
5. Start Cowrie on the sensor host.
6. Start `sensor/sensor.py`.
7. Start the React dashboard.

## Notes

- The dashboard is currently configured to use the **internal collector API** at `http://10.10.30.102:8000`.
- For production, move to same-origin API routing and HTTPS.
