# Setup Notes

## PostgreSQL table

```sql
CREATE TABLE IF NOT EXISTS attacks (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    source_ip INET,
    dest_port INTEGER,
    protocol TEXT,
    country TEXT,
    payload TEXT,
    processed BOOLEAN DEFAULT FALSE,
    analysis JSONB,
    analyzed_at TIMESTAMPTZ,
    asn TEXT,
    org TEXT,
    threat_score INTEGER
);
```

## Collector API

Run in a venv with:

```bash
pip install flask flask-cors psycopg2-binary
python3 api.py
```

## LLM API

Run in a venv with:

```bash
pip install flask requests
python3 llm_api.py
```

Make sure Ollama is installed and the model exists:

```bash
ollama list
```

## Forwarder

Run in a venv with:

```bash
pip install psycopg2-binary requests
python3 llm_forwarder.py
```

## Sensor

Run in a venv with:

```bash
pip install requests
python3 sensor.py
```

## Cowrie notes

Current Cowrie install flow uses:

```bash
python -m pip install -e .
cowrie start
```

Default SSH listener is typically port `2222`. Redirect port 22 to 2222 separately if desired.

## Dashboard

The current dashboard assumes the collector API is reachable at:

```js
const API_BASE = "http://10.10.30.102:8000";
```

Then run:

```bash
npm install
npm run dev -- --host
```
