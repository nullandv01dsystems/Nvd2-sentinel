#!/usr/bin/env python3
from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import psycopg2
import psycopg2.extras

app = Flask(__name__)
CORS(app)

DB_CONFIG = {
    "dbname": "sentinel",
    "user": "sentinel_user",
    "password": "!changeMe!",
    "host": "127.0.0.1",
    "port": 5432,
}


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"})


@app.route("/api/ingest", methods=["POST"])
def ingest():
    data = request.get_json(silent=True) or {}

    source_ip = data.get("ip")
    dest_port = data.get("port")
    protocol = data.get("protocol")
    country = data.get("country")
    payload = json.dumps(data)

    if not source_ip or not protocol:
        return jsonify({"status": "error", "error": "ip and protocol are required"}), 400

    query = """
        INSERT INTO attacks (source_ip, dest_port, protocol, country, payload, processed)
        VALUES (%s, %s, %s, %s, %s, false)
        RETURNING id, timestamp;
    """

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query, (source_ip, dest_port, protocol, country, payload))
            row = cur.fetchone()
            conn.commit()

    return jsonify({
        "status": "ingested",
        "attack_id": row["id"],
        "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None,
    })


@app.route("/api/attacks", methods=["GET"])
def get_attacks():
    query = """
        SELECT
          id,
          timestamp,
          REPLACE(source_ip::text, '/32', '') AS source_ip,
          dest_port,
          protocol,
          country,
          asn,
          org,
          processed,
          analyzed_at,
          threat_score,
          analysis->>'attack_type' AS attack_type,
          analysis->>'severity' AS severity,
          analysis->>'confidence' AS confidence,
          analysis->>'summary' AS summary
        FROM attacks
        ORDER BY
          COALESCE(threat_score, 0) DESC,
          CASE analysis->>'severity'
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            ELSE 0
          END DESC,
          timestamp DESC
        LIMIT 50;
    """

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query)
            rows = cur.fetchall()

    return jsonify(rows)


@app.route("/api/summary", methods=["GET"])
def get_summary():
    query = """
        SELECT
          COUNT(*) AS total_attacks,
          COUNT(*) FILTER (WHERE processed = true) AS processed_attacks,
          COUNT(*) FILTER (WHERE analysis->>'severity' = 'critical') AS critical_count,
          COUNT(*) FILTER (WHERE analysis->>'severity' = 'high') AS high_count,
          COUNT(*) FILTER (WHERE analysis->>'severity' = 'medium') AS medium_count,
          COUNT(*) FILTER (WHERE analysis->>'severity' = 'low') AS low_count,
          COUNT(DISTINCT source_ip) AS unique_ips,
          COALESCE(MAX(threat_score), 0) AS max_threat_score
        FROM attacks;
    """

    with get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(query)
            row = cur.fetchone()

    return jsonify(row)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
