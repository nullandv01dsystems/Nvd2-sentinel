#!/usr/bin/env python3
import json
import time
import logging
import psycopg2
import psycopg2.extras
import requests

DB_CONFIG = {
    "dbname": "sentinel",
    "user": "sentinel_user",
    "password": "!changeMe!",
    "host": "127.0.0.1",
    "port": 5432,
}

LLM_API_URL = "http://<LLMIP>:5000/analyze"
POLL_INTERVAL = 5
BATCH_SIZE = 10

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def get_conn():
    return psycopg2.connect(**DB_CONFIG)


def fetch_unprocessed(cur):
    cur.execute(
        """
        SELECT id, timestamp, source_ip, dest_port, protocol, country, payload
        FROM attacks
        WHERE COALESCE(processed, false) = false
        ORDER BY timestamp ASC
        LIMIT %s
        """,
        (BATCH_SIZE,),
    )
    return cur.fetchall()


def enrich_ip(ip):
    if not ip:
        return {"country": "Unknown", "asn": None, "org": None}

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,as,org,query",
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()

        if data.get("status") != "success":
            return {"country": "Unknown", "asn": None, "org": None}

        as_field = data.get("as") or ""
        asn = as_field.split(" ")[0] if as_field else None

        return {
            "country": data.get("country") or "Unknown",
            "asn": asn,
            "org": data.get("org") or None,
        }
    except Exception as e:
        logging.warning("IP enrichment failed for %s: %s", ip, e)
        return {"country": "Unknown", "asn": None, "org": None}


def analyze_attack(row, ipintel):
    data = {
        "id": row["id"],
        "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None,
        "ip": str(row["source_ip"]) if row["source_ip"] else None,
        "port": row["dest_port"],
        "protocol": row["protocol"],
        "country": ipintel["country"],
        "asn": ipintel["asn"],
        "org": ipintel["org"],
        "payload": row["payload"],
    }

    r = requests.post(LLM_API_URL, json=data, timeout=30)
    r.raise_for_status()
    return r.json()


def mark_processed(cur, attack_id, ipintel, result):
    threat_score = result.get("threat_score")
    try:
        threat_score = int(threat_score) if threat_score is not None else None
    except Exception:
        threat_score = None

    cur.execute(
        """
        UPDATE attacks
        SET processed = true,
            country = %s,
            asn = %s,
            org = %s,
            threat_score = %s,
            analysis = %s::jsonb,
            analyzed_at = NOW()
        WHERE id = %s
        """,
        (
            ipintel["country"],
            ipintel["asn"],
            ipintel["org"],
            threat_score,
            json.dumps(result),
            attack_id,
        ),
    )


def main():
    logging.info("Starting LLM forwarder")
    while True:
        try:
            with get_conn() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    rows = fetch_unprocessed(cur)

                    if not rows:
                        time.sleep(POLL_INTERVAL)
                        continue

                    logging.info("Found %d unprocessed attacks", len(rows))

                    for row in rows:
                        attack_id = row["id"]
                        ip = str(row["source_ip"]) if row["source_ip"] else None

                        try:
                            ipintel = enrich_ip(ip)
                            result = analyze_attack(row, ipintel)
                            mark_processed(cur, attack_id, ipintel, result)
                            conn.commit()
                            logging.info("Processed attack id=%s ip=%s", attack_id, ip)
                        except Exception as e:
                            conn.rollback()
                            logging.exception("Failed processing attack id=%s: %s", attack_id, e)

            time.sleep(POLL_INTERVAL)

        except Exception as e:
            logging.exception("Main loop error: %s", e)
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
