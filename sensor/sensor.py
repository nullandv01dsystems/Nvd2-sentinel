#!/usr/bin/env python3
import json
import logging
import os
import time
from typing import Optional

import requests

COLLECTOR_URL = "http://API:8000/api/ingest"
LOG_FILE = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
STATE_FILE = os.path.expanduser("~/.sensor_offset")
POLL_INTERVAL = 2
REQUEST_TIMEOUT = 10

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def load_offset() -> int:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_offset(offset: int) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write(str(offset))


def normalize_event(raw: dict) -> Optional[dict]:
    src_ip = raw.get("src_ip") or raw.get("ip")
    src_port = raw.get("src_port")
    dest_port = raw.get("dest_port") or raw.get("sensor_port") or 22
    username = raw.get("username")
    password = raw.get("password")
    timestamp = raw.get("timestamp")
    eventid = raw.get("eventid")

    if not src_ip:
        return None

    return {
        "ip": src_ip,
        "port": dest_port,
        "protocol": "ssh",
        "username": username,
        "password": password,
        "timestamp": timestamp,
        "eventid": eventid,
        "payload": {
            "src_port": src_port,
            "session": raw.get("session"),
            "message": raw.get("message"),
            "raw": raw,
        },
    }


def post_event(event: dict) -> bool:
    try:
        r = requests.post(COLLECTOR_URL, json=event, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        logging.info("Sent event for ip=%s status=%s", event.get("ip"), r.status_code)
        return True
    except Exception as e:
        logging.error("Failed to send event for ip=%s: %s", event.get("ip"), e)
        return False


def process_new_lines() -> None:
    if not os.path.exists(LOG_FILE):
        logging.warning("Log file does not exist yet: %s", LOG_FILE)
        return

    current_size = os.path.getsize(LOG_FILE)
    offset = load_offset()

    if current_size < offset:
        logging.info("Log rotated or truncated. Resetting offset to 0.")
        offset = 0

    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        f.seek(offset)

        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                logging.warning("Skipping non-JSON line")
                continue

            event = normalize_event(raw)
            if not event:
                continue

            sent = post_event(event)
            if not sent:
                logging.warning("Stopping processing until next cycle to avoid skipping unsent events")
                break

            offset = f.tell()
            save_offset(offset)


def main():
    logging.info("Starting NVD2 sensor")
    while True:
        try:
            process_new_lines()
        except Exception as e:
            logging.exception("Sensor loop error: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
