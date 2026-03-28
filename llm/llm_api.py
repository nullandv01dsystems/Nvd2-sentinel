#!/usr/bin/env python3
from flask import Flask, request, jsonify
import subprocess
import json

app = Flask(__name__)
MODEL = "qwen3b-honeypot"


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json

    prompt = f"""
You are a cybersecurity threat analysis engine.

Return ONLY valid JSON with these keys:
attack_type
intent
severity
confidence
attacker_skill
likely_next_action
recommended_detection
recommended_response
summary
threat_score

Rules:
- threat_score must be an integer from 1 to 100
- severity must be one of: low, medium, high, critical
- confidence must be a number from 0.0 to 1.0

Analyze this honeypot session:
{json.dumps(data, indent=2)}
"""

    try:
        result = subprocess.run(
            ["ollama", "run", MODEL, prompt],
            capture_output=True,
            text=True,
            timeout=30,
        )

        output = result.stdout.strip()

        try:
            parsed = json.loads(output)
        except Exception:
            parsed = {"raw_output": output}

        return jsonify(parsed)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
