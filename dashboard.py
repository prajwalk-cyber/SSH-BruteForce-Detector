from flask import Flask, render_template, jsonify
import json
import os
import subprocess
from datetime import datetime
from collections import defaultdict
import re

app = Flask(__name__)

STATE_FILE  = "blocked_ips.json"
DETECTOR_LOG = "detector.log"

FAIL_PATTERN = re.compile(
    r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Failed attempt from (\d+\.\d+\.\d+\.\d+)\s+\[(\d+)/(\d+)\]"
)


def load_blocked():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def parse_detector_log():
    """Read detector.log and return recent attack events."""
    events = []
    if not os.path.exists(DETECTOR_LOG):
        return events
    with open(DETECTOR_LOG) as f:
        for line in f:
            m = FAIL_PATTERN.search(line)
            if m:
                events.append({
                    "time": m.group(1),
                    "ip": m.group(2),
                    "count": int(m.group(3)),
                    "threshold": int(m.group(4))
                })
    return events[-100:]  # last 100 events


def get_attack_stats(events):
    per_ip = defaultdict(int)
    for e in events:
        per_ip[e["ip"]] += 1
    return dict(sorted(per_ip.items(), key=lambda x: x[1], reverse=True)[:10])


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    blocked  = load_blocked()
    events   = parse_detector_log()
    top_ips  = get_attack_stats(events)

    # Recent attacks (last 20)
    recent = [e for e in events[-20:]][::-1]

    return jsonify({
        "blocked_count": len(blocked),
        "total_events":  len(events),
        "blocked_ips":   blocked,
        "top_attackers": top_ips,
        "recent_events": recent,
        "last_updated":  datetime.now().strftime("%H:%M:%S")
    })


@app.route("/api/unblock/<ip>", methods=["POST"])
def unblock(ip):
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        blocked = load_blocked()
        blocked.pop(ip, None)
        with open(STATE_FILE, "w") as f:
            json.dump(blocked, f, indent=2)
        return jsonify({"status": "unblocked", "ip": ip})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
