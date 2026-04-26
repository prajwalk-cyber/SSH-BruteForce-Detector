import re
import time
import subprocess
import logging
import json
import os
from datetime import datetime
from collections import defaultdict

# ─── CONFIG ────────────────────────────────────────────────────────────────
LOG_FILE       = "/var/log/auth.log"   # Ubuntu/Debian
# LOG_FILE     = "/var/log/secure"     # CentOS/RHEL — uncomment if needed
THRESHOLD      = 5                     # failed attempts before block
TIME_WINDOW    = 60                    # seconds to count attempts in
BLOCK_DURATION = 3600                  # seconds to keep IP blocked (1 hour)
STATE_FILE     = "blocked_ips.json"    # persists blocked IPs across restarts
WHITELIST      = {"127.0.0.1", "::1"} # IPs never to block
# ───────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    handlers=[
        logging.FileHandler("detector.log"),
        logging.StreamHandler()
    ]
)

# Regex patterns for failed SSH attempts in auth.log
FAIL_PATTERNS = [
    re.compile(r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Failed password for invalid user .+ from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Invalid user .+ from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Connection closed by authenticating user .+ (\d+\.\d+\.\d+\.\d+).+\[preauth\]"),
]

# ip -> list of attempt timestamps
attempt_log = defaultdict(list)

# ip -> block timestamp
blocked_ips = {}


def load_state():
    """Load previously blocked IPs from disk so blocks survive restarts."""
    global blocked_ips
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            blocked_ips = json.load(f)
        logging.info(f"Loaded {len(blocked_ips)} previously blocked IPs")


def save_state():
    with open(STATE_FILE, "w") as f:
        json.dump(blocked_ips, f, indent=2)


def block_ip(ip: str):
    """Add iptables DROP rule for the given IP."""
    if ip in WHITELIST:
        logging.warning(f"Attempted to block whitelisted IP {ip} — skipped")
        return
    if ip in blocked_ips:
        return

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        blocked_ips[ip] = datetime.now().isoformat()
        save_state()
        logging.warning(f"BLOCKED  {ip}  — exceeded {THRESHOLD} attempts")
    except subprocess.CalledProcessError as e:
        logging.error(f"iptables error blocking {ip}: {e.stderr.decode()}")
    except PermissionError:
        logging.error("Need sudo to run iptables. Start with: sudo python3 detector.py")


def unblock_ip(ip: str):
    """Remove iptables rule for the given IP after block duration expires."""
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True
        )
        blocked_ips.pop(ip, None)
        save_state()
        logging.info(f"UNBLOCKED  {ip}  — block duration expired")
    except subprocess.CalledProcessError:
        pass


def expire_old_blocks():
    """Auto-unblock IPs whose block duration has passed."""
    now = datetime.now()
    to_unblock = []
    for ip, blocked_at in list(blocked_ips.items()):
        elapsed = (now - datetime.fromisoformat(blocked_at)).total_seconds()
        if elapsed > BLOCK_DURATION:
            to_unblock.append(ip)
    for ip in to_unblock:
        unblock_ip(ip)


def extract_ip(line: str):
    """Return the attacker IP from a log line, or None."""
    for pattern in FAIL_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


def process_line(line: str):
    """Check a single log line and block IP if threshold exceeded."""
    ip = extract_ip(line)
    if not ip:
        return

    now = time.time()
    # Keep only attempts within the time window
    attempt_log[ip] = [t for t in attempt_log[ip] if now - t < TIME_WINDOW]
    attempt_log[ip].append(now)

    count = len(attempt_log[ip])
    logging.info(f"Failed attempt from {ip}  [{count}/{THRESHOLD}]")

    if count >= THRESHOLD:
        block_ip(ip)


def tail_log(filepath: str):
    """Generator: yields new lines appended to the log file (like tail -f)."""
    with open(filepath, "r") as f:
        f.seek(0, 2)          # jump to end of file
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)
                expire_old_blocks()


def main():
    logging.info("SSH Brute Force Detector started")
    logging.info(f"Watching: {LOG_FILE}")
    logging.info(f"Threshold: {THRESHOLD} attempts in {TIME_WINDOW}s → auto-block")

    load_state()

    if not os.path.exists(LOG_FILE):
        logging.error(f"Log file not found: {LOG_FILE}")
        logging.error("On Kali/Ubuntu the file is /var/log/auth.log")
        logging.error("Make sure SSH service is running: sudo service ssh start")
        return

    try:
        for line in tail_log(LOG_FILE):
            process_line(line)
    except KeyboardInterrupt:
        logging.info("Detector stopped by user")


if __name__ == "__main__":
    main()
