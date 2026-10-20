# 🛡️ SSH Brute Force Detector & Autonomous Intrusion Response

[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org/)
[![Linux](https://img.shields.io/badge/OS-Linux%20%7C%20Ubuntu%20%7C%20Debian-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://kernel.org/)
[![Firewall](https://img.shields.io/badge/Firewall-iptables%20Kernel%20Filtering-E95420?style=for-the-badge)](https://netfilter.org/)
[![Flask](https://img.shields.io/badge/Dashboard-Flask-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)

> **A real-time Host-based Intrusion Detection & Prevention System (HIDS/IPS)** that continuously tails `/var/log/auth.log`, identifies distributed and brute-force authentication attacks via regex pattern analysis, and autonomously enforces kernel-level drops via `iptables` while rendering a real-time web SOC telemetry dashboard.

---

## ⚡ Detection & Mitigation Pipeline

```
  Attacker (Hydra / Medusa / Botnet)
                 |
                 v
   +---------------------------+
   |   OpenSSH Daemon (:22)    |
   +-------------+-------------+
                 |
                 v Logs Event
   +---------------------------+
   |    /var/log/auth.log      |
   +-------------+-------------+
                 |
                 v Streaming Ingestion (tail -f generator)
   +---------------------------+
   |     detector.py Engine    |
   | - Regex Event Extractor   |
   | - Sliding Window Tracker  |
   | - Threshold Evaluator     |
   +-------------+-------------+
                 | Threshold Exceeded (>= 5 attempts / 60s)
                 v
   +---------------------------+      +---------------------------+
   |    iptables INPUT Rule    |      |    Flask SOC Dashboard    |
   |   (Kernel DROP Target)    | <--- |   (Real-time Telemetry,   |
   +---------------------------+      |    Manual Unblock & Logs) |
                                      +---------------------------+
```

---

## 🌟 Key Capabilities

- **Real-Time Streaming Log Analysis:** Implements a non-blocking Python generator mimicking `tail -f` directly against standard system authentication streams (`/var/log/auth.log` or `/var/log/secure`).
- **Autonomous Kernel Enforcement:** Invokes the Linux `netfilter/iptables` subsystem to drop malicious packets before they reach user space.
- **Sliding Window Rate Limiting:** Enforces granular temporal counters (e.g., 5 failed attempts within 60 seconds) with automated state expiry and unblocking.
- **Persistent Incident Storage:** Maintains blocked IP history and active jail state across process restarts (`blocked_ips.json`).
- **Self-Lockout Prevention:** Configurable IP whitelisting engine (`127.0.0.1`, `::1`, management subnets).
- **Interactive SOC Dashboard:** Lightweight Flask-based administrative control pane with live incident feed and one-click manual unblock overrides.

---

## 📁 Repository Structure

```
├── detector.py        # Core HIDS engine: log parser, rate tracker, iptables manager
├── dashboard.py       # Flask SOC telemetry web server
├── dashboard.html     # Responsive frontend UI for monitoring and incident response
├── requirements.txt   # Runtime dependencies
├── blocked_ips.json   # (Auto-generated) State cache of jailed IP addresses
└── detector.log       # (Auto-generated) Operational audit log
```

---

## 🚀 Quickstart & Deployment

### 1. Prerequisites
- Linux OS (Ubuntu 20.04/22.04/24.04, Debian 11/12, Kali Linux)
- Root/`sudo` privileges (required for `iptables` rule manipulation)
- Python 3.9+

### 2. Installation
```bash
# Clone the repository
git clone git@github.com:prajwalk-cyber/SSH-BruteForce-Detector.git
cd SSH-BruteForce-Detector

# Install dependencies
pip3 install -r requirements.txt
```

### 3. Configuration
Customize parameters at the top of `detector.py`:
```python
THRESHOLD      = 5                     # Max failed attempts before blocking
TIME_WINDOW    = 60                    # Sliding time window (seconds)
BLOCK_DURATION = 3600                  # Block lifetime in seconds (1 hr)
WHITELIST      = {"127.0.0.1", "::1"} # Safe management IPs
```

### 4. Running the System
Start the detector daemon:
```bash
sudo python3 detector.py
```

In a separate terminal or background session, launch the SOC dashboard:
```bash
sudo python3 dashboard.py
```
Access the dashboard at **`http://localhost:5000`**.

---

## 🧪 Red Team Simulation (Verification with Hydra)

Test the automated response pipeline from an external machine or attacker VM (e.g., Kali Linux):

```bash
# Launch SSH brute-force attack
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP> -t 4 -V
```

**Target Detector Output:**
```text
2026-10-20 14:23:01  INFO  Failed attempt from 192.168.1.100  [1/5]
2026-10-20 14:23:02  INFO  Failed attempt from 192.168.1.100  [2/5]
2026-10-20 14:23:03  INFO  Failed attempt from 192.168.1.100  [3/5]
2026-10-20 14:23:04  INFO  Failed attempt from 192.168.1.100  [4/5]
2026-10-20 14:23:05  WARNING  BLOCKED  192.168.1.100  — exceeded 5 attempts
```

**Verify Active Firewall Drop:**
```bash
sudo iptables -L INPUT -n -v | grep DROP
```

---

## 🔒 Security & Best Practices
- **Production Daemonization:** Deploy via `systemd` service units with `Restart=always` for 24/7 endpoint protection.
- **Fail-Safe Whitelisting:** Always verify your administrator workstation IP is added to `WHITELIST` before live activation.

---

## 📜 License
Distributed under the MIT License.
