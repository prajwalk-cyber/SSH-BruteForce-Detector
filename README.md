# SSH Brute Force Detector + Auto Blocker

Monitors `/var/log/auth.log` in real time, detects repeated failed SSH login
attempts, and automatically blocks attacker IPs using `iptables`. Includes a
live web dashboard built with Flask.

---

## Project structure

```
ssh_brute_detector/
├── detector.py        ← core engine (monitors logs + blocks IPs)
├── dashboard.py       ← Flask web dashboard
├── requirements.txt
├── blocked_ips.json   ← auto-created, persists blocked IPs
├── detector.log       ← auto-created, all events logged here
└── templates/
    └── dashboard.html ← live dashboard UI
```

---

## Setup (on the TARGET machine — Ubuntu/Debian VM)

```bash
# 1. Clone / copy the project
git clone https://github.com/YOUR_USERNAME/ssh-brute-detector
cd ssh-brute-detector

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Make sure SSH service is running
sudo service ssh start
sudo service ssh status

# 4. Run the detector (needs sudo for iptables)
sudo python3 detector.py

# 5. In a second terminal, run the dashboard
sudo python3 dashboard.py

# 6. Open browser → http://localhost:5000
```

---

## Testing with Kali Linux (simulating the attack)

### Step 1 — find your target VM's IP
On the target Ubuntu VM:
```bash
ip a   # note the IP, e.g. 192.168.1.50
```

### Step 2 — from Kali, run Hydra (SSH brute force)
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.50 -t 4 -V
```
- `-l root` → try username "root"
- `-P rockyou.txt` → password wordlist
- `-t 4` → 4 parallel threads
- `-V` → verbose (shows each attempt)

### Step 3 — watch the detector react
On the target VM terminal you will see:
```
2024-01-15 14:23:01  INFO  Failed attempt from 192.168.1.100  [1/5]
2024-01-15 14:23:02  INFO  Failed attempt from 192.168.1.100  [2/5]
2024-01-15 14:23:03  INFO  Failed attempt from 192.168.1.100  [3/5]
2024-01-15 14:23:04  INFO  Failed attempt from 192.168.1.100  [4/5]
2024-01-15 14:23:05  WARNING  BLOCKED  192.168.1.100  — exceeded 5 attempts
```

Hydra on Kali will hang/timeout → IP is blocked.

### Step 4 — verify the block
```bash
sudo iptables -L INPUT -n   # you will see DROP rule for Kali's IP
```

### Step 5 — manually unblock (after testing)
```bash
sudo iptables -D INPUT -s 192.168.1.100 -j DROP
# or use the dashboard Unblock button at http://localhost:5000
```

---

## Deployment options

### Option A — Local VirtualBox lab (easiest, free)
- Install VirtualBox on your laptop
- Create Ubuntu 22.04 VM (target) + use your Kali as attacker
- Set both VMs to "Host-only Adapter" networking
- Run detector on Ubuntu VM, attack from Kali
- Show dashboard at http://[ubuntu-vm-ip]:5000

### Option B — Oracle Cloud free VM (real internet deployment ★ best for demo)
- Sign up at cloud.oracle.com (free forever tier — no credit card risk)
- Create Ubuntu 22.04 VM (Always Free)
- SSH into your cloud VM and clone the project
- Run detector + dashboard
- Open port 5000 in Oracle's security rules
- Share the public IP — anyone can see live attacks from the internet
- Real attackers will hit your VM within hours — amazing demo data

```bash
# On Oracle Cloud VM
sudo ufw allow 22    # SSH
sudo ufw allow 5000  # dashboard
sudo ufw enable
```

### Option C — Raspberry Pi (if you have one)
- Flash Ubuntu Server on Pi
- Run detector 24/7 on your local network
- Port forward 5000 on your router for remote access

---

## Configuring the detector

Edit the CONFIG section at the top of `detector.py`:

```python
THRESHOLD      = 5      # attempts before block (lower = more aggressive)
TIME_WINDOW    = 60     # seconds window to count attempts
BLOCK_DURATION = 3600   # auto-unblock after 1 hour (set 0 to block forever)
WHITELIST      = {"127.0.0.1", "::1"}   # add your own IP here!
```

> **Important:** Add your own machine's IP to WHITELIST before running,
> or you may accidentally block yourself during testing.

---

## What you learn from this project

- Linux log file parsing with Python
- Regex pattern matching on real auth.log format
- subprocess module for running system commands
- iptables firewall rules (how blocking actually works at kernel level)
- File-based state persistence (JSON)
- Flask REST API design
- Real-time dashboard with polling
- Security trade-offs (false positives, whitelisting, block duration)

---

## Ideas to extend the project

- [ ] Telegram / email alert when an IP is blocked
- [ ] GeoIP lookup — show attacker's country on a world map
- [ ] Fail2ban comparison — benchmark your tool vs the industry standard
- [ ] Add IPv6 support
- [ ] Slack webhook notification
- [ ] SQLite database instead of JSON for better scalability
- [ ] Rate limiting per username, not just per IP

---

## Disclaimer

This tool is for educational purposes and authorized security monitoring only.
Deploy it only on systems you own or have explicit permission to monitor.
Do not use Hydra or any brute force tool against systems you do not own.
