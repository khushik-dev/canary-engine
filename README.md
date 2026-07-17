# 🛡️ Ransomware Detection Canary Engine

**Cisco CCST Cybersecurity Internship Project**  
**Team:** Khushik + [Partner Name]  
**Duration:** 5 Weeks  
**Environment:** Ubuntu 24.04 (WSL) + Python 3.12  

---

## 📌 What is this project?

A lightweight security agent that monitors hidden "canary" bait files 
on a Samba network file share. The moment ransomware touches these files, 
the system automatically:

1. Detects the file modification in real time
2. Identifies the attacker's IP address
3. Cuts off that machine from the network — automatically, in under 2 seconds

No human intervention required.

---

## 🎯 How It Works
Ransomware connects to shared folder

↓

Starts encrypting files one by one

↓

Touches a hidden canary bait file

↓

Linux Inotify detects change INSTANTLY

↓

samba_parser.py identifies attacker IP

↓

isolate.py blocks IP via iptables

↓

Attack stopped in under 2 seconds ✅

---

## 🏗️ Project Structure
canary-engine/

├── canary_files/               # Hidden bait files (ransomware targets)
│   ├── passwords_backup.xlsx
│   ├── important_documents.docx
│   ├── client_data_2024.pdf
│   ├── financial_records.zip
│   ├── HR/
│   │   ├── employee_salaries.xlsx
│   │   └── employee_records.docx
│   ├── Finance/
│   │   ├── financial_records.xlsx
│   │   └── budget_report.pdf
│   └── Management/
│       ├── strategy_2026.docx
│       └── board_minutes.pdf
│
├── logs/
│   └── watcher.log             # Complete timestamped event log
│
├── scripts/
│   ├── watcher.py              # Main detection engine (runs 24/7)
│   ├── samba_parser.py         # Attacker IP identification
│   ├── isolate.py              # Automatic network blocking
│   ├── simulate_attack.py      # Safe ransomware simulator
│   ├── reset_canary.py         # Restore canary files after test
│   └── email_alert.py          # Email notification system
│
├── dashboard/
│   ├── app.py                  # Flask web dashboard + auth
│   └── templates/
│       ├── login.html           # Secure login page
│       ├── pin.html             # Admin PIN verification
│       ├── dashboard.html       # Viewer panel (read only)
│       └── admin.html           # Admin panel (full access)
│
├── config/
│   ├── settings.py             # Central configuration file
│   └── smb.conf                # Samba share configuration
│
├── .env                        # Credentials (never commit!)
└── .gitignore                  # Protects .env from git
│
└── README.md

---

## 🔧 Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.12 | Main programming language |
| Linux Inotify API | Real-time file system monitoring |
| inotify_simple | Python wrapper for Inotify |
| Samba (SMB) | Network file share (simulates company server) |
| smbstatus | Live connection tracking |
| iptables | Automatic network firewall blocking |
| RotatingFileHandler | Auto-managed log rotation |
| WSL Ubuntu 24.04 | Development + deployment environment |

---

## ⚙️ Setup Instructions

### 1. Prerequisites
```bash
sudo apt install -y samba smbclient iptables
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
```

### 2. Create virtual environment
```bash
cd ~/canary-engine
python3 -m venv venv
source venv/bin/activate
pip install inotify_simple
```

### 3. Configure sudoers (eliminates password prompt delay)
```bash
sudo visudo
# Add this line at the bottom:
# khushik ALL=(ALL) NOPASSWD: /usr/bin/smbstatus, /usr/sbin/iptables
```

### 4. Configure Samba
```bash
sudo cp config/smb.conf /etc/samba/smb.conf
sudo smbpasswd -a khushik
sudo service smbd start
sudo service nmbd start
```

### 5. Create canary files
```bash
cd canary_files
echo "Confidential - Do Not Share" > passwords_backup.xlsx
echo "Q4 Financial Summary 2024" > financial_records.zip
echo "Client Database Export" > client_data_2024.pdf
echo "System Administrator Credentials" > important_documents.docx
```

---

## 🚀 How To Run

### Terminal 1 — Start the detection engine
```bash
cd ~/canary-engine
source venv/bin/activate
python3 scripts/watcher.py
```

### Terminal 2 — Simulate attacker's machine connecting
```bash
smbclient //localhost/CanaryShare -U khushik
```

### Terminal 3 — Launch the simulated attack
```bash
cd ~/canary-engine
source venv/bin/activate
python3 scripts/simulate_attack.py
```

---

## 📊 Expected Demo Output
[2026-07-03 06:14:11] Samba status : RUNNING ✓

[2026-07-03 06:14:11] Canary Engine STARTED

[2026-07-03 06:14:11] Watching folder : /home/khushik/canary-engine/canary_files

[2026-07-03 06:14:11] Watcher is ACTIVE. Press Ctrl+C to stop.
[2026-07-03 06:15:21] CANARY TRIGGERED — client_data_2024.pdf

[2026-07-03 06:15:21] Attacker IP identified: 127.0.0.1

[2026-07-03 06:15:21] SUCCESS: IP 127.0.0.1 BLOCKED via iptables

[2026-07-03 06:15:21] NETWORK ISOLATION COMPLETE
=======================================================

*** RANSOMWARE ALERT ***

File      : client_data_2024.pdf

Attacker  : 127.0.0.1

Status    : ✅ BLOCKED AUTOMATICALLY
---

## 🧹 After Each Test Run

```bash
# Terminal 1
Ctrl+C                                    # stop watcher

# Terminal 3
python3 scripts/reset_canary.py           # restore canary files
sudo iptables -F INPUT                    # unblock all IPs
sudo iptables -L INPUT -n                 # verify clean
```

---

## 🔒 Security Improvements Implemented

| Issue | Fix Applied |
|---|---|
| Wrong attacker attribution | Filter smbstatus by CanaryShare only |
| Duplicate iptables rules | Check before blocking |
| Hardcoded paths | Central config/settings.py |
| Broad exception handling | Specific exception types |
| Log file growing forever | RotatingFileHandler (5MB × 5 files) |
| sudo password causing delay | sudoers NOPASSWD rule |
| No Samba startup check | check_samba_running() at startup |
| Subnet mask false positives | Filter 255.x.x.x addresses |
| Reset triggering false alerts | Separate reset_canary.py script |
| Plain text passwords | werkzeug password hashing |
| Brute force login | Rate limiting (5 attempts, 5 min lockout) |
| Blocks lost on reboot | iptables-persistent rules |
| Only root folder watched | Recursive os.walk() monitoring |
| Credentials in source code | .env file + python-dotenv |

---

## 👥 Team Contributions

| Task | Person |
|---|---|
| Environment Setup (WSL, Python, iptables) | Khushik |
| watcher.py — Core detection engine | Khushik |
| Samba share configuration | Khushik |
| samba_parser.py — Attacker IP identification | Khushik |
| isolate.py — Automatic network blocking | Partner |
| simulate_attack.py — Attack simulator | Srishti |
| config/settings.py — Central configuration | Both |
| Security fixes & code review | Both |
| Testing & Integration | Both |
| Documentation | Both |

---

## 📈 Project Scores (Final)
Architecture        8.5 / 10
Code Quality        8.5 / 10
Security            9.5 / 10
Performance         9.0 / 10
Reliability         9.0 / 10
Maintainability     9.0 / 10
Production Ready    8.5 / 10
UI/UX               8.5 / 10
Email Integration   9.0 / 10
─────────────────────────────
Overall             9.1 / 10  
---

## 🗓️ Timeline
Week 1   Environment setup + Linux/Python basics
Week 2   Canary files + watcher.py (Inotify)
Week 3   Samba integration + samba_parser.py
Week 4   isolate.py + end-to-end testing
Week 5   Code review + 8 security fixes + documentation
---

## 📚 Key Concepts Demonstrated

- **Canary Trap Strategy** — industry-standard deception technique
- **Real-time File Monitoring** — Linux Inotify API
- **Network Forensics** — IP identification via live Samba connections
- **Automated Incident Response** — zero human intervention needed
- **Defense in Depth** — detection + isolation working together
- **Audit Trail** — complete timestamped log for forensic analysis