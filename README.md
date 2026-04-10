# 🛡️ NIDS — Network Intrusion Detection System

A production-ready Network Intrusion Detection System built in Python 3.10+. Captures live network packets, detects attacks using both **Snort-style rules** and **Machine Learning (Isolation Forest)**, and dispatches real-time alerts to multiple channels.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          main.py                                 │
│                    (Orchestrator / CLI)                           │
├──────────┬──────────┬──────────┬──────────┬──────────┬───────────┤
│ Packet   │  Rule    │   ML     │  Alert   │ Database │ Dashboard │
│ Capture  │  Engine  │ Detector │ Manager  │  (SQL)   │  (Rich)   │
│ (Scapy)  │ (Snort)  │ (IsoFor) │ (Multi)  │ (SQLite) │  (CLI)   │
└──────────┴──────────┴──────────┴──────────┴──────────┴───────────┘
     │           │           │          │          │          │
     ▼           ▼           ▼          ▼          ▼          ▼
  Live NIC   .rules     joblib      Terminal   alerts.db   Live TUI
  sniffing   files      models      + File     (ORM)       panels
                                    + Email
                                    + Slack
```

### Data Flow

1. **PacketCapture** sniffs raw packets from a network interface using Scapy
2. Each packet is parsed into a `PacketInfo` struct (IP, ports, flags, DNS, ARP, etc.)
3. The callback dispatches each packet to:
   - **RuleEngine**: matches against Snort-style rules + 5 heuristic detectors
   - **MLDetector**: extracts features over a sliding window → Isolation Forest prediction
4. Any detections are sent to **AlertManager**, which:
   - Persists to **SQLite** via SQLAlchemy ORM
   - Prints Rich colored panels to the **terminal**
   - Writes to a rotating **log file**
   - Sends **email** notifications (SMTP/TLS)
   - Posts to **Slack** via incoming webhook
5. **Dashboard** (Rich Live) reads from all subsystems and renders a full-screen TUI

---

## 📁 Project Structure

```
nids-project/
├── main.py                  # Entry point — ties everything together
├── config.yaml              # All settings, thresholds, notification config
├── requirements.txt         # Python dependencies
├── README.md                # This file
│
├── src/
│   ├── __init__.py
│   ├── packet_capture.py    # Live packet sniffing (Scapy)
│   ├── rule_engine.py       # Snort-style rules + heuristic detectors
│   ├── ml_detector.py       # Isolation Forest anomaly detection
│   ├── alert_manager.py     # Multi-channel alert dispatcher
│   ├── database.py          # SQLite ORM (SQLAlchemy)
│   └── dashboard.py         # Rich CLI live dashboard
│
├── tests/
│   ├── __init__.py
│   └── test_detector.py     # Unit + integration tests
│
├── rules/
│   └── default.rules        # Auto-generated Snort-style rule file
│
├── models/                  # Trained ML models (auto-created)
├── logs/                    # Alert log files (auto-created)
└── data/                    # SQLite database (auto-created)
```

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+**
- **Administrator/root privileges** (required for raw packet capture)
- **Npcap** (Windows) or **libpcap** (Linux/macOS)

### Installation

```bash
# Clone or download the project
cd nids-project

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
# or
.\venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

### Windows-specific: Install Npcap

1. Download Npcap from [npcap.com](https://npcap.com/)
2. During installation, **check "Install Npcap in WinPcap API-compatible Mode"**
3. Restart your terminal

### Run the NIDS

```bash
# Basic run (auto-detect interface, with dashboard)
sudo python main.py                # Linux/macOS
# or run PowerShell/CMD as Administrator:
python main.py                     # Windows

# Specify a network interface
python main.py --interface eth0

# Pre-train the ML model with synthetic data
python main.py --train

# Run without the dashboard (headless/log-only mode)
python main.py --no-dashboard

# List available network interfaces
python main.py --list-interfaces

# Use a custom config file
python main.py --config /path/to/custom.yaml
```

---

## 🔍 Attack Detection

### Rule-Based Detection (5 built-in heuristic detectors)

| Attack Type     | Detection Method                                         | Default Threshold     |
|-----------------|----------------------------------------------------------|-----------------------|
| **Port Scan**   | Tracks unique dst ports per src IP within time window    | 15 ports in 60s       |
| **SYN Flood**   | Counts SYN packets per src IP                            | 100 SYNs in 10s       |
| **Brute Force** | Connection rate to SSH (22) / FTP (21) ports             | 5 attempts in 60s     |
| **ARP Spoofing**| Multiple MACs claiming the same IP address               | 2+ MACs per IP        |
| **DNS Poisoning**| Divergent DNS answers for the same query                | 5+ different answers  |

### Snort-Style Custom Rules

Create `.rules` files in the `rules/` directory:

```
# Example: Detect SSH connections
alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001; severity:HIGH; flags:S; attack_type:brute_force;)

# Example: Detect DNS zone transfer
alert tcp any any -> any 53 (msg:"DNS zone transfer"; sid:1005; severity:HIGH; flags:S; attack_type:dns_enum;)

# Example: Detect SMB traffic
alert tcp any any -> any 445 (msg:"SMB access attempt"; sid:1007; severity:MEDIUM; flags:S; attack_type:recon;)
```

**Rule syntax:**
```
<action> <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (options)
```

**Available options:**
- `msg:"description"` — Alert message
- `sid:1001` — Signature ID
- `severity:HIGH` — LOW, MEDIUM, HIGH, CRITICAL
- `flags:S` — TCP flags (S=SYN, A=ACK, F=FIN, P=PUSH, R=RST)
- `content:"pattern"` — Payload substring match
- `attack_type:port_scan` — Classification label

### ML-Based Anomaly Detection

The Isolation Forest model extracts **14 features** from sliding traffic windows:

| Feature               | Description                                      |
|-----------------------|--------------------------------------------------|
| packets_per_second    | Packet rate                                      |
| unique_src_ips        | Number of distinct source IPs                    |
| unique_dst_ips        | Number of distinct destination IPs               |
| unique_dst_ports      | Port diversity                                   |
| syn_ratio             | Fraction of pure SYN packets                     |
| avg_payload_size      | Mean payload bytes                               |
| protocol_entropy      | Shannon entropy of protocol distribution         |
| tcp/udp/icmp/arp_ratio| Protocol mix ratios                              |
| avg_dst_port          | Mean destination port number                     |
| port_range_span       | Max port - Min port                              |
| connection_diversity  | Unique (src, dst, port) tuples / total packets   |

**Training modes:**
- **Auto-train**: Collects baseline samples during startup, trains automatically
- **Pre-train**: `python main.py --train` generates synthetic data and saves the model
- **Periodic retrain**: Configurable retraining interval in `config.yaml`

---

## 🔔 Alert Channels

### Terminal (Rich)
Colored alert panels printed directly to the terminal with severity-based styling.

### Log File
Rotating log file at `logs/alerts.log` with configurable size limits and backup count.

### Email (SMTP)
```yaml
# config.yaml
alerts:
  email:
    enabled: true
    smtp_server: "smtp.gmail.com"
    smtp_port: 587
    sender: "nids@yourdomain.com"
    password: ""  # Or set NIDS_EMAIL_PASSWORD env var
    recipients: ["admin@yourdomain.com"]
    min_severity: "HIGH"
```

### Slack Webhook
```yaml
# config.yaml
alerts:
  slack:
    enabled: true
    webhook_url: ""  # Or set NIDS_SLACK_WEBHOOK env var
    channel: "#security-alerts"
    min_severity: "MEDIUM"
```

---

## 📊 Dashboard

The Rich-based CLI dashboard provides real-time monitoring:

```
┌─────────────────────────────────────────────────────────────┐
│        🛡️  NETWORK INTRUSION DETECTION SYSTEM  🛡️           │
├────────────────────┬────────────────────────────────────────┤
│ 📡 Capture Stats   │ 📊 Alert Summary                      │
│  Total: 12,345     │  [By Type]      [By Severity]         │
│  PPS: 45.2         │  port_scan: 12   CRITICAL: 3          │
│  TCP: 8,901 (72%)  │  syn_flood: 5    HIGH: 8              │
│  UDP: 2,134 (17%)  │  brute_force: 3  MEDIUM: 15           │
├────────────────────┤                                        │
│ 🤖 ML Detector     ├────────────────────────────────────────┤
│  Status: ✅ Trained │ 🚨 Recent Alerts                      │
│  Predictions: 892  │  04-11 02:35 | HIGH  | port_scan      │
│  Anomalies: 12     │  04-11 02:34 | CRIT  | syn_flood      │
├────────────────────┤  04-11 02:33 | MED   | brute_force    │
│ 🎯 Top Attackers   │  ...                                   │
│  1. 10.0.0.5  (15) │                                        │
│  2. 10.0.0.3  (8)  │                                        │
└────────────────────┴────────────────────────────────────────┘
```

---

## ⚙️ Configuration

All settings are in `config.yaml`. Key sections:

| Section       | Purpose                                                |
|---------------|--------------------------------------------------------|
| `capture`     | Interface, BPF filter, promiscuous mode                |
| `thresholds`  | Detection sensitivity for each attack type             |
| `rules`       | Rule directory path, enable/disable                    |
| `ml`          | Model params, contamination rate, retrain interval     |
| `alerts`      | Channel settings (terminal, file, email, Slack)        |
| `database`    | SQLite path, max alerts, prune interval                |
| `dashboard`   | Refresh rate, display limits                           |

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/test_detector.py -v

# Run with coverage
pytest tests/test_detector.py -v --cov=src --cov-report=term-missing

# Run a specific test class
pytest tests/test_detector.py::TestRuleEngine -v

# Run a specific test
pytest tests/test_detector.py::TestMLDetector::test_anomaly_detection -v
```

### Test Coverage

- **Database**: CRUD, analytics, pruning, serialization
- **Rule Engine**: Parsing, matching, port ranges, all 5 heuristic detectors
- **ML Detector**: Feature extraction, training, prediction, persistence, edge cases
- **Alert Manager**: Dispatch, DB persistence, severity normalization
- **Integration**: Full pipeline (scan → detect → alert → store)

---

## 🔐 Security Notes

1. **Run as admin/root** — Raw packet capture requires elevated privileges
2. **Sensitive config** — Use environment variables for passwords:
   ```bash
   export NIDS_EMAIL_PASSWORD="your-smtp-password"
   export NIDS_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
   ```
3. **Database** — SQLite file is local; restrict file permissions in production
4. **Network exposure** — This tool only listens; it does not modify or block traffic

---

## 📝 License

MIT License. See LICENSE file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Ensure all tests pass: `pytest tests/ -v`
4. Submit a pull request

---

*Built with Python, Scapy, scikit-learn, SQLAlchemy, and Rich.*
