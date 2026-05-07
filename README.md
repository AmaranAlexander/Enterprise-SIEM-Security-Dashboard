# Enterprise Security Monitoring Platform

A full-stack Security Information and Event Management (SIEM) platform that collects real Windows security events, correlates them against MITRE ATT&CK® detection rules, and displays everything in a live React dashboard.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Architecture                                │
│                                                                     │
│  Windows Event Log                                                  │
│  (Security / System)                                                │
│        │                                                            │
│        ▼  polls every 10s                                           │
│  Python Watcher ──► FastAPI Backend ──► SQLite Database             │
│                          │                    │                     │
│                    Parser + Risk          Correlation               │
│                    Scorer                 Rule Engine               │
│                          │                    │                     │
│                          └────────────────────┘                     │
│                                    │                                │
│                                    ▼                                │
│                           React Dashboard                           │
│                    (auto-refreshes every 30s)                       │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

- **Real-time Windows event monitoring** — watches the Security and System logs live using `wevtutil`, no agents required
- **MITRE ATT&CK® aligned alerts** — every alert tagged with technique ID and tactic (T1110, T1078, T1021, T1046, etc.)
- **YAML correlation rules** — brute force, port scan, privilege escalation, lateral movement detection out of the box; add your own without touching Python
- **Risk scoring (0–100)** — every event scored by severity, event type, MITRE technique, and threat intel
- **Multi-format log ingestion** — Syslog RFC 3164/5424, CEF (Palo Alto / ArcSight), JSON, Windows Event XML
- **Interactive dashboard** — dark-themed, production-grade UI with event timeline, severity breakdown, top source IPs, and MITRE heatmap
- **Forensic investigation** — pivot from any IP or username to see every associated event and alert
- **Alert workflow** — acknowledge, close, or mark false positives with full audit trail
- **CSV / JSON export** — download filtered event sets for offline analysis
- **Demo data included** — 7 days of realistic attack scenarios generated on first run so the dashboard is immediately useful

---

## Quick Start

**Prerequisites:** Python 3.10+, Node.js 18+, Windows (for live event monitoring)

```powershell
# 1. Clone the repo
git clone https://github.com/AmaranAlexander/Enterprise-SIEM-Security-Dashboard.git
cd Enterprise-SIEM-Security-Dashboard

# 2. Start everything with one command
.\scripts\start.ps1
```

`start.ps1` will automatically:
1. Install Python dependencies
2. Generate 7 days of demo security events (first run only)
3. Start the FastAPI backend on **http://localhost:8000**
4. Install frontend dependencies and start the React dev server on **http://localhost:5173**

Open **http://localhost:5173** in your browser — the dashboard loads with data immediately.

---

## Manual Setup

If you prefer to run each piece separately:

```powershell
# Terminal 1 — Backend
pip install -r requirements.txt
py scripts/generate_demo_data.py   # only needed on first run
py -m backend.main
```

```powershell
# Terminal 2 — Frontend
cd frontend
npm install --legacy-peer-deps
npm run dev
```

---

## Live Windows Event Monitoring

The watcher connects directly to the Windows Event Log and ships new events to the SIEM in real time. **Run as Administrator** to access the Security log.

```powershell
# Watch Security + System logs (run as Administrator)
.\scripts\start_watcher.ps1

# System log only — no admin required
.\scripts\start_watcher.ps1 -Channels System

# Dry run — print events to console without sending to SIEM
.\scripts\start_watcher.ps1 -DryRun

# Backfill the last 60 minutes of history on startup
.\scripts\start_watcher.ps1 -Backfill 60
```

The watcher saves a bookmark in `.watcher_state.json` and resumes exactly where it left off on restart — no duplicate events.

### Monitored Event IDs

| Event ID | Description | MITRE Technique | Severity |
|----------|-------------|-----------------|----------|
| 4625 | Failed logon | T1110 Brute Force | Medium |
| 4624 | Successful logon (non-system) | — | Info |
| 4672 | Admin privileges assigned at logon | T1078 Valid Accounts | Medium |
| 4740 | Account locked out | T1110 Brute Force | High |
| 4720 | New user account created | T1136 Create Account | Medium |
| 4697 | Service installed | T1543 Create Service | High |
| 4698 | Scheduled task created | T1053 Scheduled Task | Medium |
| 4719 | Audit policy changed | T1562 Defense Evasion | High |
| 4688 | Process created | — | Low |
| 1102 | Security log cleared | T1070 Indicator Removal | Critical |
| 7045 | New service (System log) | T1543 Create Service | High |
| 7036 | Service state changed | — | Info |

### Generating Test Events

Run these in any PowerShell window to produce real security events:

```powershell
# Brute force — triggers an alert after 5 failures
1..10 | ForEach-Object {
  net use \\localhost\ipc$ /user:hacker wrongpassword 2>$null
  Start-Sleep 1
}

# Service install (high severity)
New-Service -Name "TestSvc" -BinaryPathName "C:\Windows\System32\notepad.exe"
Remove-Service -Name "TestSvc" -ErrorAction SilentlyContinue

# Service restart (System log)
Restart-Service -Name Spooler
```

Events appear in the dashboard within ~10 seconds.

---

## Detection Rules

Rules are YAML files in `backend/rules/`. The correlation engine runs automatically whenever new events arrive.

| Rule | Triggers When | MITRE | Severity |
|------|--------------|-------|----------|
| Brute Force | 5+ failed logins from same IP in 10 min | T1110 | High |
| Port Scan | 10+ scan events from same IP in 5 min | T1046 | Medium |
| Privilege Escalation | 5+ privilege events from same user in 15 min | T1078 | Critical |
| Lateral Movement | 3+ logins to 3+ distinct hosts in 30 min | T1021 | Critical |

### Adding a Custom Rule

Create a new `.yaml` file in `backend/rules/` and restart the backend:

```yaml
id: my_rule_001
name: "Repeated Failed Logins"
description: "Detects brute force attempts against local accounts."
mitre_technique: "T1110"
mitre_tactic: "credential-access"
severity: high
risk_score: 75
conditions:
  - event_type: failed_login
    min_count: 10
    window_minutes: 5
    group_by: source_ip
alert_template: "Brute force detected from {source_ip}"
```

---

## Dashboard Pages

| Page | What It Shows |
|------|--------------|
| **Dashboard** | Event timeline, severity breakdown, top source IPs, MITRE heatmap, recent alerts |
| **Events** | Full searchable/filterable event log with drill-down detail panel |
| **Alerts** | Correlation rule hits grouped by severity with workflow status buttons |
| **Investigation** | Pivot by IP or username — see all associated events and alerts |
| **Rules** | All loaded YAML rules with alert counts |
| **Wiki** | Built-in reference guide for the platform |

---

## API Reference

The backend exposes a full REST API. Interactive docs available at **http://localhost:8000/docs**.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/events` | List events (filterable by severity, IP, type, time range) |
| GET | `/api/events/{id}` | Single event with related events |
| GET | `/api/events/export` | Download as CSV or JSON |
| GET | `/api/alerts` | List alerts by status / severity |
| PATCH | `/api/alerts/{id}` | Update alert status |
| GET | `/api/stats/summary` | Dashboard counts |
| GET | `/api/stats/timeline` | Event counts over time |
| GET | `/api/stats/top-sources` | Top source IPs by event count |
| GET | `/api/stats/mitre-coverage` | MITRE technique coverage |
| GET | `/api/stats/investigation/ip/{ip}` | All activity for an IP |
| GET | `/api/stats/investigation/user/{user}` | All activity for a username |
| POST | `/api/ingest` | Ingest a batch of log lines |
| POST | `/api/ingest/correlate` | Manually trigger correlation engine |
| GET | `/api/rules` | List all loaded detection rules |
| GET | `/api/health` | Health check |

### Ingesting External Logs

```bash
# Syslog
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"lines": ["<38>May 15 10:23:01 web-01 sshd[1234]: Failed password for root from 185.220.101.47 port 54321 ssh2"], "run_correlation": true}'

# JSON
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"lines": ["{\"timestamp\":\"2025-05-06T10:00:00\",\"event_type\":\"failed_login\",\"source_ip\":\"185.220.101.47\",\"severity\":\"high\",\"message\":\"Login failed\"}"], "format": "json"}'
```

---

## Project Structure

```
├── backend/
│   ├── main.py                  # FastAPI app entry point
│   ├── config.py                # Settings (DB path, CORS, etc.)
│   ├── database.py              # SQLAlchemy engine + session
│   ├── models/
│   │   ├── event.py             # Event database model
│   │   └── alert.py             # Alert database model
│   ├── routers/
│   │   ├── events.py            # /api/events
│   │   ├── alerts.py            # /api/alerts
│   │   ├── stats.py             # /api/stats/*
│   │   ├── ingest.py            # /api/ingest
│   │   └── rules.py             # /api/rules
│   ├── services/
│   │   ├── parsers/
│   │   │   ├── syslog_parser.py # RFC 3164/5424
│   │   │   ├── cef_parser.py    # Common Event Format
│   │   │   ├── json_parser.py   # Generic JSON logs
│   │   │   └── windows_parser.py# Windows Event XML
│   │   ├── ingestion.py         # Format detection + pipeline
│   │   ├── correlation.py       # YAML rule engine
│   │   └── enrichment.py        # IP geolocation
│   ├── rules/
│   │   ├── brute_force.yaml
│   │   ├── port_scan.yaml
│   │   ├── privilege_escalation.yaml
│   │   └── lateral_movement.yaml
│   └── utils/
│       └── risk_score.py        # 0-100 risk scoring
├── frontend/
│   └── src/
│       ├── pages/               # Dashboard, Events, Alerts, Investigation, Rules, Wiki
│       ├── components/          # Layout, charts, badges, tables
│       ├── hooks/               # React Query data hooks
│       ├── api/                 # Axios client
│       ├── utils/               # Time formatting helpers
│       └── types/               # TypeScript interfaces
├── scripts/
│   ├── generate_demo_data.py    # Generates 7 days of realistic demo events
│   ├── watch_windows_events.py  # Windows Event Log watcher
│   ├── start_watcher.ps1        # Watcher launcher (with admin check)
│   └── start.ps1                # One-command startup script
├── requirements.txt
└── README.md
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python 3.10+) |
| Database | SQLite + SQLAlchemy (WAL mode) |
| Frontend | React 19, TypeScript, Vite |
| Styling | Tailwind CSS |
| Charts | Recharts |
| Data Fetching | TanStack Query (React Query) |
| Routing | React Router v7 |
| Log Collection | Python + wevtutil (Windows) |
| Rule Engine | YAML + Python sliding window |

---

## Comparison to Commercial SIEMs

| Feature | This Platform | Splunk | Elastic SIEM |
|---------|--------------|--------|--------------|
| Log Ingestion | ✓ | ✓ | ✓ |
| MITRE ATT&CK | ✓ | ✓ (add-on) | ✓ |
| Correlation Rules | YAML | SPL | EQL |
| Real-time Monitoring | ✓ | ✓ | ✓ |
| Cost | Free | $10k+/yr | $$$ |
| Setup Time | 2 min | Days | Hours |

---

## Extending the Platform

- **Real-time syslog receiver** — add a UDP socket listener in `backend/routers/ingest.py`
- **Threat intelligence** — integrate AbuseIPDB or VirusTotal in `backend/services/enrichment.py`
- **Email / Slack alerts** — add notifications in `backend/services/alerting.py`
- **Production database** — swap SQLite for PostgreSQL + TimescaleDB for large-scale deployments
- **Authentication** — JWT auth is partially wired in `backend/config.py`

---

*Built by Amaran Alexander*
