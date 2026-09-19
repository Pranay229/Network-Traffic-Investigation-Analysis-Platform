# Nova Cyber Spark™ — Network Security Investigation & Monitoring Platform

**Architect & Founder:** Pranay Kumar Mallem  
**Edition:** v2026.1 Enterprise SOC Edition  
**License:** Authorized Defensive & Security Investigation Use Only  

---

## 🛡️ Overview

**Nova Cyber Spark™** is an enterprise-grade Network Security Investigation and Monitoring Platform designed for Security Operations Centers (SOC), network engineers, and digital forensics analysts.

The platform provides end-to-end network visibility: from non-intrusive port scanning and real-time PCAP traffic ingestion to multi-protocol deep packet classification, sliding-window throughput analysis, centralized rule-based threat detections, and publication-ready 17-section forensic PDF incident reports.

---

## ✨ Core Features

- **16-Protocol Forensic Analysis Engine**: Core Network (`IPv4`, `IPv6`, `TCP`, `UDP`, `ICMP`, `ARP`) & Application Protocols (`DNS`, `HTTP`, `HTTPS/TLS`, `DHCP`, `SSH`, `FTP`, `SMTP`, `SMB`, `NTP`, `SNMP`).
- **Reusable Traffic Analysis Engine**: Real-time throughput calculations including Packets/sec (PPS), Bytes/sec (BPS), Connection Rates, and average packet sizes with dynamic sliding time-windows (`5s`, `30s`, `1m`, `5m`).
- **Centralized Rule-Based Detection Engine**: 14 standardized rules (`NET-001` through `NET-014`) for port scan identification, SYN flood detection, traffic volume spikes, repeated connection failures, ARP address inconsistencies, DNS query anomalies, and unencrypted protocol detection.
- **Strict Evidence-Based Reporting**: Observations, technical analyses, and defensive triage recommendations without unsupported speculation.
- **Chronological Security Timeline**: Microsecond-accurate event logging with interactive drawers, multi-severity filters (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and category tagging.
- **IOC Explorer**: Extracts and correlates observable Indicators of Compromise (IPs, domains, URLs, ports, SHA-256 payload hashes).
- **17-Section Forensic PDF Reports**: Dynamic ReportLab generation delivering executive summaries, discovered hosts, active services, protocol breakdowns, traffic timeline graphs, and investigation guidance.
- **Enterprise Application Security**: Argon2id password hashing, JWT authentication, RBAC authorization (`ADMIN`, `ANALYST`, `VIEWER`), IDOR protection, safe subprocess execution (`shell=False`), and Netlify SPA deployment support.

---

## 🏛️ Architecture & Technology Stack

### Frontend
- **React 19** & **TypeScript**
- **Vite 8** with Netlify Single-Page Application (SPA) redirect routing
- **TailwindCSS 4** with Custom SOC Dark Mode Design System
- **Recharts** for real-time throughput metrics and protocol distribution charts
- **Lucide React** cybersecurity icon set

### Backend
- **Python 3.13** & **FastAPI**
- **Wireshark TShark** native packet dissection engine
- **SQLAlchemy 2.0 ORM** with SQLite / PostgreSQL support & automatic schema migrations
- **Pydantic v2** data validation and response schemas
- **ReportLab** enterprise PDF document generation

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.11+
- Node.js 18+
- Wireshark / TShark (installed and added to PATH)

### 2. Backend Setup
```bash
cd backend
python -m venv .venv
# Activate virtualenv (Windows: .venv\Scripts\activate, Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

### 3. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

### 4. Unified Production Server
```bash
# Builds the frontend and serves unified SPA & REST API on port 8001
python run_production.py
```
Open [http://localhost:8001](http://localhost:8001) in your browser.

---

## 🌐 Netlify Deployment

The frontend includes production-ready Netlify configuration (`netlify.toml` and `public/_redirects`):

- **Build Command**: `npm run build`
- **Publish Directory**: `dist`
- **Base Directory**: `frontend` (or `network-traffic-investigation/frontend` depending on repository root)

---

## ⚖️ Copyright & Intellectual Property

© 2026 **Nova Cyber Spark™**. All rights reserved.  
Founder & Chief Architect: **Pranay Kumar Mallem**  
All patents, designs, architectures, and intellectual property rights are reserved.
