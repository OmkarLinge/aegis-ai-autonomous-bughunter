# 🛡️ Aegis AI — Autonomous Bug Hunter

> **Agentic AI system that autonomously explores web applications, detects vulnerabilities, and generates professional security reports.**

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green)
![React](https://img.shields.io/badge/React-18-cyan)
![License](https://img.shields.io/badge/License-MIT-purple)

---

## ⚠️ IMPORTANT DISCLAIMER

> **This tool is for EDUCATIONAL purposes and AUTHORIZED penetration testing ONLY.**
>
> You must only scan systems you **own** or have **explicit written permission** to test.
> Unauthorized scanning is **illegal** under computer fraud and abuse laws worldwide.
> The authors assume no liability for misuse.

---

## 🏗️ Architecture

```
User → React Dashboard → FastAPI Backend → AI Orchestrator
                                                │
                         ┌──────────────────────┼────────────────────────┐
                         │                      │                        │
                    Recon Agent          Endpoint Intel         Strategy Agent
                    (Crawler)            (NLP Classify)         (AI Reasoning)
                         │                      │                        │
                         └──────────────────────┼────────────────────────┘
                                                │
                                         Exploit Agent
                                    (SQLi/XSS/Headers/SSTI)
                                                │
                                      ML Vulnerability Classifier
                                      (Random Forest + Isolation Forest)
                                                │
                                         Report Agent
                                    (PDF / JSON / Markdown)
                                                │
                                       Dashboard + WebSocket
```

---

## 🤖 Agent System

| Agent | Purpose | Techniques |
|-------|---------|------------|
| **Recon Agent** | Discover attack surface | Web crawling, common path probing, tech detection |
| **Endpoint Intelligence** | Classify endpoints | NLP pattern matching, risk scoring |
| **Strategy Agent** | Plan scan order | Rule-based reasoning, priority queuing |
| **Exploit Agent** | Test vulnerabilities | SQLi, XSS, Redirect, SSTI, Headers |
| **ML Classifier** | Predict severity | Random Forest, feature extraction |
| **Anomaly Detector** | Detect blind vulns | Isolation Forest, time-delay analysis |
| **Report Agent** | Generate reports | ReportLab PDF, JSON, Markdown |

---

## 📁 Project Structure

```
aegis-ai-bughunter/
├── backend/
│   ├── main.py              # FastAPI server + WebSocket
│   └── orchestrator.py      # Scan lifecycle manager
├── agents/
│   ├── recon_agent.py       # Reconnaissance
│   ├── endpoint_intelligence_agent.py
│   ├── exploit_agent.py     # Vulnerability testing
│   └── strategy_agent.py    # AI scanning brain
├── scanner/
│   ├── crawler.py           # Web crawler (BFS)
│   ├── request_engine.py    # HTTP layer with rate limiting
│   └── payload_engine.py    # Exploit payload injectors
├── ml_models/
│   ├── vulnerability_classifier.py  # Random Forest
│   └── anomaly_detector.py          # Isolation Forest
├── reports/
│   └── report_generator.py  # PDF/JSON/MD reports
├── database/
│   └── models.py            # SQLAlchemy ORM
├── utils/
│   ├── config.py            # Global configuration
│   └── logger.py            # Structured logging
├── frontend/                # React + Vite + TailwindCSS
│   └── src/
│       ├── pages/
│       │   ├── Dashboard.jsx
│       │   ├── NewScan.jsx
│       │   ├── LiveScan.jsx
│       │   ├── Vulnerabilities.jsx
│       │   └── Reports.jsx
│       └── components/
├── run.py                   # Unified launcher
├── demo_scan.py             # CLI demo scanner
└── README.md
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10+
- Node.js 18+

### 1. Clone / Extract

```bash
unzip aegis-ai-bughunter.zip
cd aegis-ai-bughunter
```

### 2. Backend Setup

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate    # Linux/Mac
# OR
venv\Scripts\activate       # Windows

# Install Python dependencies
pip install -r backend/requirements.txt
```

### 3. Frontend Setup

```bash
cd frontend
npm install
cd ..
```

---

## ▶️ Running the System

### Option A: Full Stack (Recommended)

**Terminal 1 — Backend:**
```bash
python run.py
# Server starts at http://localhost:8000
# API docs at http://localhost:8000/api/docs
```

**Terminal 2 — Frontend:**
```bash
cd frontend
npm run dev
# Dashboard at http://localhost:5173
```

Open **http://localhost:5173** in your browser.

### Option B: CLI Demo (No UI)

```bash
python demo_scan.py https://your-authorized-target.com
```

---

## 🖥️ Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Overview stats, recent scans, charts |
| New Scan | `/scan/new` | Configure and launch a scan |
| Live Monitor | `/live/:id` | Real-time agent activity feed |
| Vulnerabilities | `/vulnerabilities` | Sortable/filterable finding list |
| Reports | `/reports` | Download PDF/JSON/Markdown reports |

---

## 🔬 Example Scan Workflow

1. Open the dashboard at `http://localhost:5173`
2. Click **New Scan**
3. Enter your authorized target URL (e.g., `https://your-lab.example.com`)
4. Select vulnerability test types
5. Check the authorization confirmation
6. Click **Launch Aegis Scan**
7. Watch the **Live Monitor** for real-time agent activity
8. View findings in **Vulnerabilities**
9. Download your report from **Reports**

---

## 🧠 AI Techniques Used

| Domain | Technique | Location |
|--------|-----------|----------|
| Machine Learning | Random Forest Classifier | `ml_models/vulnerability_classifier.py` |
| Anomaly Detection | Isolation Forest | `ml_models/anomaly_detector.py` |
| NLP Classification | Regex + pattern matching | `agents/endpoint_intelligence_agent.py` |
| Agentic Reasoning | Rule-based decision engine | `agents/strategy_agent.py` |
| Multi-Agent Coordination | Async orchestration | `backend/orchestrator.py` |
| Feature Engineering | HTTP response features | `ml_models/vulnerability_classifier.py` |

---

## 🔒 Security Tests Included

- **SQL Injection** — Error-based, boolean-based detection
- **Cross-Site Scripting (XSS)** — Reflected XSS detection
- **Open Redirect** — URL redirect parameter testing
- **Security Header Misconfiguration** — CSP, HSTS, X-Frame-Options, etc.
- **Server-Side Template Injection (SSTI)** — Template expression evaluation
- **Server Version Disclosure** — Header-based version exposure
- **Technology Fingerprinting** — CMS, framework, server detection

---

## ⚙️ Configuration

Edit `utils/config.py` to customize:

```python
ScanConfig(
    max_depth=3,              # Crawl depth (1-5)
    max_endpoints=200,        # Max endpoints per scan
    request_timeout=10,       # HTTP timeout (seconds)
    delay_between_requests=0.5  # Rate limiting
)
```

---

## 📊 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scans` | Start a new scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan state |
| `GET` | `/api/scans/{id}/vulnerabilities` | Get findings |
| `GET` | `/api/scans/{id}/logs` | Get agent logs |
| `GET` | `/api/scans/{id}/attack-graph` | Get graph data |
| `GET` | `/api/scans/{id}/report/{format}` | Download report |
| `DELETE` | `/api/scans/{id}` | Cancel a scan |
| `WS` | `/ws/{id}` | Live scan events |

Full interactive docs: `http://localhost:8000/api/docs`

---

## 🏆 FAANG-Level Features

- ✅ **Multi-Agent Architecture** — Specialized agents with clear responsibilities
- ✅ **Machine Learning** — Real Random Forest + Isolation Forest models
- ✅ **WebSocket Real-Time** — Live agent event streaming
- ✅ **Async Python** — Full asyncio/FastAPI backend
- ✅ **Professional Reports** — PDF with ReportLab, JSON, Markdown
- ✅ **Attack Graph** — Visual vulnerability chain visualization
- ✅ **AI Reasoning Logs** — Transparent agent decision display
- ✅ **Rate Limiting** — Responsible scanning with configurable delays
- ✅ **Technology Detection** — 20+ tech signatures detected
- ✅ **Clean Architecture** — Modular, testable, documented code

---

## 📄 License

MIT License — see `LICENSE` file.

---

*Built with ❤️ for the security community. Stay ethical.*
