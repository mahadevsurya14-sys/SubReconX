<p align="center">
  <img src="subreconx/static/img/banner.svg" alt="SubReconX Banner" width="100%"/>
</p>

<p align="center">
  <a href="#features"><img src="https://img.shields.io/badge/status-active_development-00ff88?style=flat-square&logo=statuspage&logoColor=white" alt="Status"/></a>
  <a href="#installation"><img src="https://img.shields.io/badge/python-3.10%2B-3572A5?style=flat-square&logo=python&logoColor=white" alt="Python"/></a>
  <a href="#tech-stack"><img src="https://img.shields.io/badge/framework-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow?style=flat-square" alt="License"/></a>
  <a href="#"><img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue?style=flat-square" alt="Platform"/></a>
</p>

<p align="center">
  <b>Advanced Subdomain Discovery & Attack Surface Mapping Platform</b><br/>
  <sub>For authorized penetration testing, bug bounty reconnaissance, and security research.</sub>
</p>

---

## ⚠️ Responsible Use Disclaimer

> **SubReconX is designed for authorized security assessments only.**
>
> - Only scan domains you **own** or have **explicit written permission** to assess.
> - The tool enforces scope restrictions — respect them.
> - This tool does **not** exploit vulnerabilities, bypass authentication, or perform denial-of-service attacks.
> - You are responsible for complying with all applicable laws and regulations.

---

## 🔍 Overview

SubReconX is a modular, production-quality platform that discovers subdomains associated with a target domain, verifies DNS resolution, optionally probes HTTP/HTTPS availability, and produces professional reports — all through a sleek cybersecurity dashboard.

It is **not** a thin wrapper around a CLI tool. SubReconX has its own orchestration pipeline, data storage, historical analysis, scope enforcement, and reporting engine.

---

## ✨ Features

| Category | Capabilities |
|----------|-------------|
| **🔎 Discovery** | Passive subdomain enumeration via Subfinder (+ optional Amass), result normalization & deduplication |
| **🌐 DNS Verification** | A / AAAA / CNAME record resolution, wildcard detection, configurable resolvers |
| **📡 HTTP Probing** | Status codes, response times, page titles, redirect tracking — rate-limited & timeout-bounded |
| **📊 Analysis** | Historical scan comparison, new/removed subdomain detection, grouping by IP/source/status |
| **🖥️ Dashboard** | Dark-themed responsive web UI with search, filters, pagination, live scan progress |
| **📄 Reporting** | Downloadable CSV, JSON, and professional HTML reports with full metadata |
| **🔒 Security** | Scope enforcement, input validation, command injection prevention, no credential storage |
| **📦 Storage** | SQLite-backed scan history with full audit trail |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Dashboard (HTML/CSS/JS)               │
├─────────────────────────────────────────────────────────┤
│                    FastAPI REST API                       │
├──────────┬──────────┬──────────┬──────────┬──────────────┤
│ Discovery│   DNS    │  HTTP    │Historical│  Reporting   │
│  Engine  │ Resolver │ Prober   │Comparator│   Engine     │
├──────────┴──────────┴──────────┴──────────┴──────────────┤
│          Scope Manager  ·  Domain Validator              │
├─────────────────────────────────────────────────────────┤
│               SQLite Database Layer                      │
└─────────────────────────────────────────────────────────┘
```

<details>
<summary><b>📁 Project Structure</b></summary>

```
SubReconX/
├── run.py                        # Application entry point
├── requirements.txt              # Production dependencies
├── requirements-dev.txt          # Development dependencies
├── pyproject.toml                # Project metadata
├── .env.example                  # Configuration template
├── .gitignore
│
├── subreconx/                    # Main package
│   ├── __init__.py
│   ├── config.py                 # Settings (env-based)
│   ├── models.py                 # Pydantic data models
│   ├── exceptions.py             # Custom exceptions
│   │
│   ├── core/                     # Business logic
│   │   ├── scope.py              # Scope authorization
│   │   ├── domain_validator.py   # Domain validation
│   │   ├── normalizer.py         # Hostname normalization
│   │   ├── dns_resolver.py       # DNS resolution engine
│   │   ├── http_prober.py        # HTTP/HTTPS prober
│   │   ├── comparator.py         # Scan comparison
│   │   ├── orchestrator.py       # Scan pipeline
│   │   └── discovery/
│   │       ├── base.py           # Abstract engine
│   │       ├── subfinder.py      # Subfinder integration
│   │       └── amass.py          # Amass integration
│   │
│   ├── db/                       # Data layer
│   │   ├── database.py           # SQLite setup
│   │   └── repositories.py       # CRUD operations
│   │
│   ├── api/                      # FastAPI backend
│   │   ├── app.py                # App factory
│   │   ├── dependencies.py
│   │   └── routes/
│   │       ├── scans.py
│   │       ├── results.py
│   │       ├── reports.py
│   │       └── health.py
│   │
│   ├── reporting/                # Report generators
│   │   ├── csv_report.py
│   │   ├── json_report.py
│   │   └── html_report.py
│   │
│   ├── static/                   # Frontend assets
│   │   ├── css/dashboard.css
│   │   ├── js/dashboard.js
│   │   └── img/banner.svg
│   │
│   └── templates/                # Jinja2 templates
│       ├── dashboard.html
│       └── report.html
│
└── tests/                        # Automated tests
    ├── conftest.py
    ├── test_config.py
    ├── test_domain_validator.py
    ├── test_scope.py
    └── ...
```

</details>

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| Web Framework | FastAPI + Uvicorn |
| Data Validation | Pydantic v2 |
| DNS Resolution | dnspython |
| HTTP Client | HTTPX (async) |
| Database | SQLite via aiosqlite |
| Templating | Jinja2 |
| Testing | Pytest + pytest-asyncio |
| Enumeration | Subfinder (primary), Amass (optional) |

---

## 📦 Installation

### Prerequisites

- **Python 3.10+** installed
- **pip** package manager
- **Subfinder** (recommended) — [Install Guide](https://github.com/projectdiscovery/subfinder#installation)
- **Amass** (optional) — [Install Guide](https://github.com/owasp-amass/amass#installation)

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/SubReconX.git
cd SubReconX

# 2. Create a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env as needed

# 5. Launch
python run.py
```

### Platform-Specific Notes

<details>
<summary><b>🪟 Windows 11</b></summary>

```powershell
# Ensure Python is in PATH
python --version   # Should show 3.10+

# Create & activate venv
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install
pip install -r requirements.txt

# Run
python run.py
```

> **Note:** If PowerShell blocks script execution, run:
> `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`

</details>

<details>
<summary><b>🐧 Kali Linux</b></summary>

```bash
# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Ensure ~/go/bin is in PATH
export PATH=$PATH:~/go/bin

# Setup SubReconX
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

</details>

---

## 🚀 Usage

### Web Dashboard

After launching with `python run.py`:

1. Open **http://127.0.0.1:8000** in your browser
2. Enter a target domain you are authorized to assess
3. Configure scan options (DNS verification, HTTP probing)
4. Review the scope display and start the scan
5. Monitor progress in real-time
6. Export results as CSV, JSON, or HTML

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scans` | Start a new scan |
| `GET` | `/api/scans/{id}` | Get scan status |
| `GET` | `/api/scans/{id}/results` | Get scan results |
| `GET` | `/api/scans` | List scan history |
| `POST` | `/api/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/reports/{id}/{format}` | Download report (csv/json/html) |

Full interactive API documentation is available at **http://127.0.0.1:8000/docs** (Swagger UI).

---

## 📄 Reports

SubReconX generates three report formats:

| Format | Content |
|--------|---------|
| **CSV** | Flat tabular data — hostnames, sources, DNS records, HTTP status |
| **JSON** | Structured data — full scan results with metadata |
| **HTML** | Professional styled report — summary, charts, detailed tables |

All reports include: scan metadata, timestamps, scope information, source attribution, DNS results, HTTP status (when collected), errors, and warnings.

---

## ⚙️ Configuration

All settings can be configured via environment variables (prefix: `SUBRECONX_`) or a `.env` file. See [`.env.example`](.env.example) for all available options.

Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `SUBRECONX_LOG_LEVEL` | `INFO` | Logging verbosity |
| `SUBRECONX_HOST` | `127.0.0.1` | Server bind address |
| `SUBRECONX_PORT` | `8000` | Server port |
| `SUBRECONX_DNS_RESOLVERS` | `["8.8.8.8","1.1.1.1","9.9.9.9"]` | DNS resolvers |
| `SUBRECONX_HTTP_CONCURRENCY` | `10` | Max parallel HTTP probes |
| `SUBRECONX_HTTP_RATE_LIMIT` | `20.0` | Max HTTP requests/second |

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest -v

# Run with coverage
pytest --cov=subreconx --cov-report=term-missing

# Run specific test module
pytest tests/test_domain_validator.py -v
```

---

## 🔒 Security Design

- **Scope enforcement** — Active checks are locked to explicitly authorized domains
- **Input validation** — All domain inputs are sanitized and checked for injection patterns
- **Safe subprocess** — External tools are called with list-form arguments, never `shell=True`
- **No credential storage** — API keys loaded from environment variables only
- **Conservative probing** — Rate limiting, timeouts, concurrency caps on all network calls
- **No exploitation** — The tool discovers and reports; it does not attack, authenticate, or crawl

---

## 🚧 Known Limitations

- Subdomain discovery relies on passive sources — results depend on public data availability
- External tools (Subfinder, Amass) must be installed separately
- SQLite is suitable for local use; not designed for high-concurrency multi-user deployments
- HTTP probing respects `robots.txt` conventions but does not parse them automatically
- Wildcard DNS detection uses heuristics and may produce false positives

---

## 🗺️ Roadmap

- [ ] Additional passive sources (Certificate Transparency, SecurityTrails API)
- [ ] Subdomain wordlist brute-forcing (opt-in, with rate limiting)
- [ ] Technology fingerprinting integration
- [ ] Slack/Discord/Webhook notifications
- [ ] Docker deployment support
- [ ] Multi-user authentication for team use
- [ ] PDF report generation

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with 🔒 for the security community. Use responsibly.</sub>
</p>
