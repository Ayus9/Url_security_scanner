# 🔐 Smart URL Security Scanner


> **A full-stack cybersecurity tool that performs deep URL analysis using local heuristics, VirusTotal API (70+ engines), and OWASP ZAP active scanning — built as a BCA Final Year Project.**

</div>

---

## ⚠️ Disclaimer

> This tool is built **strictly for educational and security awareness purposes only.**  
> Only scan URLs that you **own** or have **explicit written permission** to test.  
> Unauthorized scanning of third-party websites may be **illegal** in your jurisdiction.  
> The author takes no responsibility for any misuse of this tool.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [VirusTotal Setup](#-virustotal-setup)
- [OWASP ZAP Setup](#-owasp-zap-setup)
- [Risk Scoring](#-risk-scoring)
- [What I Learned](#-what-i-learned)
- [Future Improvements](#-future-improvements)
- [Contributing](#-contributing)
- [License](#-license)
- [Author](#-author)

---

## ✨ Features

### 🔍 Local URL Intelligence (No API needed — instant results)

| # | Check | What It Detects |
|---|-------|----------------|
| 1 | HTTPS Verification | Missing SSL/TLS encryption |
| 2 | IP-based URL | Direct IP URLs used in phishing |
| 3 | Subdomain Analysis | Excessive subdomain nesting |
| 4 | Brand Keyword Detection | Fake PayPal, Amazon, bank pages |
| 5 | URL Length | Abnormally long suspicious URLs |
| 6 | @ Symbol Obfuscation | user@evil.com URL tricks |
| 7 | Unicode / IDN Characters | Homograph attacks |
| 8 | SQL Injection Patterns | ' OR 1=1, UNION SELECT, DROP TABLE |
| 9 | XSS Payloads | script tags, onerror=, alert() |
| 10 | Path Traversal | ../ directory climbing |
| 11 | Open Redirect | Redirect parameter abuse |
| 12 | High-Risk TLDs | .xyz .tk .ml .cf .gq |
| 13 | Multiple Hyphens | Domain spoofing patterns |
| 14 | Non-Standard Ports | Unusual port numbers |

### 🛡️ VirusTotal Integration
- Submits URL to **70+ antivirus engines** simultaneously
- Shows malicious / suspicious / harmless / undetected counts
- Lists which specific engines flagged the URL and why
- Direct link to the full VirusTotal report
- Free API: 4 requests/minute, 500/day

### ⚡ OWASP ZAP Active Scanning
- **Spider scan** — crawls and maps all pages of the target
- **Active scan** — real HTTP-based vulnerability testing
- Returns alerts sorted by Risk Level (High → Medium → Low → Info)
- Shows **CWE ID** and **WASC ID** for every vulnerability
- Provides actionable fix/solution for each alert found

### 📊 Smart Aggregate Risk Score
- Combines all 3 sources into one final score (0–100)
- Color-coded: 🟢 LOW | 🟡 MEDIUM | 🔴 HIGH
- Tailored recommendations based on risk level

### 🎨 UI Features
- Dark hacker-style terminal aesthetic
- Matrix rain canvas animation background
- Animated risk gauge with color transitions
- Collapsible ZAP alert accordion with CWE/WASC tags
- Scan history (last 20 scans)
- Export full report as .txt
- Printable report page at /report

---

## 🛠️ Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Language | Python | 3.10+ | Core backend |
| Web Framework | Flask | 3.0.3 | REST API + routing |
| CORS | Flask-CORS | 4.0.1 | Cross-origin requests |
| HTTP Client | Requests | 2.32.3 | External API calls |
| Frontend | HTML5 | — | Page structure |
| Styling | CSS3 | — | Dark terminal UI |
| Interactivity | Vanilla JavaScript | ES6+ | DOM + Fetch API |
| Animation | Canvas API | — | Matrix rain effect |
| Threat Intel | VirusTotal API | v3 | URL reputation |
| Vuln Scanner | OWASP ZAP | 2.15+ | Active scanning |

---

    ## 📂 Project Structure

    ```
    url-scanner/
    │
    ├── app.py                    ← Flask app — all routes & config
    ├── requirements.txt          ← Python dependencies
    ├── README.md                 ← This file
    ├── LICENSE                   ← MIT License
    ├── .gitignore                ← Git ignore rules
    │
    ├── utils/                    ← Backend logic (modular)
    │   ├── __init__.py
    │   ├── local_analyzer.py     ← 14 heuristic URL checks
    │   ├── virustotal.py         ← VirusTotal API v3
    │   ├── zap_scanner.py        ← OWASP ZAP spider + scan
    │   └── risk_calculator.py    ← Weighted score formula
    │
    ├── templates/                ← Jinja2 HTML (Flask)
    │   ├── index.html            ← Main scanner page
    │   └── report.html           ← Printable report page
    │
    └── static/
        ├── css/
        │   └── style.css         ← Dark hacker stylesheet
        └── js/
            ├── matrix.js         ← Matrix rain animation
            ├── scanner.js        ← Scanner logic + API calls
            └── report.js         ← Report page renderer
    ```

    ---

## ⚙️ How It Works

```
┌──────────────────────────────────────────────────┐
│                  USER BROWSER                     │
│         Enter URL  →  Click SCAN NOW              │
└─────────────────────┬────────────────────────────┘
                      │  POST /api/scan
                      ▼
┌──────────────────────────────────────────────────┐
│             FLASK BACKEND  (app.py)               │
│                                                   │
│  ┌─────────────────────────────────────────────┐  │
│  │  local_analyzer.py — instant heuristics     │  │
│  └──────────────────────┬──────────────────────┘  │
│                          │                         │
│  ┌──────────────┐  ┌─────▼──────────────────────┐ │
│  │virustotal.py │  │     zap_scanner.py          │ │
│  │  ~15 seconds │  │     ~60-90 seconds          │ │
│  └──────┬───────┘  └──────────────┬─────────────┘ │
│         │                         │                │
│  ┌──────▼─────────────────────────▼─────────────┐ │
│  │         risk_calculator.py                   │ │
│  │   Aggregate = local + VT weight + ZAP weight │ │
│  └──────────────────────┬───────────────────────┘ │
└─────────────────────────┼────────────────────────┘
                          │  JSON Response
                          ▼
┌──────────────────────────────────────────────────┐
│             FRONTEND  (scanner.js)                │
│  Risk Gauge + Issues + VT Panel + ZAP Alerts      │
└──────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites
- Python 3.10+ → [python.org](https://python.org)
- pip (comes with Python)
- Git → [git-scm.com](https://git-scm.com)

### Step 1 — Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/url-security-scanner.git
cd url-security-scanner
```

### Step 2 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 3 — Run the server
```bash
python app.py
```

You should see:
```
==================================================
  Smart URL Security Scanner
  Open: http://127.0.0.1:5000
==================================================
 * Running on http://127.0.0.1:5000
```

### Step 4 — Open browser
```
http://localhost:5000
```

✅ Works immediately with local analysis. VirusTotal and ZAP are optional.

---

## 🔧 Configuration

All config via environment variables — no hardcoded secrets.

| Variable | Default | Description |
|----------|---------|-------------|
| `VT_API_KEY` | `""` | Your VirusTotal API key |
| `ZAP_URL` | `http://localhost:8080` | OWASP ZAP daemon URL |
| `ZAP_KEY` | `changeme` | OWASP ZAP API key |

**Windows:**
```cmd
set VT_API_KEY=your_key_here
python app.py
```

**Mac / Linux:**
```bash
export VT_API_KEY=your_key_here
python app.py
```

---

## 📖 Usage

### Basic scan
1. Open `http://localhost:5000`
2. Enter a URL → click **SCAN NOW**
3. See risk score, issues, checks, recommendations

### With VirusTotal
1. Set `VT_API_KEY` environment variable
2. Tick **🛡 VirusTotal** checkbox
3. Scan — results in ~15 seconds

### With OWASP ZAP
1. Start ZAP daemon (see setup below)
2. Tick **⚡ OWASP ZAP** checkbox
3. Scan — results in ~60-90 seconds

### Test URLs to try right now

```
# Should score LOW (safe)
https://google.com

# Should score MEDIUM (suspicious)
https://paypal-secure-verify.xyz/account

# Should score HIGH (dangerous)
http://192.168.1.1/login?id=1' OR 1=1--
```

---

## 🔌 API Reference

Base URL: `http://localhost:5000`

### GET `/api/health`
Check backend status.
```json
{ "status": "online", "vt_ready": false, "zap_url": "http://localhost:8080" }
```

### POST `/api/scan`
Full scan endpoint.

Request:
```json
{ "url": "https://example.com", "virustotal": true, "zap": false }
```

Response:
```json
{
  "local": {
    "score": 5,
    "issues": [],
    "checks": [{"label": "HTTPS", "status": "pass"}],
    "recommendations": ["URL appears relatively safe."]
  },
  "virustotal": {
    "available": true,
    "malicious": 0,
    "suspicious": 0,
    "total_engines": 72
  },
  "aggregate_score": 5
}
```

### POST `/api/virustotal`
VirusTotal only: `{ "url": "https://example.com" }`

### POST `/api/zap`
ZAP only: `{ "url": "https://example.com" }`

---

## 🛡️ VirusTotal Setup

1. Go to [virustotal.com](https://www.virustotal.com) → Sign up free
2. Click avatar → **API Key** → Copy
3. Set environment variable:
```bash
export VT_API_KEY=paste_your_key_here
```

| Limit | Free Tier |
|-------|-----------|
| Requests/minute | 4 |
| Requests/day | 500 |
| Engines | 70+ |
| Cost | Free |

---

## ⚡ OWASP ZAP Setup

Download: [zaproxy.org/download](https://www.zaproxy.org/download/)

**Windows:**
```cmd
zap.bat -daemon -port 8080 -config api.key=changeme
```

**Mac/Linux:**
```bash
./zap.sh -daemon -port 8080 -config api.key=changeme
```

Set key:
```bash
export ZAP_KEY=changeme
```

> ⚠️ ZAP sends real HTTP requests. Only test on sites you own.

---

## 📊 Risk Scoring

```
Final Score = local_score
            + (malicious_engines  × 5)
            + (suspicious_engines × 2)
            + (zap_high_alerts    × 10)
            + (zap_medium_alerts  × 5)
            + (zap_low_alerts     × 1)

Capped at 100
```

| Score | Risk | Action |
|-------|------|--------|
| 0–39 | 🟢 LOW | Safe to visit |
| 40–69 | 🟡 MEDIUM | Caution advised |
| 70–100 | 🔴 HIGH | Do NOT visit |

---

## 🧠 What I Learned

**Security Concepts:**
- How SQL Injection, XSS, Path Traversal attacks work
- Phishing domain techniques (subdomain nesting, brand spoofing, homographs)
- OWASP Top 10 vulnerabilities and detection methods
- How VirusTotal aggregates threat intelligence
- CWE and WASC vulnerability classification systems

**Technical Skills:**
- Flask REST API design with modular architecture
- Third-party API integration (VirusTotal v3)
- Automating security tools via REST API (OWASP ZAP)
- Regex pattern matching for security heuristics
- Vanilla JavaScript: Fetch API, async/await, DOM manipulation
- Canvas API for procedural animations
- Weighted scoring algorithm design

---

## 🔮 Future Improvements

- [ ] PDF report export
- [ ] Database — store full scan history (SQLite)
- [ ] User login and personal scan dashboard
- [ ] Bulk URL scanning via CSV upload
- [ ] Email alerts for HIGH risk URLs
- [ ] WHOIS domain lookup integration
- [ ] SSL certificate expiry checker
- [ ] Shodan API for IP reputation
- [ ] Docker containerization
- [ ] Deploy to cloud (Render / Railway)

---

## 🤝 Contributing

1. Fork this repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit: `git commit -m "Add: your feature"`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Ayush** — BCA Student | Cybersecurity Enthusiast

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/YOUR_PROFILE)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/YOUR_USERNAME)

---

## ⭐ Support

If this project helped you:
- ⭐ **Star** this repo
- 🍴 **Fork** and build your version
- 📢 **Share** with classmates
- 🐛 **Open an issue** for bugs

---

<div align="center">

**Built with 💚 for educational purposes**

*Smart URL Security Scanner — BCA Final Year Project*

*⚠️ Educational and security awareness use only*

</div>
