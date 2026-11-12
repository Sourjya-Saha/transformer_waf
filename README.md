# 🛡️ Transformer-Based Web Application Firewall (WAF)

> **Deep Learning Anomaly Detection, Zero-Regex Threat Inspection, Live IPv4/IPv6 Geolocation Intelligence, and Retro macOS SOC Terminal Console.**

---

## 📌 Executive Summary

Modern web application firewalls rely on brittle, static regular expression rule sets (e.g., ModSecurity CRS) that are vulnerable to evasion techniques like encoding mutations, token splitting, and zero-day payload structures. 

This project implements a **deep-learning anomaly detection WAF** powered by a **BERT-style Masked Autoencoder (MAE)** trained on byte-level Byte-Pair Encoded (BPE) web tokens. Instead of searching for known attack signatures, the model learns the statistical, lexical, and structural probability distribution of legitimate HTTP requests. Payloads that deviate significantly in cross-entropy loss or contain anomalous structural characters trigger real-time mitigation, token attribution, and tamper-evident cryptographic logging.

---

## 🏗️ System Architecture

```
                                +---------------------------+
                                |  Client / External User   |
                                +-------------+-------------+
                                              |
                     [ Cloudflare Tunnel / Public Internet / HTTPS ]
                                              |
                                              v
                                +---------------------------+
                                |    Cloudflare Edge / CDN  |
                                | (CF-Connecting-IP, IPv6)  |
                                +-------------+-------------+
                                              |
                                              v
                              +-------------------------------+
                              |    Transformer WAF (Port 8000)|
                              |          waf/waf.py           |
                              +---------------+---------------+
                                              |
                  +---------------------------+---------------------------+
                  |                                                       |
        [ Anomaly Score < 1.0 ]                                 [ Anomaly Score >= 1.0 ]
                  |                                                       |
                  v                                                       v
        +-------------------+                                   +-------------------+
        | HTTP 200 / PASS   |                                   | HTTP 403 BLOCKED  |
        | Inject Hardened   |                                   | Threat Token      |
        | CSP & DOM Shield  |                                   | Attribution       |
        +---------+---------+                                   +---------+---------+
                  |                                                       |
                  v                                                       v
        +-------------------+                                   +-------------------+
        | Upstream Backend  |                                   | SHA-256 Chained   |
        | OWASP Juice Shop  |                                   | Audit Log         |
        | (Port 3000)       |                                   | (waf_chain.jsonl) |
        +-------------------+                                   +-------------------+
                  |                                                       |
                  +---------------------------+---------------------------+
                                              |
                                              v
                                +---------------------------+
                                |  Retro macOS SOC Console  |
                                |     http://localhost:8000 |
                                |   (/console / /terminal)  |
                                +---------------------------+
```

### Core Pipeline Stages:
1. **Multi-Pass Normalization (`waf/data.py`)**: Resolves recursive URL encoding (up to 3 passes), Unicode variations, whitespace collapsing, and masks high-entropy dynamic session values.
2. **Byte-Pair Encoding (BPE)**: High-resolution subword tokenization preserving exact byte semantics without out-of-vocabulary (`[UNK]`) blind spots.
3. **Transformer Scorer (`waf/model.py`)**: Contextual reconstruction engine measuring per-token cross-entropy error against benign baselines.
4. **Token Attribution Engine**: Highlights the exact tokens (e.g., `' OR '`, `alert`, `<iframe`, `admin`) responsible for crossing the anomaly threshold.
5. **Live Geolocation Engine**: Resolves IPv4 and complex IPv6 addresses (including Indian telecom networks like Reliance Jio `2405:201:...`, `2409:40e1:...` and Bharti Airtel) using Cloudflare headers and multi-tier geolocation fallbacks.
6. **Client-Side Runtime & CSP Hardener**: Injects Content Security Policies (`script-src 'self'`, `frame-src 'self'`) into upstream responses to mitigate client-side DOM-based XSS attacks.
7. **Tamper-Evident SHA-256 Hash Chain (`waf/chain.py`)**: Every request verdict is cryptographically linked to the previous record hash.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- **Python 3.10+** (Tested on Python 3.11 & 3.13)
- **Docker & Docker Compose** (for running target applications like OWASP Juice Shop)
- **Cloudflared CLI** (optional, for public testing tunnels)

### 2. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/sourjyasaha/WAF-TEST.git
cd WAF-TEST

# Install Python requirements
pip install -r requirements.txt
```

Copy the environment configuration template:
```bash
cp .env.example .env
```

---

## 🧪 Running with OWASP Juice Shop

OWASP Juice Shop is the most sophisticated and modern insecure web application available, providing a realistic testbed for SQL Injection, XSS, and broken access controls.

### Step 1: Start OWASP Juice Shop
Run Juice Shop in Docker on port `3000`:
```bash
docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
```
Verify Juice Shop is accessible directly at `http://localhost:3000`.

### Step 2: Launch the Transformer WAF Reverse Proxy
Start the WAF proxying to Juice Shop in active blocking mode:
```bash
python waf/waf.py serve --port 8000 --proxy http://localhost:3000 --block
```

| Flag | Description |
|---|---|
| `--port 8000` | Port where the WAF reverse proxy listens |
| `--proxy http://localhost:3000` | Upstream target backend URL |
| `--block` | Active blocking mode (returns `403 Forbidden` on anomalies; omits to run in monitor/log-only mode) |
| `--threshold 1.0` | Anomaly score threshold (default: `1.0`) |

Now access the application through the WAF at:
👉 **`http://localhost:8000`**

---

## 🌐 Public Testing with Cloudflare Tunnels

To test the WAF against attacks originating from remote devices, mobile phones, or cellular networks (IPv4/IPv6), expose the WAF using a Cloudflare Tunnel (`cloudflared`).

### Step 1: Install Cloudflared
- **Windows (winget):**
  ```powershell
  winget install Cloudflare.cloudflared
  ```
- **macOS (Homebrew):**
  ```bash
  brew install cloudflared
  ```
- **Linux:**
  ```bash
  curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  sudo dpkg -i cloudflared.deb
  ```

### Step 2: Create a Quick Ad-Hoc Tunnel
Run `cloudflared` pointing to the WAF proxy on port 8000:
```bash
cloudflared tunnel --url http://localhost:8000
```

Cloudflare will output a public HTTPS URL:
```text
+--------------------------------------------------------------------------------------------+
|  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |
|  https://recording-common-dramatic-brooklyn.trycloudflare.com                             |
+--------------------------------------------------------------------------------------------+
```

### Step 3: Test from Mobile & External Networks
Open the Cloudflare URL on a mobile device on 4G/5G or send attack payloads from an external network. The WAF will automatically extract:
- `CF-Connecting-IP`
- `CF-IPCountry`
- `X-Forwarded-For`
- Resolve the exact City, State, and ISP/Telecom provider (e.g. `Reliance Jio`, `Kolkata, West Bengal, IN 🇮🇳`).

---

## 🖥️ Web Console & Retro macOS Terminal

The WAF features a built-in interactive macOS SOC Terminal interface with real-time SSE streaming.

Open your browser to:
👉 **`http://localhost:8000/console`** (or `http://localhost:8000/terminal`)

### Features:
- **macOS Window Frame**: Styled terminal with traffic status lights (Red = Blocked, Green = Allowed).
- **Live Event Stream**: Server-Sent Events (`/api/waf/stream`) streaming live requests without page reloads.
- **Geographic Details**: Live display of client IP, flag, city, region, and ISP.
- **Offending Token Highlighter**: Color-coded breakdown of tokens contributing to anomaly scores.

---

## ⚔️ Security Attack Scenarios & Research Findings

### Scenario 1: SQL Injection (Login Form Bypass)
Submit a classic SQL injection payload in the login endpoint (`POST /rest/user/login`):
```json
{
  "email": "' OR 1=1--",
  "password": "test"
}
```

**WAF Terminal Output:**
```text
[12:44:37 AM] [BLOCKED - 403] 2405:201:8017:6003:b5d1:38be:3b7:afad POST
http://localhost:8000/rest/user/login
 |-- VIOLATION: TRANSFORMER_WAF (Stage: TRANSFORMER_WAF)
 |-- Reason: Transformer Anomaly Detected (score: 1.07 > 1.00). 
 |   Anomalous tokens: '-'=11.8, 'or'=8.9, 'password'=7.5, ' '=6.5, '='=6.3
 \-- Transformer Anomaly Score: 1.07 (Alert Threshold: 1.00 • Level: ALERT)
```
The request is immediately halted with `HTTP 403 Forbidden` and never reaches the backend database.

---

### Scenario 2: DOM-based XSS vs. Network-Layer WAF (Key Research Finding)

During security evaluation with the payload:
```html
http://localhost:8000/#/search?q=<iframe src="javascript:alert('XSS_TEST')"></iframe>
```
An interesting architectural boundary was observed:
1. **The URL Fragment (`#/...`)**: RFC 3986 specifies that URL fragments following `#` are handled purely client-side by the browser and **never sent over the wire** in the HTTP request line.
2. **Reverse Proxy Limitation**: Any network-layer reverse proxy WAF cannot inspect URL fragments because the browser never transmits them to the server.
3. **The Socket.IO Secondary Channel**: As Juice Shop executed client-side search logic, it synchronized state with the server via WebSocket / Socket.IO polling (`POST /socket.io/?...`).
4. **WAF Detection**: The Transformer WAF detected the anomalous payload inside the Socket.IO stream and blocked the POST request with score `1.465` (offending tokens: `alert`, `<`, `iframe`).
5. **Defense-in-Depth Solution**: To prevent DOM execution when fragments never touch the wire, the WAF implements **Content Security Policy (CSP) Injection & Client-Side Runtime Shielding** directly in the HTML response stream:
   ```http
   Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' * data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' *; frame-src 'self'; object-src 'none';
   ```

---

## 📁 Repository Structure

```
WAF-TEST/
├── .env.example                     # Sanitized configuration template
├── .gitignore                       # Rules excluding datasets, caches, and secrets
├── README.md                        # Master documentation
├── requirements.txt                 # Project dependencies
├── docker-compose.juiceshop.yml     # Standalone Juice Shop stack
├── tests/
│   └── test_waf.py                  # Pytest test suite (Scorer, Normalizer, Hash Chain, Routes)
├── waf/
│   ├── waf.py                       # Core Flask reverse proxy, scoring pipeline & CSP shield
│   ├── model.py                     # PyTorch BERT Masked Autoencoder architecture
│   ├── data.py                      # Multi-pass decoding & tokenizer normalization
│   ├── chain.py                     # SHA-256 tamper-evident cryptographic hash audit log
│   ├── terminal_ui.py               # Retro macOS SOC Terminal Console HTML/CSS/JS
│   ├── evaluate.py                  # Anomaly evaluation scripts
│   ├── finetune.py                  # LoRA parameter-efficient adaptation engine
│   ├── benchmark_all_attacks.py     # 860+ payload threat matrix evaluation
│   └── model/
│       ├── model.pt                 # Trained PyTorch Transformer weights (35.4 MB)
│       ├── tokenizer.json           # Byte-Pair Encoding (BPE) vocabulary
│       ├── config.json              # Model hyperparameters
│       └── lora.pt                  # Trained LoRA adapter weights
```

---

## 📊 Endpoints Reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/console` or `/terminal` | `GET` | Retro macOS SOC Terminal visual dashboard |
| `/api/waf/stream` | `GET` | Real-time Server-Sent Events (SSE) log feed |
| `/api/waf/logs` | `GET` | REST JSON endpoint for audit history |
| `/health` | `GET` | Health check probe (returns `200 OK`) |
| `/score` | `POST` | Programmatic single-request anomaly evaluation |
| `/check` | Any | Nginx `auth_request` subrequest validation |
| `/*` | Any | Transparent reverse proxy to upstream backend |

---

## 🧪 Verification & Unit Testing

Run the test suite using pytest:
```bash
# Set environment flag to disable external plugin conflicts
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"   # PowerShell
# export PYTEST_DISABLE_PLUGIN_AUTOLOAD="1" # Linux/macOS

python -m pytest tests/test_waf.py -v
```

**Expected Test Results:**
```text
tests/test_waf.py::test_scorer_loading PASSED             [ 20%]
tests/test_waf.py::test_normalization_rules PASSED        [ 40%]
tests/test_waf.py::test_benign_vs_attack_scoring PASSED   [ 60%]
tests/test_waf.py::test_hash_chain_integrity PASSED       [ 80%]
tests/test_waf.py::test_flask_endpoints PASSED            [100%]
====================== 5 passed in 7.65s =======================
```

Verify cryptographic hash audit chain integrity:
```bash
python waf/chain.py verify waf_chain.jsonl
```

---

## 📜 License

MIT License. Designed and developed for advanced web application security research and machine learning threat intelligence.
