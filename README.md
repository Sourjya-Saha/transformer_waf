# Production-Ready Web Application Firewall (WAF)

A high-performance, deterministic Web Application Firewall (WAF) engineered in Python, FastAPI, and HTTPX. Designed to sit between reverse proxies (e.g. Nginx) and upstream application servers to intercept, parse, inspect, filter, and secure all incoming HTTP traffic.

> [!IMPORTANT]
> **Deterministic Network Layer Security**:
> - **Zero AI / Zero ML / Zero Transformers / Zero Blockchain / Zero Anomaly Detection**.
> - 100% deterministic rule matching, RFC compliance enforcement, CIDR subnet filtering, multi-pass encoding normalization, Token Bucket & Sliding Window rate limiting, and secure XML/JSON/Multipart payload inspection.

---

## 1. System Architecture

```
                      +-------------------+
                      | Client / Internet |
                      +---------+---------+
                                |
                                v
               [ Port 80 / 443 (frontend-net) ]
                      +-------------------+
                      |    Nginx Proxy    |
                      +---------+---------+
                                |  (X-Forwarded-For / X-Real-IP)
                                v
               [ Port 8000 (Internal WAF Gateway) ]
                      +-------------------+
                      |   Web Firewall    |
                      +---------+---------+
                                |
                   +------------+------------+
                   |                         |
            [ BLOCK (403/429) ]       [ ALLOW (Forward) ]
                   |                         |
                   v                         v
          +-----------------+    [ Port 8080 (backend-net) ]
          | Security Logger |       +-------------------+
          |  (waf.log file) |       |  Backend Server   |
          +-----------------+       | (Zero Public Access)|
                                    +-------------------+
```

### Request Processing Pipeline

```
Incoming HTTP Request
        │
        ▼
Extract Client IP (Trusted Proxy Header Resolution)
        │
        ▼
[ Stage 1: IP Filtering ] ──(Blocklist / Allowlist CIDR Evaluation)──► [ BLOCK 403 ]
        │
        ▼
[ Stage 2: Rate Limiting ] ──(Token Bucket & Sliding Window Limits)──► [ BLOCK 429 ]
        │
        ▼
[ Stage 3: Header Validation ] ──(Required Headers, RFC, CRLF, UA)───► [ BLOCK 403 ]
        │
        ▼
[ Stage 4: URL Inspection ] ──(Path Traversal, Double URL-Decode)────► [ BLOCK 403 ]
        │
        ▼
[ Stage 5: Request Body Inspection ] ──(JSON, Form, Multipart, XML)──► [ BLOCK 403 ]
        │
        ▼
[ Forwarding Engine ] ──(Async HTTPX Connection Pool)────────────────► Upstream Backend
```

---

## 2. Directory Structure

```
web_firewall/
├── config/
│   ├── __init__.py
│   └── settings.py              # Environment configuration & pydantic settings
├── engine/
│   ├── __init__.py
│   └── decision_engine.py       # Sequential security decision pipeline
├── filters/
│   ├── __init__.py
│   ├── ip_filter.py             # Single IP and CIDR subnet evaluation
│   ├── rate_limiter.py          # Token Bucket & Sliding Window algorithms
│   └── header_validator.py      # RFC header validation, scanners & CRLF detection
├── gateway/
│   ├── __init__.py
│   ├── proxy.py                 # FastAPI reverse proxy application & file logger
│   ├── request_forwarder.py     # Async HTTPX connection pool & protocol relay
│   └── server.py                # Uvicorn ASGI server entrypoint
├── inspectors/
│   ├── __init__.py
│   ├── url_inspector.py         # Path traversal & multi-decode URL analyzer
│   └── body_inspector.py        # JSON, Form, Multipart & XML/XXE payload inspector
├── parsers/
│   ├── __init__.py
│   ├── request_parser.py        # Unified ASGI request extractor
│   ├── header_parser.py         # RFC 7230 header parser & size limiter
│   ├── query_parser.py          # Query parser with multi-pass decoding
│   ├── cookie_parser.py         # Cookie string parser
│   └── body_parser.py           # DefusedXML, JSON, Form & Multipart extractor
├── rules/
│   ├── __init__.py
│   └── rules.py                 # Compiled deterministic regex attack signatures
├── demo_backend/
│   ├── backend_app.py           # Sample backend server for isolation demo
│   └── Dockerfile               # Backend container Dockerfile
├── logs/                        # Local security audit logs (waf.log)
├── tests/                       # Pytest unit and integration test suite
├── Dockerfile                   # Multi-stage production WAF container
├── docker-compose.yml           # 3-tier isolated network deployment
├── nginx.conf                   # Production Nginx reverse proxy configuration
└── requirements.txt             # Python dependencies
```

---

## 3. Configuration Reference

All settings can be customized via environment variables with prefix `WAF_` or in a `.env` file:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `WAF_HOST` | `0.0.0.0` | Listening host for WAF gateway |
| `WAF_PORT` | `8000` | Listening port for WAF gateway |
| `WAF_BACKEND_URL` | `http://backend:8080` | URL of the protected backend server |
| `WAF_LOG_FILE` | `logs/waf.log` | Path to structured audit log file |
| `WAF_LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `WAF_TRUSTED_PROXIES` | `["127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]` | CIDRs trusted to supply `X-Forwarded-For` / `X-Real-IP` |
| `WAF_IP_ALLOWLIST` | `[]` | Explicit allowed IPs/CIDRs (takes precedence; triggers default-deny if populated) |
| `WAF_IP_BLOCKLIST` | `[]` | Blocked IPs/CIDRs |
| `WAF_RATE_LIMIT_ENABLED` | `True` | Enable or disable rate limiter |
| `WAF_RATE_LIMIT_ALGORITHM` | `token_bucket` | Rate limiting algorithm (`token_bucket` or `sliding_window`) |
| `WAF_RATE_LIMIT_REQUESTS_PER_MINUTE` | `100` | Allowed requests per minute |
| `WAF_RATE_LIMIT_REQUESTS_PER_HOUR` | `1000` | Allowed requests per hour |
| `WAF_RATE_LIMIT_REQUESTS_PER_DAY` | `10000` | Allowed requests per day |
| `WAF_RATE_LIMIT_BURST` | `20` | Burst token capacity for Token Bucket algorithm |
| `WAF_REQUIRED_HEADERS` | `["host", "user-agent"]` | Mandatory HTTP request headers |
| `WAF_BLOCKED_USER_AGENTS` | `["sqlmap", "nikto", "nmap", "gobuster", ...]` | Scanner signatures |
| `WAF_MAX_HEADER_SIZE` | `16384` (16 KB) | Maximum total HTTP header size |
| `WAF_MAX_BODY_SIZE` | `10485760` (10 MB) | Maximum request body payload size |
| `WAF_MAX_DECODE_ITERATIONS` | `3` | Iterations for unquoting nested percent encodings |
| `WAF_STRICT_CONTENT_LENGTH` | `True` | Validate `Content-Length` matches actual body length |

---

## 4. Local Setup & Testing

### Prerequisites
- Python 3.10+
- `pip`

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run the Test Suite
Execute all 55 comprehensive unit and integration tests:
```bash
pytest -v tests/
```

### Step 3: Run the Backend and WAF Locally
In Terminal 1 (Start Sample Backend):
```bash
python -m demo_backend.backend_app
```

In Terminal 2 (Start WAF Gateway):
```bash
python -m web_firewall.gateway.server
```

---

## 5. Docker Deployment (3-Tier Production Stack)

The provided `docker-compose.yml` launches a 3-tier architecture with network isolation:
1. **`waf_nginx`**: Public-facing proxy receiving external traffic on port `80`.
2. **`waf_gateway`**: WAF container bridging `frontend-net` and `backend-net`.
3. **`waf_backend`**: Isolated upstream container inside `backend-net` with zero external ports.

### Build and Start Stack
```bash
docker compose up --build -d
```

### Check Running Services
```bash
docker compose ps
```

---

## 6. Verification and Security Validation (cURL Examples)

### Test 1: Legitimate Allowed Request
```bash
curl -i http://localhost/api/users \
  -H "Host: localhost" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```
**Expected Response**: `HTTP/1.1 200 OK` with JSON user list.

---

### Test 2: Path Traversal Attack (`../` and `..\`)
```bash
curl -i "http://localhost/files/../../etc/passwd" \
  -H "Host: localhost" \
  -H "User-Agent: Mozilla/5.0"
```
**Expected Response**: `HTTP/1.1 403 Forbidden`
```json
{
  "error": "Forbidden",
  "message": "Request blocked by Web Application Firewall policy",
  "stage": "URL_INSPECTOR",
  "rule_id": "PT-001",
  "reason": "Malicious pattern detected in URL path (PATH_TRAVERSAL): Detects standard directory traversal patterns"
}
```

---

### Test 3: URL-Encoded & Double-Encoded Traversal (`%252e%252e%252f`)
```bash
curl -i "http://localhost/static/%252e%252e%252fetc%252fshadow" \
  -H "Host: localhost" \
  -H "User-Agent: Mozilla/5.0"
```
**Expected Response**: `HTTP/1.1 403 Forbidden` (`PT-003` Double-Encoded Traversal detected).

---

### Test 4: Blocked Automated Scanner User-Agent
```bash
curl -i http://localhost/ \
  -H "Host: localhost" \
  -H "User-Agent: sqlmap/1.5.2#stable"
```
**Expected Response**: `HTTP/1.1 403 Forbidden` (`HEADER_VALIDATOR: Blocked User-Agent signature identified`).

---

### Test 5: Missing Required Header (`Host` or `User-Agent`)
```bash
curl -i http://localhost/ -H "User-Agent:"
```
**Expected Response**: `HTTP/1.1 403 Forbidden` (`Missing required HTTP header: 'user-agent'`).

---

### Test 6: Malicious JSON Payload (SQL Injection)
```bash
curl -i -X POST http://localhost/api/login \
  -H "Host: localhost" \
  -H "User-Agent: Mozilla/5.0" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR 1=1--", "password": "password"}'
```
**Expected Response**: `HTTP/1.1 403 Forbidden` (`BODY_INSPECTOR: SQL_INJECTION`).

---

### Test 7: Malicious XML Payload (XXE Injection)
```bash
curl -i -X POST http://localhost/api/upload \
  -H "Host: localhost" \
  -H "User-Agent: Mozilla/5.0" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>'
```
**Expected Response**: `HTTP/1.1 403 Forbidden` (`BODY_INSPECTOR: XML_EXTERNAL_ENTITY`).

---

### Test 8: Rate Limiting Burst Exhaustion (HTTP 429)
Send rapid requests exceeding burst limits:
```bash
for i in {1..25}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost/ -H "Host: localhost" -H "User-Agent: Mozilla/5.0"; done
```
**Expected Response**: Initial requests return `200`, followed by `429 Too Many Requests` with `Retry-After` header.

---

## 7. Structured Audit Logging

Every decision (both `ALLOW` and `BLOCK`) is logged to `logs/waf.log` in single-line JSON format:

```json
{
  "timestamp": "2026-08-20T00:50:00.123456+00:00",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "url": "http://localhost/files/../../etc/passwd",
  "headers": {"host": "localhost", "user-agent": "Mozilla/5.0"},
  "status_code": 403,
  "action": "BLOCK",
  "pipeline_stage": "URL_INSPECTOR",
  "rule_id": "PT-001",
  "reason": "Malicious pattern detected in URL path (PATH_TRAVERSAL): Detects standard directory traversal patterns"
}
```

View live logs:
```bash
tail -f logs/waf.log
```
