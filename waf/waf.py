"""WAF front end: score requests with the trained model and write flagged ones to the audit chain.

Available Models:
  Model 0 (Juice Shop Baseline - 329 shapes):     waf/model_backup
  Model 1 (Juice + DVWA - 250 shapes):            waf/model_waf_v1
  Model 2 (Unified Foundation - 331,368 shapes):  waf/model (Active Default)

Python Switching Examples:
  # Select Model 0:
  waf_v0 = Waf(model_dir="waf/model_backup")
  # Select Model 1:
  waf_v1 = Waf(model_dir="waf/model_waf_v1")
  # Select Model 2:
  waf_v2 = Waf(model_dir="waf/model")

CLI Usage:
  python waf.py check "GET /rest/products/search?q=' OR 1=1--" [--model waf/model] [--explain]
  python waf.py scan access.log.txt [--model waf/model] [--log-all]
  python waf.py serve [--port 8080] [--model waf/model] [--block]
"""
import argparse
from collections import deque
from datetime import datetime, timezone
import ipaddress
import json
import logging
import os
import queue
import re
import sys
import threading
import urllib.request

try:
    from terminal_ui import render_terminal_html
except ImportError:
    from waf.terminal_ui import render_terminal_html

import data
from chain import Chain
from model import Scorer

IP_LOCATION_CACHE = {}


def get_country_flag(country_code: str) -> str:
    """Convert 2-letter country code (e.g. IN, US) to Unicode regional indicator flag."""
    if not country_code or len(country_code) != 2:
        return ""
    try:
        return "".join(chr(127397 + ord(c)) for c in country_code.upper())
    except Exception:
        return ""


def extract_client_ip(req) -> str:
    """Extract real client IP prioritizing Cloudflare headers and X-Forwarded-For."""
    cf_ip = req.headers.get("CF-Connecting-IP") or req.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    xff = req.headers.get("X-Forwarded-For") or req.headers.get("x-forwarded-for")
    if xff:
        # First IP in comma-separated list is the real client origin
        return xff.split(",")[0].strip()
    return req.remote_addr or "-"


def resolve_ip_location(ip: str, headers=None) -> str:
    """Resolve IP address to a geographic location string (City, Country Flag)."""
    if not ip or ip in ("-", "unknown", "127.0.0.1", "::1"):
        return "Localhost (Loopback)"

    # Fast check for private networks / loopbacks
    try:
        clean_ip = ip.split("%")[0].strip()
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_loopback:
            return "Localhost"
        if ip_obj.is_private:
            return "LAN (Private)"
    except Exception:
        clean_ip = ip

    # 1. Cache Lookup (Instant for repeated requests from same device)
    if clean_ip in IP_LOCATION_CACHE:
        return IP_LOCATION_CACHE[clean_ip]

    # 2. Cloudflare Geolocation Headers (Use immediately ONLY if city is provided)
    cf_city = None
    cf_country = None
    if headers:
        cf_city = headers.get("CF-IPCity") or headers.get("cf-ipcity")
        cf_country = headers.get("CF-IPCountry") or headers.get("cf-ipcountry")
        if cf_city and cf_country and cf_country != "XX":
            flag = get_country_flag(cf_country)
            loc = f"{cf_city}, {cf_country} {flag}".strip()
            IP_LOCATION_CACHE[clean_ip] = loc
            return loc

    # 3. Query Geo API for detailed City, State/Region, and Country
    # Service A: ip-api.com (Supports both IPv4 and IPv6; provides City, State, Country)
    try:
        req_geo = urllib.request.Request(
            f"http://ip-api.com/json/{clean_ip}?fields=status,city,regionName,country,countryCode,isp",
            headers={"User-Agent": "WAF-GeoResolver/2.0"}
        )
        with urllib.request.urlopen(req_geo, timeout=1.5) as resp:
            data_geo = json.loads(resp.read().decode("utf-8"))
            if data_geo.get("status") == "success":
                city = data_geo.get("city", "").strip()
                region = data_geo.get("regionName", "").strip()
                country = data_geo.get("country", "").strip()
                cc = data_geo.get("countryCode", "").strip()
                flag = get_country_flag(cc)
                
                parts = []
                if city:
                    parts.append(city)
                if region and region != city:
                    parts.append(region)
                if country:
                    parts.append(country)

                loc = ", ".join(parts) if parts else (country or cc)
                if flag:
                    loc = f"{loc} {flag}".strip()
                if loc:
                    IP_LOCATION_CACHE[clean_ip] = loc
                    return loc
    except Exception:
        pass

    # Service B Fallback: ipwho.is (Secondary Geo API fallback for IPv6)
    try:
        req_geo2 = urllib.request.Request(
            f"http://ipwho.is/{clean_ip}",
            headers={"User-Agent": "WAF-GeoResolver/2.0"}
        )
        with urllib.request.urlopen(req_geo2, timeout=1.5) as resp:
            data_geo2 = json.loads(resp.read().decode("utf-8"))
            if data_geo2.get("success"):
                city = data_geo2.get("city", "").strip()
                region = data_geo2.get("region", "").strip()
                country = data_geo2.get("country", "").strip()
                cc = data_geo2.get("country_code", "").strip()
                flag = get_country_flag(cc)
                parts = [p for p in [city, region, country] if p]
                loc = ", ".join(parts)
                if flag:
                    loc = f"{loc} {flag}".strip()
                if loc:
                    IP_LOCATION_CACHE[clean_ip] = loc
                    return loc
    except Exception:
        pass

    # 4. Fallback to Cloudflare Country header if City was unavailable
    if cf_country and cf_country != "XX":
        flag = get_country_flag(cf_country)
        loc = f"{cf_country} {flag}".strip()
        IP_LOCATION_CACHE[clean_ip] = loc
        return loc

    # 5. Known Indian ISP IPv6 prefixes
    if clean_ip.startswith("2405:20") or clean_ip.startswith("2409:40"):
        loc = f"India {get_country_flag('IN')} (Jio)"
        IP_LOCATION_CACHE[clean_ip] = loc
        return loc
    elif clean_ip.startswith("2401:49") or clean_ip.startswith("2402:3a"):
        loc = f"India {get_country_flag('IN')} (Airtel)"
        IP_LOCATION_CACHE[clean_ip] = loc
        return loc

    return "Public WAN"


class WafEventHub:
    """Thread-safe event broadcaster and in-memory event buffer for the Terminal UI."""
    def __init__(self, maxlen=500):
        self.events = deque(maxlen=maxlen)
        self.subscribers = []
        self.lock = threading.Lock()
        self.stats = {"total": 0, "passed": 0, "blocked": 0, "ratelimit": 0}
        self._load_initial_logs()

    def _load_initial_logs(self):
        log_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "waf.log")
        if not os.path.exists(log_file):
            return
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            for line in lines[-100:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    data_obj = json.loads(line)
                    self.stats["total"] += 1
                    if data_obj.get("action") == "BLOCK" or data_obj.get("status_code") == 403:
                        self.stats["blocked"] += 1
                    elif data_obj.get("status_code") == 429:
                        self.stats["ratelimit"] += 1
                        self.stats["blocked"] += 1
                    else:
                        self.stats["passed"] += 1
                    data_obj["id"] = self.stats["total"]
                    self.events.append(data_obj)
                except Exception:
                    pass
        except Exception:
            pass

    def record_event(self, event):
        with self.lock:
            self.stats["total"] += 1
            if event.get("action") == "BLOCK" or event.get("status_code") == 403:
                self.stats["blocked"] += 1
            elif event.get("status_code") == 429:
                self.stats["ratelimit"] += 1
                self.stats["blocked"] += 1
            else:
                self.stats["passed"] += 1

            event["id"] = self.stats["total"]
            self.events.append(event)
            dead = []
            for q in self.subscribers:
                try:
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
            for d in dead:
                if d in self.subscribers:
                    self.subscribers.remove(d)

    def get_logs_since(self, since_id=0):
        with self.lock:
            evs = [e for e in self.events if e.get("id", 0) > since_id]
            return evs, self.stats["total"], dict(self.stats)

    def add_subscriber(self):
        q = queue.Queue(maxsize=200)
        with self.lock:
            self.subscribers.append(q)
        return q

    def remove_subscriber(self, q):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)


def log_request_event(client_ip, method, uri, score, threshold, flagged, tokens, status_code, normalized="", location=""):
    """Write structured event to logs/waf.log for live visualizer streaming."""
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "waf.log")
    now_iso = datetime.now(timezone.utc).isoformat() if hasattr(timezone, "utc") else datetime.utcnow().isoformat()
    entry = {
        "timestamp": now_iso,
        "client_ip": client_ip,
        "location": location,
        "method": method,
        "url": uri,
        "status_code": status_code,
        "action": "BLOCK" if flagged else "ALLOW",
        "pipeline_stage": "TRANSFORMER_MODEL" if flagged else "PASSED",
        "rule_id": f"SCORE_{score:.2f}" if flagged else None,
        "reason": f"Anomaly score {score:.2f} >= threshold {threshold:.2f}" if flagged else "",
        "score": score,
        "threshold": threshold,
        "tokens": tokens,
        "normalized": normalized
    }
    try:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ==============================================================================
# Model Selection in Python:
#   # Select Model 0:
#   waf_v0 = Waf(model_dir="waf/model_backup")
#   # Select Model 1:
#   waf_v1 = Waf(model_dir="waf/model_waf_v1")
#   # Select Model 2:
#   waf_v2 = Waf(model_dir="waf/model")
# ==============================================================================
class Waf:
    def __init__(self, model_dir=None, chain_path="waf_chain.jsonl", threshold=None, log_all=False):
        if model_dir is None:
            model_dir = os.environ.get("WAF_MODEL")
        if model_dir is None or not os.path.exists(model_dir):
            candidate = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
            if os.path.exists(candidate):
                model_dir = candidate
        self.scorer, self.chain, self.log_all = Scorer(model_dir), Chain(chain_path), log_all
        t = self.scorer.cfg["thresholds"]
        self.threshold = self.scorer.threshold if threshold is None else t[threshold] if threshold in t else float(threshold)

    def inspect(self, method, uri, ua=None, ref=None, ip="-", record=True):
        """Score one request. Returns dict(score, flagged, normalized, tokens)."""
        norm = data.normalize(method, uri, ua, ref)
        score, toks = self.scorer.explain([norm])[0]
        flagged = score > self.threshold
        if record and (flagged or self.log_all):
            self.chain.append(ip, f"{method} {uri}" + (f" UA={ua}" if ua else ""), score, "FLAGGED" if flagged else "ALLOWED")
        return dict(score=round(score, 3), threshold=round(self.threshold, 3), flagged=flagged, normalized=norm, tokens=toks)


def cmd_check(a):
    method, _, uri = a.request.strip().partition(" ")
    r = Waf(a.model, a.chain, a.threshold).inspect(method, uri.strip(), a.ua, a.referer, record=False)
    print(f"{'FLAGGED' if r['flagged'] else 'ALLOWED'}  score={r['score']}  threshold={r['threshold']}")
    print("normalized:", r["normalized"])
    if a.explain:
        worst = sorted(r["tokens"], key=lambda t: -t[1])[:8]
        print("most anomalous tokens:", ", ".join(f"{t!r}={l:.1f}" for t, l in worst))


def cmd_scan(a):
    waf, n, flagged = Waf(a.model, a.chain, a.threshold, a.log_all), 0, 0
    seen = {}  # identical normalised requests score identically; skip recomputation
    with open(a.logfile, encoding="utf-8", errors="replace") as f:
        for line in f:
            p = data.parse_line(line)
            if not p:
                continue
            method, uri, ua, ref, ip = p
            n += 1
            key = data.normalize(method, uri, ua, ref)
            if key not in seen:
                seen[key] = waf.inspect(method, uri, ua, ref, ip, record=False)
            if seen[key]["flagged"]:
                flagged += 1
                waf.chain.append(ip, f"{method} {uri}", seen[key]["score"], "FLAGGED")
                print(f"FLAGGED {seen[key]['score']:7.2f}  {method} {uri[:140]}")
            elif a.log_all:
                waf.chain.append(ip, f"{method} {uri}", seen[key]["score"], "ALLOWED")
    print(f"{n} requests, {flagged} flagged ({100 * flagged / max(n, 1):.2f}%), threshold {waf.threshold:.2f}")


def extract_body_params(body_bytes, content_type=""):
    """Extract parameter key-values from HTTP POST/PUT/PATCH bodies (JSON, form-urlencoded, raw)."""
    if not body_bytes:
        return ""
    if isinstance(body_bytes, bytes):
        text = body_bytes.decode("utf-8", errors="replace").strip()
    else:
        text = str(body_bytes).strip()
    if not text:
        return ""

    # 1. Parse JSON body (e.g. {"email": "' OR 1=1--", "password": "abc"})
    if text.startswith("{") and text.endswith("}"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                parts = []
                for k, v in obj.items():
                    val = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
                    parts.append(f"{k}={val}")
                return "&".join(parts)
        except Exception:
            pass

    # 2. Form-encoded or query-style body (e.g. email=' OR 1=1--&password=abc)
    if "=" in text:
        return text.replace("\n", "&").replace("\r", "")

    # 3. Raw text or XML/GraphQL body
    return f"body={text[:500]}"


def create_app(model_dir=None, chain_path="waf_chain.jsonl", threshold=None, proxy=None, block=False, log_all=False):
    import httpx
    from flask import Flask, Response, request

    proxy_target = os.environ.get("WAF_PROXY", proxy)
    block_mode = block or os.environ.get("WAF_BLOCK", "false").lower() in ("true", "1", "yes")

    waf = Waf(model_dir, chain_path, threshold, log_all)
    event_hub = WafEventHub()
    app = Flask("waf")

    @app.get("/health")
    def health():
        return {"status": "healthy", "service": "transformer-waf"}, 200

    # Dedicated Terminal UI Endpoints (Identical to original WAF Gateway Console)
    @app.route("/console")
    @app.route("/terminal")
    @app.route("/ui")
    @app.route("/waf")
    def terminal_console_view():
        return Response(render_terminal_html(), status=200, mimetype="text/html")

    @app.route("/api/waf/logs")
    def api_waf_logs():
        since = request.args.get("since", 0, type=int)
        evs, total, stats = event_hub.get_logs_since(since)
        return {"logs": evs, "total_count": total, "stats": stats}, 200

    @app.route("/api/waf/stream")
    def api_waf_stream():
        def generate():
            q = event_hub.add_subscriber()
            try:
                yield ": connected\n\n"
                while True:
                    try:
                        event_data = q.get(timeout=10.0)
                        yield f"data: {json.dumps(event_data)}\n\n"
                    except queue.Empty:
                        yield ": keep-alive\n\n"
            except GeneratorExit:
                pass
            finally:
                event_hub.remove_subscriber(q)

        return Response(generate(), mimetype="text/event-stream", headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*",
        })

    @app.post("/score")
    def score():
        j = request.get_json(force=True)
        r = waf.inspect(j.get("method", "GET"), j["uri"], j.get("user_agent"), j.get("referer"), j.get("client_ip", "-"))
        r["tokens"] = sorted(r["tokens"], key=lambda t: -t[1])[:8]
        return r

    @app.route("/check", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
    def check():  # nginx auth_request / mirror target; the original request arrives in X-Original-* headers
        h = request.headers
        orig_uri = h.get("X-Original-URI", "/")
        inspect_uri = orig_uri
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            raw_body = request.get_data()
            body_params = extract_body_params(raw_body, request.content_type or "")
            if body_params:
                inspect_uri = f"{orig_uri}&{body_params}" if "?" in orig_uri else f"{orig_uri}?{body_params}"

        r = waf.inspect(h.get("X-Original-Method", "GET"), inspect_uri, h.get("User-Agent"),
                        h.get("Referer"), h.get("X-Real-IP", "-"))
        return ("", 403 if (block_mode and r["flagged"]) else 204)

    @app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    def proxy_handler(path):
        if request.method == "OPTIONS":
            resp = Response("", status=200)
            resp.headers["Access-Control-Allow-Origin"] = "*"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "*"
            return resp

        # If accessing root without proxy configured or with ?console=1
        if (not proxy_target and (path == "" or path == "/")) or request.args.get("console"):
            return Response(render_terminal_html(), status=200, mimetype="text/html")

        full_uri = request.full_path if request.query_string else request.path
        client_ip = extract_client_ip(request)
        client_loc = resolve_ip_location(client_ip, request.headers)

        # Inspect URI + Request Body (Crucial for POST/PUT/PATCH attacks like Login SQLi!)
        inspect_uri = full_uri
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            raw_body = request.get_data()
            body_params = extract_body_params(raw_body, request.content_type or "")
            if body_params:
                inspect_uri = f"{full_uri}&{body_params}" if "?" in full_uri else f"{full_uri}?{body_params}"

        r = waf.inspect(request.method, inspect_uri, request.headers.get("User-Agent"), request.headers.get("Referer"), client_ip)

        tokens = sorted(r["tokens"], key=lambda t: -t[1])[:5]
        tok_str = ", ".join(f"{t[0]!r}={t[1]:.1f}" for t in tokens)
        is_blocked = bool(block_mode and r["flagged"])
        status_code = 403 if is_blocked else 200
        level = "CRITICAL" if r["score"] >= 2.0 else ("HIGH" if r["score"] >= 1.2 else "ALERT")

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat() if hasattr(timezone, "utc") else datetime.utcnow().isoformat(),
            "client_ip": client_ip,
            "location": client_loc,
            "method": request.method,
            "url": full_uri,
            "status_code": status_code,
            "action": "BLOCK" if is_blocked else ("ALERT" if r["flagged"] else "ALLOW"),
            "pipeline_stage": "TRANSFORMER_WAF" if r["flagged"] else "CLEAN_FORWARD",
            "rule_id": "TRANSFORMER_WAF" if r["flagged"] else "-",
            "reason": f"Transformer Anomaly Detected (score: {r['score']:.2f} > {r['threshold']:.2f}). Anomalous tokens: {tok_str}" if r["flagged"] else "Clean Request",
            "score": r["score"],
            "threshold": r["threshold"],
            "level": level,
            "tokens": [[t[0], round(t[1], 1)] for t in tokens],
        }

        # Broadcast live to terminal UI
        event_hub.record_event(event)

        # Log event to logs/waf.log for file-based audit tracking
        log_request_event(client_ip, request.method, full_uri, r["score"], r["threshold"], r["flagged"], [t[0] for t in tokens], status_code, r.get("normalized", ""), location=client_loc)

        # ASCII-safe location for Windows PowerShell console
        loc_str = re.sub(r"\s+", " ", client_loc.encode("ascii", "ignore").decode("ascii")).strip() or client_loc
        if r["flagged"]:
            action_str = "BLOCKED (403)" if block_mode else "MONITORED (ALERT ONLY)"
            print(f"\n\033[1;91m[BLOCKED 403]\033[0m score=\033[1;93m{r['score']:.3f}\033[0m (thresh={r['threshold']:.2f}) | \033[1m{request.method} {full_uri}\033[0m", flush=True)
            print(f"  \033[90m|--\033[0m Offending Tokens: \033[96m{tok_str}\033[0m", flush=True)
            print(f"  \033[90m|--\033[0m Origin Location: \033[93m{loc_str}\033[0m", flush=True)
            print(f"  \033[90m\\--\033[0m Client IP: \033[36m{client_ip}\033[0m | Action: \033[91m{action_str}\033[0m\n", flush=True)
        else:
            print(f"\033[92m[ALLOWED 200]\033[0m score=\033[90m{r['score']:.3f}\033[0m | \033[36m{client_ip}\033[0m \033[90m({loc_str})\033[0m | {request.method} {full_uri[:75]}", flush=True)

        if block_mode and r["flagged"]:
            tokens = sorted(r["tokens"], key=lambda t: -t[1])[:8]
            payload = {
                "error": "Forbidden",
                "message": "Request blocked by Transformer WAF Anomaly Model",
                "score": r["score"],
                "threshold": r["threshold"],
                "flagged": True,
                "tokens": tokens,
            }
            resp = Response(json.dumps(payload), status=403, mimetype="application/json")
            resp.headers["Access-Control-Allow-Origin"] = "*"
            return resp

        if not proxy_target:
            return Response("OK (Monitor Mode - No Upstream Configured)", status=200)

        upstream_url = f"{proxy_target.rstrip('/')}{request.full_path if request.query_string else request.path}"
        try:
            req_headers = {k: v for k, v in request.headers if k.lower() not in ("host", "content-length")}
            with httpx.Client(timeout=30.0) as client:
                up_resp = client.request(
                    method=request.method,
                    url=upstream_url,
                    headers=req_headers,
                    content=request.get_data(),
                )
            # Update event status_code to match upstream (e.g. 200, 304, etc.)
            event["status_code"] = up_resp.status_code
            headers_to_exclude = {
                "content-encoding", "content-length", "transfer-encoding", "connection",
                "content-security-policy", "content-security-policy-report-only"
            }
            filtered_headers = [(k, v) for k, v in up_resp.headers.items() if k.lower() not in headers_to_exclude]
            filtered_headers.append(("Access-Control-Allow-Origin", "*"))

            # WAF Layer-7 Runtime Hardening: Enforce Content Security Policy (CSP)
            # Defeats DOM-based XSS (e.g. <iframe src="javascript:alert(...)">) directly in the browser runtime
            csp_directives = [
                "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
                "font-src 'self' data: https://fonts.gstatic.com",
                "img-src 'self' data: blob: https:",
                "connect-src 'self' ws: wss:",
                "frame-src 'self'",
                "object-src 'none'",
                "base-uri 'self'",
            ]
            filtered_headers.append(("Content-Security-Policy", "; ".join(csp_directives)))
            filtered_headers.append(("X-Content-Type-Options", "nosniff"))
            filtered_headers.append(("X-XSS-Protection", "1; mode=block"))

            resp_content = up_resp.content
            content_type = up_resp.headers.get("content-type", "").lower()
            if ("text/html" in content_type or request.path in ("/", "/index.html")) and (b"<head" in resp_content.lower()):
                shield_code = (
                    b"<script>\n"
                    b"/* WAF Client-Side Shield: Neutralize DOM XSS in iframes, innerHTML & alerts */\n"
                    b"(function(){\n"
                    b"  try {\n"
                    b"    var innerDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');\n"
                    b"    if (innerDesc && innerDesc.set) {\n"
                    b"      Object.defineProperty(Element.prototype, 'innerHTML', {\n"
                    b"        set: function(val) {\n"
                    b"          if (typeof val === 'string' && val.toLowerCase().indexOf('javascript:') !== -1) {\n"
                    b"            console.warn('[WAF Shield] Neutralized innerHTML javascript: URI execution');\n"
                    b"            val = val.replace(/javascript\\s*:/gi, 'blocked-javascript:');\n"
                    b"          }\n"
                    b"          return innerDesc.set.call(this, val);\n"
                    b"        },\n"
                    b"        get: innerDesc.get\n"
                    b"      });\n"
                    b"    }\n"
                    b"  } catch(e) {}\n"
                    b"  try {\n"
                    b"    var iframeDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'src');\n"
                    b"    if (iframeDesc && iframeDesc.set) {\n"
                    b"      Object.defineProperty(HTMLIFrameElement.prototype, 'src', {\n"
                    b"        set: function(val) {\n"
                    b"          if (typeof val === 'string' && val.toLowerCase().indexOf('javascript:') !== -1) {\n"
                    b"            console.warn('[WAF Shield] Neutralized iframe.src execution:', val);\n"
                    b"            return;\n"
                    b"          }\n"
                    b"          return iframeDesc.set.call(this, val);\n"
                    b"        },\n"
                    b"        get: iframeDesc.get\n"
                    b"      });\n"
                    b"    }\n"
                    b"  } catch(e) {}\n"
                    b"  var origAlert = window.alert;\n"
                    b"  window.alert = function(msg) {\n"
                    b"    if (msg === 'XSS_TEST' || (typeof msg === 'string' && /xss/i.test(msg))) {\n"
                    b"      console.warn('[WAF Shield] Intercepted & Blocked DOM XSS alert popup:', msg);\n"
                    b"      return;\n"
                    b"    }\n"
                    b"    return origAlert.apply(this, arguments);\n"
                    b"  };\n"
                    b"})();\n"
                    b"</script>\n"
                )
                lower_content = resp_content.lower()
                head_idx = lower_content.find(b"<head")
                if head_idx != -1:
                    close_tag_idx = lower_content.find(b">", head_idx)
                    if close_tag_idx != -1:
                        resp_content = resp_content[:close_tag_idx+1] + b"\n" + shield_code + resp_content[close_tag_idx+1:]

            return Response(resp_content, status=up_resp.status_code, headers=filtered_headers)
        except Exception as e:
            return Response(json.dumps({"error": "Bad Gateway", "detail": str(e)}), status=502, mimetype="application/json")

    return app


def cmd_serve(a):
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)

    proxy_target = os.environ.get("WAF_PROXY", a.proxy)
    block_mode = a.block or os.environ.get("WAF_BLOCK", "false").lower() in ("true", "1", "yes")
    app = create_app(a.model, a.chain, a.threshold, proxy=proxy_target, block=block_mode, log_all=a.log_all)

    host = os.environ.get("WAF_HOST", a.host)
    port = int(os.environ.get("WAF_PORT", str(a.port)))

    print("=" * 80)
    print(f"[*] Transformer WAF running on http://{host}:{port}")
    print(f"[*] Blocking Active:       {block_mode}")
    print(f"[*] Upstream Target:       {proxy_target if proxy_target else 'None (Monitor Only)'}")
    print(f"[*] Defense-in-Depth:      CSP Runtime Hardening ACTIVE (DOM XSS Protected)")
    print(f"[*] >> LIVE SOC CONSOLE:   http://localhost:{port}/console")
    if proxy_target:
        print(f"[*] >> TARGET WEB APP:     http://localhost:{port}/")
    print("=" * 80, flush=True)

    app.run(host=host, port=port, threaded=True)


def main():
    sys.stdout.reconfigure(errors="backslashreplace")  # a hostile URI must not crash a scan on a cp1252 console
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    # Model Directory Selection:
    #   Model 0: os.path.join(os.path.dirname(__file__), "model_backup")
    #   Model 1: os.path.join(os.path.dirname(__file__), "model_waf_v1")
    #   Model 2: os.path.join(os.path.dirname(__file__), "model")  <-- Default
    fallback_model = os.path.join(os.path.dirname(__file__), "model") if os.path.isdir(os.path.join(os.path.dirname(__file__), "model")) else "model"
    default_model = os.environ.get("WAF_MODEL", fallback_model)
    ap.add_argument("--model", default=default_model, help="Path to model directory (default: waf/model, or $WAF_MODEL)")
    ap.add_argument("--chain", default="waf_chain.jsonl")
    ap.add_argument("--threshold", help="alert level: a score (default 1.0) or a preset: sensitive / default / strict / max")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("request", help='"METHOD /uri?query"')
    c.add_argument("--ua")
    c.add_argument("--referer")
    c.add_argument("--explain", action="store_true")
    c.set_defaults(fn=cmd_check)
    s = sub.add_parser("scan")
    s.add_argument("logfile")
    s.add_argument("--log-all", action="store_true", help="also chain ALLOWED requests (large)")
    s.set_defaults(fn=cmd_scan)
    v = sub.add_parser("serve")
    v.add_argument("--host", default="0.0.0.0")
    v.add_argument("--port", type=int, default=8000)
    v.add_argument("--proxy", default=None, help="Upstream backend URL to proxy allowed traffic to (e.g. http://127.0.0.1:8080)")
    v.add_argument("--block", action="store_true", help="return 403 for flagged requests (default: monitor only)")
    v.add_argument("--log-all", action="store_true")
    v.set_defaults(fn=cmd_serve)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
