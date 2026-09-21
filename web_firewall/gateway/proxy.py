"""FastAPI Gateway Application and Security Interceptor."""
import asyncio
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import logging
import os
from typing import Optional, Set

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse

from web_firewall.config.settings import WAFSettings, get_settings
from web_firewall.parsers.request_parser import RequestParser
from web_firewall.engine.decision_engine import DecisionEngine, SecurityDecision
from web_firewall.gateway.request_forwarder import RequestForwarder
from web_firewall.gateway.terminal_ui import render_terminal_html


class WafEventHub:
    """In-memory event buffer and real-time SSE broadcaster for the WAF Terminal Console."""

    def __init__(self, maxlen: int = 300):
        self.events: deque = deque(maxlen=maxlen)
        self.subscribers: Set[asyncio.Queue] = set()
        self.stats = {
            "total": 0,
            "passed": 0,
            "blocked": 0,
            "ratelimit": 0,
        }

    def record_event(
        self,
        client_ip: str,
        method: str,
        url: str,
        status_code: int,
        action: str,
        pipeline_stage: str,
        rule_id: str,
        reason: str,
        threat_score: float = 0.0,
    ) -> dict:
        self.stats["total"] += 1
        if action == "ALLOW":
            self.stats["passed"] += 1
        elif status_code == 429:
            self.stats["ratelimit"] += 1
            self.stats["blocked"] += 1
        else:
            self.stats["blocked"] += 1

        event = {
            "id": self.stats["total"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "client_ip": client_ip,
            "method": method,
            "url": url,
            "status_code": status_code,
            "action": action,
            "pipeline_stage": pipeline_stage,
            "rule_id": rule_id,
            "reason": reason,
            "threat_score": threat_score,
        }
        self.events.append(event)

        # Broadcast event to all active SSE subscribers
        for queue in list(self.subscribers):
            try:
                queue.put_nowait(event)
            except Exception:
                pass

        return event

    def clear(self):
        self.events.clear()
        self.stats = {"total": 0, "passed": 0, "blocked": 0, "ratelimit": 0}


global_event_hub = WafEventHub(maxlen=300)


def setup_waf_logging(settings: WAFSettings) -> logging.Logger:
    """Configure structured file and console logging for WAF security events."""
    os.makedirs(settings.LOG_DIR, exist_ok=True)
    
    waf_logger = logging.getLogger("waf.audit")
    waf_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))
    waf_logger.handlers.clear()

    formatter = logging.Formatter("%(message)s")

    # File handler
    file_handler = logging.FileHandler(settings.LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    waf_logger.addHandler(file_handler)

    # Console handler
    if settings.ENABLE_CONSOLE_LOGS:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter("[%(asctime)s] [%(levelname)s] [WAF] %(message)s")
        )
        waf_logger.addHandler(console_handler)

    return waf_logger


def log_security_event(
    logger: logging.Logger,
    client_ip: str,
    method: str,
    url: str,
    headers: dict,
    status_code: int,
    decision: SecurityDecision,
) -> None:
    """Record a structured JSON security audit log."""
    log_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "method": method,
        "url": url,
        "headers": headers,
        "status_code": status_code,
        "action": decision.action,
        "pipeline_stage": decision.pipeline_stage,
        "rule_id": decision.rule_id,
        "reason": decision.block_reason,
    }
    logger.info(json.dumps(log_record))


def create_waf_app(settings: Optional[WAFSettings] = None) -> FastAPI:
    """Application factory for the Web Application Firewall."""
    cfg = settings or get_settings()
    audit_logger = setup_waf_logging(cfg)

    request_parser = RequestParser(cfg)
    decision_engine = DecisionEngine(cfg)
    forwarder = RequestForwarder(cfg)
    event_hub = global_event_hub

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup
        yield
        # Shutdown
        await forwarder.close()

    app = FastAPI(
        title="Web Application Firewall (WAF)",
        description="High-Performance Deterministic Network Security Gateway",
        version="1.0.0",
        lifespan=lifespan,
        debug=cfg.DEBUG,
        docs_url=None,  # Security gateway hides auto-docs
        redoc_url=None,
    )

    # Attach components to state for testing and inspection
    app.state.settings = cfg
    app.state.decision_engine = decision_engine
    app.state.request_parser = request_parser
    app.state.forwarder = forwarder
    app.state.audit_logger = audit_logger
    app.state.event_hub = event_hub

    # ==========================================================================
    # Terminal UI & Management Endpoints
    # ==========================================================================
    @app.get("/terminal", include_in_schema=False)
    @app.get("/console", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    async def get_terminal_view():
        """Serves the Classical Monospace Terminal UI console."""
        return HTMLResponse(content=render_terminal_html(), status_code=200)

    @app.get("/api/waf/logs", include_in_schema=False)
    async def get_waf_logs(since: int = 0):
        """Returns JSON audit events and aggregate stats."""
        all_logs = list(event_hub.events)
        if since > 0:
            filtered = [l for l in all_logs if l.get("id", 0) > since]
        else:
            filtered = all_logs
        return {
            "status": "ok",
            "stats": event_hub.stats,
            "total_count": len(all_logs),
            "logs": filtered,
        }

    @app.get("/api/waf/stats", include_in_schema=False)
    async def get_waf_stats():
        """Returns real-time gateway metrics counter."""
        return {"status": "ok", "stats": event_hub.stats}

    @app.post("/api/waf/clear", include_in_schema=False)
    async def clear_waf_logs():
        """Clears memory log feed."""
        event_hub.clear()
        return {"status": "cleared"}

    @app.get("/api/waf/stream", include_in_schema=False)
    async def sse_stream(request: Request):
        """Server-Sent Events (SSE) stream for real-time live log terminal."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        event_hub.subscribers.add(queue)

        async def event_generator():
            try:
                # Send initial connection ping
                yield f"data: {json.dumps({'type': 'CONNECTED', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        yield f"data: {json.dumps(event)}\n\n"
                    except asyncio.TimeoutError:
                        # Heartbeat ping
                        yield ": keep-alive\n\n"
            finally:
                event_hub.subscribers.discard(queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
            },
        )

    # ==========================================================================
    # Global WAF Inspection & Reverse-Proxy Pipeline
    # ==========================================================================
    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        include_in_schema=False,
    )
    async def waf_intercept(request: Request, full_path: str):
        # Handle CORS preflight directly
        if request.method.upper() == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "86400",
                },
            )

        # Serve Terminal UI if browser opens root / or /terminal
        accept_header = request.headers.get("accept", "").lower()
        if (full_path == "" or full_path == "/") and ("text/html" in accept_header or "*/*" in accept_header and not request.query_params):
            if request.method.upper() == "GET":
                return HTMLResponse(content=render_terminal_html(), status_code=200)

        # 1. Parse incoming request
        parsed_req = await request_parser.parse_request(request)

        # 2. Apply Security Policies & Inspection Pipeline
        decision = await decision_engine.evaluate(parsed_req)

        # 3. Handle Block Decision
        if not decision.is_allowed:
            response_payload = {
                "error": "Forbidden",
                "message": "Request blocked by Web Application Firewall policy",
                "stage": decision.pipeline_stage,
                "rule_id": decision.rule_id,
                "reason": decision.block_reason,
            }
            if decision.status_code == 429:
                response_payload["error"] = "Too Many Requests"
                response_payload["message"] = "Rate limit exceeded"

            response_headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD",
                "Access-Control-Allow-Headers": "*",
            }
            if decision.retry_after is not None:
                response_headers["Retry-After"] = str(int(decision.retry_after))

            log_security_event(
                logger=audit_logger,
                client_ip=parsed_req.client_ip,
                method=parsed_req.method,
                url=parsed_req.url,
                headers=parsed_req.headers.headers,
                status_code=decision.status_code,
                decision=decision,
            )

            event_hub.record_event(
                client_ip=parsed_req.client_ip,
                method=parsed_req.method,
                url=parsed_req.url,
                status_code=decision.status_code,
                action="BLOCK",
                pipeline_stage=decision.pipeline_stage,
                rule_id=decision.rule_id or "SECURITY_VIOLATION",
                reason=decision.block_reason,
                threat_score=1.0,
            )

            return JSONResponse(
                status_code=decision.status_code,
                content=response_payload,
                headers=response_headers,
            )

        # 4. Handle Allowed Decision -> Forward to Backend Server
        upstream_response = await forwarder.forward(parsed_req)

        log_security_event(
            logger=audit_logger,
            client_ip=parsed_req.client_ip,
            method=parsed_req.method,
            url=parsed_req.url,
            headers=parsed_req.headers.headers,
            status_code=upstream_response.status_code,
            decision=decision,
        )

        event_hub.record_event(
            client_ip=parsed_req.client_ip,
            method=parsed_req.method,
            url=parsed_req.url,
            status_code=upstream_response.status_code,
            action="ALLOW",
            pipeline_stage="CLEAN_FORWARD",
            rule_id="-",
            reason="Payload verified and clean",
            threat_score=0.0,
        )

        return upstream_response

    return app


# Default ASGI app instance
app = create_waf_app()

