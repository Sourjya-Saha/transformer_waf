"""End-to-End Integration Tests for the Web Application Firewall."""
import json
import os
import shutil
import tempfile
import pytest
import httpx
from httpx import ASGITransport

from web_firewall.config.settings import WAFSettings
from web_firewall.gateway.proxy import create_waf_app


@pytest.fixture
def temp_log_dir():
    dirpath = tempfile.mkdtemp()
    yield dirpath
    shutil.rmtree(dirpath, ignore_errors=True)


@pytest.fixture
def custom_settings(temp_log_dir):
    return WAFSettings(
        BACKEND_URL="http://mock-backend:8080",
        LOG_DIR=temp_log_dir,
        LOG_FILE=os.path.join(temp_log_dir, "test_waf.log"),
        IP_BLOCKLIST=["198.51.100.0/24"],
        RATE_LIMIT_ENABLED=True,
        RATE_LIMIT_ALGORITHM="token_bucket",
        RATE_LIMIT_REQUESTS_PER_MINUTE=60,
        RATE_LIMIT_BURST=3,
        REQUIRED_HEADERS=["Host", "User-Agent"],
        BLOCKED_USER_AGENTS=["sqlmap", "nikto"],
    )


@pytest.mark.asyncio
async def test_integration_allowed_request_forwarding(custom_settings):
    # Mock backend server transport
    def backend_handler(request: httpx.Request):
        if request.url.path == "/api/items":
            return httpx.Response(200, json={"items": ["item1", "item2"]})
        return httpx.Response(404)

    app = create_waf_app(settings=custom_settings)
    # Inject mock client for upstream backend
    app.state.forwarder._client = httpx.AsyncClient(
        transport=httpx.MockTransport(backend_handler)
    )

    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://waf.local") as client:
        resp = await client.get(
            "/api/items",
            headers={"Host": "waf.local", "User-Agent": "LegitimateBrowser/1.0"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"items": ["item1", "item2"]}

    # Check log file written
    with open(custom_settings.LOG_FILE, "r", encoding="utf-8") as f:
        logs = [json.loads(line) for line in f if line.strip()]
    assert len(logs) >= 1
    assert logs[0]["action"] == "ALLOW"
    assert logs[0]["status_code"] == 200


@pytest.mark.asyncio
async def test_integration_blocked_path_traversal(custom_settings):
    app = create_waf_app(settings=custom_settings)

    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://waf.local") as client:
        resp = await client.get(
            "/files/../../etc/passwd",
            headers={"Host": "waf.local", "User-Agent": "Mozilla/5.0"},
        )
        assert resp.status_code == 403
        data = resp.json()
        assert data["error"] == "Forbidden"
        assert data["stage"] == "URL_INSPECTOR"
        assert "PT-001" in data["rule_id"] or "PT-004" in data["rule_id"]


@pytest.mark.asyncio
async def test_integration_blocked_scanner_user_agent(custom_settings):
    app = create_waf_app(settings=custom_settings)

    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://waf.local") as client:
        resp = await client.get(
            "/api/status",
            headers={"Host": "waf.local", "User-Agent": "sqlmap/1.4.11#stable"},
        )
        assert resp.status_code == 403
        data = resp.json()
        assert data["stage"] == "HEADER_VALIDATOR"
        assert "Blocked User-Agent" in data["reason"]


@pytest.mark.asyncio
async def test_integration_rate_limiting_429(custom_settings):
    def backend_handler(request: httpx.Request):
        return httpx.Response(200, json={"status": "ok"})

    app = create_waf_app(settings=custom_settings)
    app.state.forwarder._client = httpx.AsyncClient(
        transport=httpx.MockTransport(backend_handler)
    )

    async with httpx.AsyncClient(transport=ASGITransport(app=app), base_url="http://waf.local") as client:
        headers = {
            "Host": "waf.local",
            "User-Agent": "Browser/1.0",
            "X-Forwarded-For": "203.0.113.88",
        }
        # Burst is 3, so first 3 should succeed
        for _ in range(3):
            r = await client.get("/api/status", headers=headers)
            assert r.status_code == 200

        # 4th request must be rate limited (429)
        r4 = await client.get("/api/status", headers=headers)
        assert r4.status_code == 429
        assert "Retry-After" in r4.headers
        assert r4.json()["error"] == "Too Many Requests"
