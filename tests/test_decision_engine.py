"""Unit Tests for Central Decision Engine."""
import pytest
from web_firewall.config.settings import WAFSettings
from web_firewall.engine.decision_engine import DecisionEngine
from web_firewall.parsers.header_parser import ParsedHeaders
from web_firewall.parsers.query_parser import ParsedQuery
from web_firewall.parsers.body_parser import ParsedBody
from web_firewall.parsers.request_parser import ParsedHTTPRequest


def build_req(
    client_ip: str = "203.0.113.5",
    method: str = "GET",
    path: str = "/api/v1/resource",
    raw_query: str = "",
    headers_dict: dict = None,
    body_bytes: bytes = b"",
    content_type: str = "application/json",
) -> ParsedHTTPRequest:
    headers_dict = headers_dict or {"host": "api.example.com", "user-agent": "Mozilla/5.0"}
    return ParsedHTTPRequest(
        client_ip=client_ip,
        direct_ip="127.0.0.1",
        method=method,
        url=f"http://api.example.com{path}?{raw_query}",
        path=path,
        raw_query=raw_query,
        query=ParsedQuery(raw_query=raw_query),
        headers=ParsedHeaders(headers=headers_dict),
        cookies={},
        body=ParsedBody(raw_body=body_bytes, size_bytes=len(body_bytes), content_type=content_type),
        content_type=content_type,
    )


@pytest.mark.asyncio
async def test_decision_engine_allow_path():
    settings = WAFSettings()
    engine = DecisionEngine(settings)

    req = build_req()
    decision = await engine.evaluate(req)

    assert decision.is_allowed is True
    assert decision.status_code == 200
    assert decision.action == "ALLOW"
    assert decision.pipeline_stage == "PASSED"


@pytest.mark.asyncio
async def test_decision_engine_block_ip():
    settings = WAFSettings(IP_BLOCKLIST=["203.0.113.5"])
    engine = DecisionEngine(settings)

    req = build_req(client_ip="203.0.113.5")
    decision = await engine.evaluate(req)

    assert decision.is_allowed is False
    assert decision.status_code == 403
    assert decision.action == "BLOCK"
    assert decision.pipeline_stage == "IP_FILTER"


@pytest.mark.asyncio
async def test_decision_engine_block_url_traversal():
    settings = WAFSettings()
    engine = DecisionEngine(settings)

    req = build_req(path="/files/../../etc/shadow")
    decision = await engine.evaluate(req)

    assert decision.is_allowed is False
    assert decision.status_code == 403
    assert decision.action == "BLOCK"
    assert decision.pipeline_stage == "URL_INSPECTOR"
