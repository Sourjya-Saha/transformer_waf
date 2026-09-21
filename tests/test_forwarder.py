"""Unit Tests for Request Forwarder and Protocol Relay."""
import pytest
import httpx
from fastapi import Response
from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.request_parser import ParsedHTTPRequest
from web_firewall.parsers.header_parser import ParsedHeaders
from web_firewall.parsers.query_parser import ParsedQuery
from web_firewall.parsers.body_parser import ParsedBody
from web_firewall.gateway.request_forwarder import RequestForwarder


def create_sample_request(
    method: str = "GET",
    path: str = "/api/test",
    raw_query: str = "foo=bar",
    headers_dict: dict = None,
    cookies: dict = None,
    body_bytes: bytes = b"",
) -> ParsedHTTPRequest:
    headers_dict = headers_dict or {"host": "example.com", "user-agent": "TestAgent"}
    cookies = cookies or {"session": "abc123xyz"}
    return ParsedHTTPRequest(
        client_ip="203.0.113.195",
        direct_ip="127.0.0.1",
        method=method,
        url=f"http://example.com{path}?{raw_query}",
        path=path,
        raw_query=raw_query,
        query=ParsedQuery(raw_query=raw_query),
        headers=ParsedHeaders(headers=headers_dict),
        cookies=cookies,
        body=ParsedBody(raw_body=body_bytes, size_bytes=len(body_bytes)),
    )


@pytest.mark.asyncio
async def test_forwarder_preserves_request_and_response():
    # Mock upstream response
    def handler(request: httpx.Request):
        assert request.method == "POST"
        assert request.url.path == "/api/test"
        assert request.url.query.decode("latin-1") == "foo=bar"
        assert request.headers["x-forwarded-for"] == "203.0.113.195"
        assert request.headers["x-real-ip"] == "203.0.113.195"
        assert "custom-header" in request.headers
        assert request.read() == b'{"key": "value"}'

        return httpx.Response(
            status_code=201,
            headers={"Content-Type": "application/json", "X-Server-ID": "backend-01"},
            content=b'{"created": true}',
        )

    transport = httpx.MockTransport(handler)
    settings = WAFSettings(BACKEND_URL="http://mock-backend:8080")
    forwarder = RequestForwarder(settings=settings)
    forwarder._client = httpx.AsyncClient(transport=transport)

    req = create_sample_request(
        method="POST",
        headers_dict={"host": "example.com", "user-agent": "TestAgent", "custom-header": "my-value"},
        body_bytes=b'{"key": "value"}',
    )

    resp = await forwarder.forward(req)
    assert resp.status_code == 201
    assert resp.body == b'{"created": true}'
    assert resp.headers.get("x-server-id") == "backend-01"


@pytest.mark.asyncio
async def test_forwarder_all_http_verbs():
    verbs = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    settings = WAFSettings(BACKEND_URL="http://mock-backend:8080")

    for verb in verbs:
        def handler(request: httpx.Request, current_verb=verb):
            assert request.method == current_verb
            return httpx.Response(200, content=b"ok")

        forwarder = RequestForwarder(settings=settings)
        forwarder._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

        req = create_sample_request(method=verb)
        resp = await forwarder.forward(req)
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_forwarder_backend_error_handling():
    # Simulate connection error
    def error_handler(request: httpx.Request):
        raise httpx.ConnectError("Connection refused")

    settings = WAFSettings(BACKEND_URL="http://down-backend:8080")
    forwarder = RequestForwarder(settings=settings)
    forwarder._client = httpx.AsyncClient(transport=httpx.MockTransport(error_handler))

    req = create_sample_request()
    resp = await forwarder.forward(req)
    assert resp.status_code == 502
    assert b"Bad Gateway" in resp.body
