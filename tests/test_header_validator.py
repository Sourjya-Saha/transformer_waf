"""Unit Tests for HTTP Header Validator and RFC Enforcement."""
import pytest
from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.header_parser import HeaderParser
from web_firewall.filters.header_validator import HeaderValidator


@pytest.fixture
def settings():
    return WAFSettings(
        REQUIRED_HEADERS=["Host", "User-Agent"],
        BLOCKED_USER_AGENTS=["sqlmap", "nikto", "nmap"],
        ALLOWED_HOSTS=["api.example.com", "example.com"],
        STRICT_CONTENT_LENGTH=True,
    )


@pytest.fixture
def validator(settings):
    return HeaderValidator(settings=settings)


def test_valid_headers(validator):
    raw = [
        (b"Host", b"example.com"),
        (b"User-Agent", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        (b"Accept", b"application/json"),
    ]
    parser = HeaderParser()
    parsed = parser.parse(raw)

    result = validator.validate(parsed)
    assert result.is_valid is True


def test_missing_required_header(validator):
    raw = [
        (b"User-Agent", b"Mozilla/5.0"),
    ]
    parser = HeaderParser()
    parsed = parser.parse(raw)

    result = validator.validate(parsed)
    assert result.is_valid is False
    assert result.violating_header == "host"
    assert "Missing required HTTP header" in result.reason


def test_blocked_user_agent(validator):
    raw = [
        (b"Host", b"example.com"),
        (b"User-Agent", b"sqlmap/1.5.2#stable"),
    ]
    parser = HeaderParser()
    parsed = parser.parse(raw)

    result = validator.validate(parsed)
    assert result.is_valid is False
    assert result.violating_header == "user-agent"
    assert "Blocked User-Agent" in result.reason


def test_disallowed_host(validator):
    raw = [
        (b"Host", b"evil-attacker.com"),
        (b"User-Agent", b"Mozilla/5.0"),
    ]
    parser = HeaderParser()
    parsed = parser.parse(raw)

    result = validator.validate(parsed)
    assert result.is_valid is False
    assert result.violating_header == "host"
    assert "not in allowed hosts" in result.reason


def test_header_crlf_injection(validator):
    raw = [
        (b"Host", b"example.com"),
        (b"User-Agent", b"NormalUser"),
        (b"X-Custom-Header", b"value\r\nSet-Cookie: admin=true"),
    ]
    parser = HeaderParser()
    parsed = parser.parse(raw)

    result = validator.validate(parsed)
    assert result.is_valid is False
    assert result.matched_rule == "HI-001"
    assert "Dangerous character injection" in result.reason


def test_content_length_mismatch(validator):
    raw = [
        (b"Host", b"example.com"),
        (b"User-Agent", b"Mozilla/5.0"),
        (b"Content-Length", b"100"),
    ]
    parser = HeaderParser()
    parsed = parser.parse(raw)

    # Actual body size is 50 bytes, but Content-Length header is 100
    result = validator.validate(parsed, actual_body_size=50)
    assert result.is_valid is False
    assert result.violating_header == "content-length"
    assert "mismatch" in result.reason
