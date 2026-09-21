"""Unit Tests for URL and Query Inspection (Path Traversal & Injections)."""
import pytest
from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.query_parser import QueryParser
from web_firewall.inspectors.url_inspector import URLInspector


@pytest.fixture
def inspector():
    settings = WAFSettings(MAX_URL_LENGTH=500, MAX_DECODE_ITERATIONS=3)
    return URLInspector(settings=settings)


@pytest.fixture
def query_parser():
    return QueryParser(max_decode_iterations=3)


def test_safe_url(inspector, query_parser):
    path = "/api/v1/products"
    raw_query = "page=1&limit=20&sort=name"
    query = query_parser.parse(raw_query)

    res = inspector.inspect(raw_url=f"http://example.com{path}?{raw_query}", path=path, parsed_query=query)
    assert res.is_safe is True


@pytest.mark.parametrize(
    "attack_path,expected_rule",
    [
        ("../etc/passwd", "PT-001"),
        ("..\\windows\\system32", "PT-001"),
        ("/var/www/../../etc/passwd", "PT-001"),
        ("/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd", "PT-002"),
        ("/files/%252e%252e%252fetc%252fpasswd", "PT-003"),
        ("/config/.env", "PT-006"),
        ("/.git/config", "PT-006"),
        ("/windows/system32/cmd.exe", "PT-005"),
        ("/etc/shadow", "PT-004"),
        ("/images/avatar.png%00.php", "NB-001"),
    ],
)
def test_path_traversal_attacks(inspector, query_parser, attack_path, expected_rule):
    query = query_parser.parse("")
    res = inspector.inspect(raw_url=f"http://example.com{attack_path}", path=attack_path, parsed_query=query)
    assert res.is_safe is False
    assert res.matched_rule in (expected_rule, "PT-001", "PT-002", "PT-003", "PT-004", "PT-005", "PT-006", "NB-001")


@pytest.mark.parametrize(
    "attack_query,expected_rule",
    [
        ("file=../../etc/passwd", "PT-001"),
        ("doc=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "PT-002"),
        ("target=%252e%252e%252fsecret", "PT-003"),
        ("id=1%20UNION%20SELECT%20username,password%20FROM%20users", "SQL-001"),
        ("category=books'%20OR%201=1--", "SQL-002"),
        ("cmd=test;cat%20/etc/passwd", "CI-001"),
        ("name=<script>alert(1)</script>", "XSS-001"),
    ],
)
def test_query_parameter_attacks(inspector, query_parser, attack_query, expected_rule):
    path = "/search"
    query = query_parser.parse(attack_query)
    res = inspector.inspect(raw_url=f"http://example.com{path}?{attack_query}", path=path, parsed_query=query)
    assert res.is_safe is False
    assert res.matched_rule is not None


def test_url_length_exceeded(inspector, query_parser):
    long_path = "/a" * 300
    query = query_parser.parse("")
    res = inspector.inspect(raw_url=f"http://example.com{long_path}", path=long_path, parsed_query=query)
    assert res.is_safe is False
    assert "URL length exceeds" in res.reason
