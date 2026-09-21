"""Unit Tests for IP Filter (Single IP and CIDR Subnets)."""
import pytest
from web_firewall.filters.ip_filter import IPFilter


def test_allow_all_when_empty_lists():
    ip_filter = IPFilter()
    decision = ip_filter.evaluate("192.168.1.100")
    assert decision.is_allowed is True


def test_blocklist_single_ip():
    ip_filter = IPFilter(blocklist=["10.0.0.5", "192.168.1.50"])
    
    # Blocked
    d1 = ip_filter.evaluate("10.0.0.5")
    assert d1.is_allowed is False
    assert "blocked by blocklist" in d1.reason

    # Allowed
    d2 = ip_filter.evaluate("10.0.0.6")
    assert d2.is_allowed is True


def test_blocklist_cidr_subnet():
    ip_filter = IPFilter(blocklist=["192.168.1.0/24", "10.10.0.0/16"])

    # Inside subnet -> Blocked
    assert ip_filter.evaluate("192.168.1.1").is_allowed is False
    assert ip_filter.evaluate("192.168.1.254").is_allowed is False
    assert ip_filter.evaluate("10.10.25.100").is_allowed is False

    # Outside subnet -> Allowed
    assert ip_filter.evaluate("192.168.2.1").is_allowed is True
    assert ip_filter.evaluate("10.11.0.1").is_allowed is True


def test_allowlist_precedence_over_blocklist():
    # Even if in blocklist subnet, specific allowlist permits it
    ip_filter = IPFilter(
        allowlist=["192.168.1.100"],
        blocklist=["192.168.1.0/24"],
    )

    # In allowlist -> Allowed
    d1 = ip_filter.evaluate("192.168.1.100")
    assert d1.is_allowed is True

    # In blocklist and NOT in allowlist -> Blocked
    d2 = ip_filter.evaluate("192.168.1.101")
    assert d2.is_allowed is False


def test_allowlist_default_deny():
    ip_filter = IPFilter(allowlist=["10.0.0.1", "172.16.0.0/12"])

    # Matches allowlist
    assert ip_filter.evaluate("10.0.0.1").is_allowed is True
    assert ip_filter.evaluate("172.16.50.1").is_allowed is True

    # Not in allowlist
    assert ip_filter.evaluate("10.0.0.2").is_allowed is False
    assert ip_filter.evaluate("8.8.8.8").is_allowed is False


def test_ipv6_support():
    ip_filter = IPFilter(blocklist=["2001:db8::/32"])
    
    assert ip_filter.evaluate("2001:db8::1").is_allowed is False
    assert ip_filter.evaluate("2001:db9::1").is_allowed is True


def test_malformed_ip():
    ip_filter = IPFilter()
    decision = ip_filter.evaluate("invalid-ip-format")
    assert decision.is_allowed is False
    assert "Malformed" in decision.reason
