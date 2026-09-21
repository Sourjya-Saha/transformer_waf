"""IP Filtering Module with Single IP and CIDR Subnet Support."""
from dataclasses import dataclass
import ipaddress
import logging
from typing import List, Tuple, Union

logger = logging.getLogger("waf.ip_filter")

IPNetworkType = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class IPFilterDecision:
    is_allowed: bool
    reason: str
    matched_entry: str = ""


class IPFilter:
    """Evaluates client IP addresses against Allowlist and Blocklist CIDRs."""

    def __init__(self, allowlist: List[str] = None, blocklist: List[str] = None):
        self.allowlist: List[Tuple[str, IPNetworkType]] = []
        self.blocklist: List[Tuple[str, IPNetworkType]] = []

        if allowlist:
            for entry in allowlist:
                self.add_allow_entry(entry)

        if blocklist:
            for entry in blocklist:
                self.add_block_entry(entry)

    def _parse_network(self, entry: str) -> IPNetworkType:
        """Parse single IP or CIDR notation into an IPv4/IPv6 network object."""
        entry = entry.strip()
        return ipaddress.ip_network(entry, strict=False)

    def add_allow_entry(self, entry: str) -> bool:
        """Add an IP or CIDR subnet to the allowlist."""
        try:
            net = self._parse_network(entry)
            self.allowlist.append((entry, net))
            return True
        except ValueError as e:
            logger.error(f"Invalid allowlist IP/CIDR '{entry}': {e}")
            return False

    def add_block_entry(self, entry: str) -> bool:
        """Add an IP or CIDR subnet to the blocklist."""
        try:
            net = self._parse_network(entry)
            self.blocklist.append((entry, net))
            return True
        except ValueError as e:
            logger.error(f"Invalid blocklist IP/CIDR '{entry}': {e}")
            return False

    def evaluate(self, client_ip_str: str) -> IPFilterDecision:
        """Evaluate a client IP address.

        Allowlist takes explicit priority over Blocklist.
        If allowlist is non-empty and IP is not in allowlist, it is blocked.
        If IP matches blocklist, it is blocked.
        Otherwise allowed.
        """
        try:
            client_ip = ipaddress.ip_address(client_ip_str.strip())
        except ValueError:
            return IPFilterDecision(
                is_allowed=False,
                reason=f"Malformed client IP address: '{client_ip_str}'",
            )

        # Check explicit allowlist first
        for entry_str, net in self.allowlist:
            if client_ip in net:
                return IPFilterDecision(
                    is_allowed=True,
                    reason="Client IP explicitly permitted by allowlist",
                    matched_entry=entry_str,
                )

        # If allowlist is populated and IP wasn't in it -> Deny default
        if self.allowlist:
            return IPFilterDecision(
                is_allowed=False,
                reason="Client IP not present in active allowlist",
            )

        # Check blocklist
        for entry_str, net in self.blocklist:
            if client_ip in net:
                return IPFilterDecision(
                    is_allowed=False,
                    reason=f"Client IP blocked by blocklist rule ({entry_str})",
                    matched_entry=entry_str,
                )

        return IPFilterDecision(
            is_allowed=True,
            reason="Client IP passed filter evaluation",
        )
