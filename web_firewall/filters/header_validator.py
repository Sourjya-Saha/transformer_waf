"""HTTP Header Validator and Policy Enforcement."""
from dataclasses import dataclass, field
import re
from typing import List, Optional
from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.header_parser import ParsedHeaders
from web_firewall.rules.rules import HEADER_INJECTION_RULES, NULL_BYTE_RULES


@dataclass
class HeaderValidationResult:
    is_valid: bool
    reason: str = ""
    violating_header: str = ""
    matched_rule: Optional[str] = None


class HeaderValidator:
    """Validates HTTP request headers against security policies and RFC standards."""

    def __init__(self, settings: WAFSettings):
        self.settings = settings
        self.required_headers = [h.lower() for h in settings.REQUIRED_HEADERS]
        self.blocked_user_agents = [ua.lower() for ua in settings.BLOCKED_USER_AGENTS]
        self.allowed_hosts = [h.lower() for h in settings.ALLOWED_HOSTS]

    def validate(
        self, parsed_headers: ParsedHeaders, actual_body_size: int = 0
    ) -> HeaderValidationResult:
        """Execute full header validation suite."""
        # 1. Check for parser-level errors (oversized, malformed characters)
        if parsed_headers.errors:
            return HeaderValidationResult(
                is_valid=False,
                reason=f"Header parse error: {'; '.join(parsed_headers.errors)}",
            )

        # 2. Check required headers
        for req_header in self.required_headers:
            val = parsed_headers.get(req_header)
            if not val:
                return HeaderValidationResult(
                    is_valid=False,
                    reason=f"Missing required HTTP header: '{req_header}'",
                    violating_header=req_header,
                )

        # 3. Check for CRLF / Null Byte Injection across all headers
        for key, val in parsed_headers.headers.items():
            for rule in HEADER_INJECTION_RULES + NULL_BYTE_RULES:
                if rule.matches(val):
                    return HeaderValidationResult(
                        is_valid=False,
                        reason=f"Dangerous character injection detected in header '{key}': {rule.description}",
                        violating_header=key,
                        matched_rule=rule.rule_id,
                    )

        # 4. Validate Host header
        host = parsed_headers.get("host")
        if host:
            # Strip port if present
            host_domain = host.split(":")[0].strip().lower()
            if self.allowed_hosts and host_domain not in self.allowed_hosts:
                return HeaderValidationResult(
                    is_valid=False,
                    reason=f"Host header value '{host}' is not in allowed hosts list",
                    violating_header="host",
                )

        # 5. Validate User-Agent against security scanner / attack tool signatures
        user_agent = parsed_headers.get("user-agent", "").lower()
        if user_agent:
            for blocked_ua in self.blocked_user_agents:
                if blocked_ua in user_agent:
                    return HeaderValidationResult(
                        is_valid=False,
                        reason=f"Blocked User-Agent signature identified: '{blocked_ua}'",
                        violating_header="user-agent",
                        matched_rule="UA-BLOCK",
                    )

        # 6. Validate Content-Length vs Actual Body Size
        content_length_str = parsed_headers.get("content-length")
        if content_length_str is not None:
            if not content_length_str.isdigit():
                return HeaderValidationResult(
                    is_valid=False,
                    reason=f"Malformed Content-Length value: '{content_length_str}'",
                    violating_header="content-length",
                )
            content_length = int(content_length_str)
            if self.settings.STRICT_CONTENT_LENGTH and actual_body_size > 0:
                if content_length != actual_body_size:
                    return HeaderValidationResult(
                        is_valid=False,
                        reason=f"Content-Length mismatch: header says {content_length} bytes, but body is {actual_body_size} bytes",
                        violating_header="content-length",
                    )

        return HeaderValidationResult(
            is_valid=True,
            reason="All header validation policies passed",
        )
