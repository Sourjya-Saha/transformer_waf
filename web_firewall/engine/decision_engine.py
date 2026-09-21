"""Central Decision Engine for WAF Pipeline Execution."""
from dataclasses import dataclass
from typing import Optional
import logging

from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.request_parser import ParsedHTTPRequest
from web_firewall.filters.ip_filter import IPFilter
from web_firewall.filters.rate_limiter import RateLimiter
from web_firewall.filters.header_validator import HeaderValidator
from web_firewall.inspectors.url_inspector import URLInspector
from web_firewall.inspectors.body_inspector import BodyInspector

logger = logging.getLogger("waf.decision_engine")


@dataclass
class SecurityDecision:
    is_allowed: bool
    status_code: int
    block_reason: str
    rule_id: Optional[str]
    client_ip: str
    action: str  # "ALLOW" or "BLOCK"
    pipeline_stage: str
    retry_after: Optional[float] = None


class DecisionEngine:
    """Coordinates the deterministic WAF inspection pipeline and renders final decisions."""

    def __init__(self, settings: WAFSettings):
        self.settings = settings
        self.ip_filter = IPFilter(
            allowlist=settings.IP_ALLOWLIST,
            blocklist=settings.IP_BLOCKLIST,
        )
        self.rate_limiter = RateLimiter(
            algorithm=settings.RATE_LIMIT_ALGORITHM,
            requests_per_minute=settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
            requests_per_hour=settings.RATE_LIMIT_REQUESTS_PER_HOUR,
            requests_per_day=settings.RATE_LIMIT_REQUESTS_PER_DAY,
            burst_capacity=settings.RATE_LIMIT_BURST,
        )
        self.header_validator = HeaderValidator(settings=settings)
        self.url_inspector = URLInspector(settings=settings)
        self.body_inspector = BodyInspector(settings=settings)

    async def evaluate(self, parsed_req: ParsedHTTPRequest) -> SecurityDecision:
        """Execute the full inspection pipeline sequentially on the parsed request."""
        client_ip = parsed_req.client_ip

        # ---------------------------------------------------------
        # STAGE 1: IP Filtering
        # ---------------------------------------------------------
        ip_decision = self.ip_filter.evaluate(client_ip)
        if not ip_decision.is_allowed:
            return SecurityDecision(
                is_allowed=False,
                status_code=403,
                block_reason=ip_decision.reason,
                rule_id="IP-FILTER",
                client_ip=client_ip,
                action="BLOCK",
                pipeline_stage="IP_FILTER",
            )

        # ---------------------------------------------------------
        # STAGE 2: Rate Limiting
        # ---------------------------------------------------------
        if self.settings.RATE_LIMIT_ENABLED:
            rl_decision = await self.rate_limiter.evaluate(client_ip)
            if not rl_decision.is_allowed:
                return SecurityDecision(
                    is_allowed=False,
                    status_code=429,
                    block_reason=rl_decision.reason,
                    rule_id="RATE-LIMIT",
                    client_ip=client_ip,
                    action="BLOCK",
                    pipeline_stage="RATE_LIMITER",
                    retry_after=rl_decision.retry_after,
                )

        # ---------------------------------------------------------
        # STAGE 3: Header Validation
        # ---------------------------------------------------------
        if self.settings.HEADER_VALIDATION_ENABLED:
            body_size = parsed_req.body.size_bytes
            hv_result = self.header_validator.validate(parsed_req.headers, body_size)
            if not hv_result.is_valid:
                return SecurityDecision(
                    is_allowed=False,
                    status_code=403,
                    block_reason=hv_result.reason,
                    rule_id=hv_result.matched_rule or "HEADER-VALIDATION",
                    client_ip=client_ip,
                    action="BLOCK",
                    pipeline_stage="HEADER_VALIDATOR",
                )

        # ---------------------------------------------------------
        # STAGE 4: URL & Path Traversal Inspection
        # ---------------------------------------------------------
        if self.settings.URL_INSPECTION_ENABLED:
            url_result = self.url_inspector.inspect(
                raw_url=parsed_req.url,
                path=parsed_req.path,
                parsed_query=parsed_req.query,
            )
            if not url_result.is_safe:
                return SecurityDecision(
                    is_allowed=False,
                    status_code=403,
                    block_reason=url_result.reason,
                    rule_id=url_result.matched_rule or "URL-INSPECTION",
                    client_ip=client_ip,
                    action="BLOCK",
                    pipeline_stage="URL_INSPECTOR",
                )

        # ---------------------------------------------------------
        # STAGE 5: Request Body Inspection
        # ---------------------------------------------------------
        if self.settings.BODY_INSPECTION_ENABLED:
            body_result = self.body_inspector.inspect(parsed_req.body)
            if not body_result.is_safe:
                return SecurityDecision(
                    is_allowed=False,
                    status_code=403,
                    block_reason=body_result.reason,
                    rule_id=body_result.matched_rule or "BODY-INSPECTION",
                    client_ip=client_ip,
                    action="BLOCK",
                    pipeline_stage="BODY_INSPECTOR",
                )

        # ---------------------------------------------------------
        # ALLOWED: All stages passed
        # ---------------------------------------------------------
        return SecurityDecision(
            is_allowed=True,
            status_code=200,
            block_reason="",
            rule_id=None,
            client_ip=client_ip,
            action="ALLOW",
            pipeline_stage="PASSED",
        )
