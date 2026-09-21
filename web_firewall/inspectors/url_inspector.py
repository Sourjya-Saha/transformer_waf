"""URL and Query Inspection Module.

Inspects URL paths and query parameters for Path Traversal, Evasion Encodings,
Null Bytes, and Injection Payloads.
"""
from dataclasses import dataclass
from typing import List, Optional
import urllib.parse
from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.query_parser import ParsedQuery
from web_firewall.rules.rules import (
    SecurityRule,
    match_all_rules,
    match_category_rules,
    RuleCategory,
)


@dataclass
class URLInspectionResult:
    is_safe: bool
    reason: str = ""
    matched_rule: Optional[str] = None
    offending_payload: str = ""


class URLInspector:
    """Inspects URL paths and parameters against security rules and traversal signatures."""

    def __init__(self, settings: WAFSettings):
        self.settings = settings
        self.max_url_length = settings.MAX_URL_LENGTH
        self.max_decode_iterations = settings.MAX_DECODE_ITERATIONS

    def _normalize_string(self, text: str) -> List[str]:
        """Produce a list containing the raw string and all progressive decodings."""
        results = [text]
        curr = text
        for _ in range(self.max_decode_iterations):
            try:
                nxt = urllib.parse.unquote(curr)
                if nxt == curr:
                    break
                results.append(nxt)
                curr = nxt
            except Exception:
                break
        return results

    def inspect(self, raw_url: str, path: str, parsed_query: ParsedQuery) -> URLInspectionResult:
        """Perform comprehensive inspection on URL path and query components."""
        # 1. URL Length check
        if len(raw_url) > self.max_url_length:
            return URLInspectionResult(
                is_safe=False,
                reason=f"URL length exceeds maximum allowed limit ({len(raw_url)} > {self.max_url_length})",
                offending_payload=raw_url[:100] + "...",
            )

        # 2. Inspect Path (both raw and decoded forms)
        path_variants = self._normalize_string(path)
        for variant in path_variants:
            match = match_all_rules(variant)
            if match:
                rule, regex_match = match
                return URLInspectionResult(
                    is_safe=False,
                    reason=f"Malicious pattern detected in URL path ({rule.category.value}): {rule.description}",
                    matched_rule=rule.rule_id,
                    offending_payload=regex_match.group(0),
                )

        # 3. Inspect Raw and Normalized Query Strings
        query_candidates = (
            [parsed_query.raw_query]
            + parsed_query.raw_values
            + parsed_query.normalized_values
        )

        for candidate in query_candidates:
            if not candidate:
                continue
            for variant in self._normalize_string(candidate):
                match = match_all_rules(variant)
                if match:
                    rule, regex_match = match
                    return URLInspectionResult(
                        is_safe=False,
                        reason=f"Malicious pattern detected in Query parameter ({rule.category.value}): {rule.description}",
                        matched_rule=rule.rule_id,
                        offending_payload=regex_match.group(0),
                    )

        return URLInspectionResult(
            is_safe=True,
            reason="URL and Query passed all inspection rules",
        )
