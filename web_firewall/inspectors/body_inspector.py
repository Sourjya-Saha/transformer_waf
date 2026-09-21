"""Request Body Inspection Module.

Inspects JSON, Form, Multipart, and XML payloads for size limits, malformed encodings,
and malicious attack patterns.
"""
from dataclasses import dataclass
from typing import List, Optional
import urllib.parse
from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.body_parser import ParsedBody
from web_firewall.rules.rules import (
    SecurityRule,
    match_payload_rules,
    match_category_rules,
    RuleCategory,
)


@dataclass
class BodyInspectionResult:
    is_safe: bool
    reason: str = ""
    matched_rule: Optional[str] = None
    offending_payload: str = ""


class BodyInspector:
    """Inspects parsed HTTP request body structures against security policies."""

    def __init__(self, settings: WAFSettings):
        self.settings = settings
        self.max_body_size = settings.MAX_BODY_SIZE
        self.max_decode_iterations = settings.MAX_DECODE_ITERATIONS

    def _normalize_string(self, text: str) -> List[str]:
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

    def inspect(self, parsed_body: ParsedBody) -> BodyInspectionResult:
        """Inspect request body contents."""
        # 1. Body Size Limit
        if parsed_body.size_bytes > self.max_body_size:
            return BodyInspectionResult(
                is_safe=False,
                reason=f"Request body size exceeds maximum limit ({parsed_body.size_bytes} > {self.max_body_size} bytes)",
            )

        # 2. Body Parser Errors / DefusedXML Security Violations
        if parsed_body.parse_error:
            if "Defused XML" in parsed_body.parse_error or "security" in parsed_body.parse_error.lower():
                return BodyInspectionResult(
                    is_safe=False,
                    reason=f"Security violation during XML body parsing: {parsed_body.parse_error}",
                    matched_rule="XXE-001",
                )

        # 3. Inspect Raw Body Bytes for non-multipart payloads (e.g. raw XML / JSON / Form payloads)
        if parsed_body.raw_body and not parsed_body.content_type.startswith("multipart/"):
            try:
                raw_text = parsed_body.raw_body.decode("utf-8", errors="replace")
                match = match_payload_rules(raw_text)
                if match:
                    rule, regex_match = match
                    return BodyInspectionResult(
                        is_safe=False,
                        reason=f"Malicious pattern detected in raw body ({rule.category.value}): {rule.description}",
                        matched_rule=rule.rule_id,
                        offending_payload=regex_match.group(0)[:100],
                    )
            except Exception:
                pass

        # 4. Inspect all extracted structured strings (JSON keys/values, Form fields, Multipart filenames, XML text)
        for item in parsed_body.extracted_strings:
            if not item:
                continue
            for variant in self._normalize_string(item):
                match = match_payload_rules(variant)
                if match:
                    rule, regex_match = match
                    return BodyInspectionResult(
                        is_safe=False,
                        reason=f"Malicious pattern detected in body payload ({rule.category.value}): {rule.description}",
                        matched_rule=rule.rule_id,
                        offending_payload=regex_match.group(0)[:100],
                    )

        return BodyInspectionResult(
            is_safe=True,
            reason="Request body passed all inspection rules",
        )
