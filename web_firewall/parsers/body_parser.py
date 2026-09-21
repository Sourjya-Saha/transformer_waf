"""HTTP Request Body Parser.

Safely parses JSON, Form URL-encoded, Multipart form data, and XML payloads,
extracting all structural and textual values for security inspection.
"""
from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional
import urllib.parse
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException


@dataclass
class ParsedBody:
    raw_body: bytes = b""
    content_type: str = ""
    size_bytes: int = 0
    extracted_strings: List[str] = field(default_factory=list)
    parsed_json: Optional[Any] = None
    parsed_form: Optional[Dict[str, List[str]]] = None
    parsed_xml_tags: Optional[List[str]] = None
    parse_error: Optional[str] = None


class BodyParser:
    """Parses various HTTP body content types and flattens them for inspection."""

    def __init__(self, max_body_size: int = 10 * 1024 * 1024):
        self.max_body_size = max_body_size

    def parse(self, raw_body: bytes, content_type_header: str) -> ParsedBody:
        """Parse raw body bytes based on Content-Type."""
        content_type = content_type_header.lower().split(";")[0].strip() if content_type_header else ""
        size = len(raw_body)

        result = ParsedBody(
            raw_body=raw_body,
            content_type=content_type,
            size_bytes=size,
        )

        if not raw_body:
            return result

        # Add decoded raw string as fallback inspection target for non-multipart payloads
        if not content_type.startswith("multipart/"):
            try:
                raw_decoded = raw_body.decode("utf-8", errors="replace")
                result.extracted_strings.append(raw_decoded)
            except Exception:
                pass

        # 1. JSON
        if content_type in ("application/json", "application/problem+json") or (
            not content_type and raw_body.strip().startswith((b"{", b"["))
        ):
            self._parse_json(raw_body, result)

        # 2. Form URL-Encoded
        elif content_type == "application/x-www-form-urlencoded":
            self._parse_form(raw_body, result)

        # 3. Multipart Form-Data
        elif content_type.startswith("multipart/"):
            self._parse_multipart(raw_body, content_type_header, result)

        # 4. XML
        elif content_type in ("application/xml", "text/xml", "application/soap+xml") or (
            not content_type and raw_body.strip().startswith(b"<")
        ):
            self._parse_xml(raw_body, result)

        return result

    def _parse_json(self, raw_body: bytes, result: ParsedBody) -> None:
        try:
            data = json.loads(raw_body.decode("utf-8", errors="replace"))
            result.parsed_json = data
            self._extract_json_strings(data, result.extracted_strings)
        except Exception as e:
            result.parse_error = f"Malformed JSON: {str(e)}"

    def _extract_json_strings(self, obj: Any, out: List[str]) -> None:
        if isinstance(obj, str):
            out.append(obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                out.append(str(k))
                self._extract_json_strings(v, out)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_json_strings(item, out)
        elif isinstance(obj, (int, float, bool)):
            out.append(str(obj))

    def _parse_form(self, raw_body: bytes, result: ParsedBody) -> None:
        try:
            decoded = raw_body.decode("utf-8", errors="replace")
            parsed = urllib.parse.parse_qs(decoded, keep_blank_values=True)
            result.parsed_form = parsed
            for k, vals in parsed.items():
                result.extracted_strings.append(k)
                result.extracted_strings.extend(vals)
        except Exception as e:
            result.parse_error = f"Malformed form data: {str(e)}"

    def _parse_multipart(self, raw_body: bytes, content_type_header: str, result: ParsedBody) -> None:
        try:
            body_str = raw_body.decode("latin-1", errors="replace")

            # Extract header content-disposition names and filenames
            field_names = re.findall(r'name="([^"]+)"', body_str)
            file_names = re.findall(r'filename="([^"]+)"', body_str)
            result.extracted_strings.extend(field_names)
            result.extracted_strings.extend(file_names)

            # Extract text field values (parts without filename)
            parts = re.split(r'--[^\r\n]+', body_str)
            for part in parts:
                if not part.strip() or 'filename=' in part:
                    continue
                header_body_split = part.split('\r\n\r\n', 1)
                if len(header_body_split) > 1:
                    text_val = header_body_split[1].rstrip('\r\n')
                    if text_val:
                        result.extracted_strings.append(text_val)
        except Exception as e:
            result.parse_error = f"Malformed multipart data: {str(e)}"

    def _parse_xml(self, raw_body: bytes, result: ParsedBody) -> None:
        try:
            # defusedxml protects against standard entity expansion/billion laughs
            root = ET.fromstring(raw_body)
            tags: List[str] = []

            def _traverse_xml(node: ET.Element):
                tags.append(node.tag)
                result.extracted_strings.append(node.tag)
                if node.text and node.text.strip():
                    result.extracted_strings.append(node.text.strip())
                for attr_k, attr_v in node.attrib.items():
                    result.extracted_strings.append(str(attr_k))
                    result.extracted_strings.append(str(attr_v))
                for child in node:
                    _traverse_xml(child)

            _traverse_xml(root)
            result.parsed_xml_tags = tags
        except DefusedXmlException as e:
            result.parse_error = f"Defused XML security exception: {str(e)}"
        except Exception as e:
            result.parse_error = f"Malformed XML: {str(e)}"
