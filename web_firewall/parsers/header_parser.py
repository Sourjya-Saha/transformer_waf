"""HTTP Header Parser and Validator."""
from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Tuple


# RFC 7230 token characters: 1*tchar
# tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
#         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
VALID_HEADER_NAME_REGEX = re.compile(r"^[a-zA-Z0-9!#$%&'*+\-.^_`|~]+$")


@dataclass
class ParsedHeaders:
    headers: Dict[str, str] = field(default_factory=dict)
    raw_size: int = 0
    errors: List[str] = field(default_factory=list)

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        return self.headers.get(key.lower(), default)

    def contains(self, key: str) -> bool:
        return key.lower() in self.headers


class HeaderParser:
    """Parses and sanitizes HTTP headers while enforcing RFC compliance."""

    def __init__(self, max_header_size: int = 16384, max_header_value_length: int = 4096):
        self.max_header_size = max_header_size
        self.max_header_value_length = max_header_value_length

    def parse(self, raw_headers: List[Tuple[bytes, bytes]] | Dict[str, str]) -> ParsedHeaders:
        """Parse raw headers into a normalized dictionary (lowercase keys)."""
        parsed = ParsedHeaders()
        total_size = 0

        items: List[Tuple[str, str]] = []
        if isinstance(raw_headers, dict):
            items = list(raw_headers.items())
        else:
            for k, v in raw_headers:
                try:
                    k_str = k.decode("latin-1") if isinstance(k, bytes) else str(k)
                    v_str = v.decode("latin-1") if isinstance(v, bytes) else str(v)
                    items.append((k_str, v_str))
                except Exception as e:
                    parsed.errors.append(f"Header decoding error: {str(e)}")

        for key, val in items:
            key_clean = key.strip()
            val_clean = val.strip()

            # Calculate raw bytes size for header size limit
            header_line_size = len(key_clean.encode("latin-1", "replace")) + len(
                val_clean.encode("latin-1", "replace")
            ) + 4  # Includes ": " and "\r\n"
            total_size += header_line_size

            # Validate header name format
            if not VALID_HEADER_NAME_REGEX.match(key_clean):
                parsed.errors.append(f"Malformed header name format: '{key_clean}'")

            # Check for excessive value length
            if len(val_clean) > self.max_header_value_length:
                parsed.errors.append(
                    f"Header value for '{key_clean}' exceeds maximum allowed length ({len(val_clean)} > {self.max_header_value_length})"
                )

            # Store lowercased header key
            parsed.headers[key_clean.lower()] = val_clean

        parsed.raw_size = total_size
        if total_size > self.max_header_size:
            parsed.errors.append(
                f"Total header size ({total_size} bytes) exceeds maximum limit ({self.max_header_size} bytes)"
            )

        return parsed
