"""URL Query Parameter Parser and Normalizer."""
from dataclasses import dataclass, field
from typing import Dict, List
import urllib.parse


@dataclass
class ParsedQuery:
    raw_query: str = ""
    params: Dict[str, List[str]] = field(default_factory=dict)
    normalized_values: List[str] = field(default_factory=list)
    raw_values: List[str] = field(default_factory=list)


class QueryParser:
    """Parses, unquotes, and normalizes URL query strings with multi-pass decoding."""

    def __init__(self, max_decode_iterations: int = 3):
        self.max_decode_iterations = max_decode_iterations

    def multi_decode(self, value: str) -> str:
        """Repeatedly URL-decode a string to reveal double/nested encoding evasion."""
        curr = value
        for _ in range(self.max_decode_iterations):
            try:
                nxt = urllib.parse.unquote(curr)
                if nxt == curr:
                    break
                curr = nxt
            except Exception:
                break
        return curr

    def parse(self, raw_query_string: str | bytes) -> ParsedQuery:
        """Parse raw query string into structured query object."""
        if isinstance(raw_query_string, bytes):
            raw_str = raw_query_string.decode("latin-1", errors="replace")
        else:
            raw_str = str(raw_query_string)

        result = ParsedQuery(raw_query=raw_str)
        if not raw_str:
            return result

        parsed_qs = urllib.parse.parse_qs(raw_str, keep_blank_values=True)
        result.params = parsed_qs

        for k, vals in parsed_qs.items():
            result.raw_values.append(k)
            result.normalized_values.append(self.multi_decode(k))
            for v in vals:
                result.raw_values.append(v)
                result.normalized_values.append(self.multi_decode(v))

        return result
