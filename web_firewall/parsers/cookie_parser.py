"""HTTP Cookie Header Parser."""
from typing import Dict
from http.cookies import SimpleCookie


class CookieParser:
    """Parses HTTP Cookie header safely without throwing exceptions on malformed input."""

    @staticmethod
    def parse(cookie_header: str) -> Dict[str, str]:
        """Parse raw Cookie header into dictionary of key-value pairs."""
        if not cookie_header:
            return {}

        cookies: Dict[str, str] = {}
        try:
            simple = SimpleCookie()
            simple.load(cookie_header)
            for key, morsel in simple.items():
                cookies[key] = morsel.value
        except Exception:
            # Fallback manual parser for non-standard/malformed cookies
            pairs = cookie_header.split(";")
            for pair in pairs:
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    cookies[k.strip()] = v.strip().strip('"')
                else:
                    cookies[pair.strip()] = ""

        return cookies
