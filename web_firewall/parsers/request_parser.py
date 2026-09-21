"""Unified HTTP Request Parser for FastAPI/ASGI Requests."""
from dataclasses import dataclass, field
import ipaddress
from typing import Dict, List, Optional, Tuple
from fastapi import Request

from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.header_parser import HeaderParser, ParsedHeaders
from web_firewall.parsers.query_parser import QueryParser, ParsedQuery
from web_firewall.parsers.cookie_parser import CookieParser
from web_firewall.parsers.body_parser import BodyParser, ParsedBody


@dataclass
class ParsedHTTPRequest:
    client_ip: str
    direct_ip: str
    method: str
    url: str
    path: str
    raw_query: str
    query: ParsedQuery
    headers: ParsedHeaders
    cookies: Dict[str, str]
    body: ParsedBody
    content_type: str = ""
    content_length: Optional[int] = None
    all_extracted_strings: List[str] = field(default_factory=list)


class RequestParser:
    """Extracts and parses all components of an incoming HTTP request."""

    def __init__(self, settings: WAFSettings):
        self.settings = settings
        self.header_parser = HeaderParser(
            max_header_size=settings.MAX_HEADER_SIZE,
            max_header_value_length=settings.MAX_HEADER_VALUE_LENGTH,
        )
        self.query_parser = QueryParser(
            max_decode_iterations=settings.MAX_DECODE_ITERATIONS
        )
        self.cookie_parser = CookieParser()
        self.body_parser = BodyParser(max_body_size=settings.MAX_BODY_SIZE)

        # Parse trusted proxy networks
        self.trusted_proxies: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for proxy_str in settings.TRUSTED_PROXIES:
            try:
                self.trusted_proxies.append(ipaddress.ip_network(proxy_str.strip(), strict=False))
            except ValueError:
                pass

    def _is_trusted_proxy(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in self.trusted_proxies)
        except ValueError:
            return False

    def extract_client_ip(self, request: Request, parsed_headers: ParsedHeaders) -> Tuple[str, str]:
        """Extract both direct connection IP and trusted forwarded client IP."""
        direct_ip = request.client.host if request.client else "127.0.0.1"
        client_ip = direct_ip

        if self._is_trusted_proxy(direct_ip):
            # Check X-Forwarded-For (leftmost is original client)
            x_forwarded_for = parsed_headers.get("x-forwarded-for")
            if x_forwarded_for:
                ips = [x.strip() for x in x_forwarded_for.split(",") if x.strip()]
                if ips:
                    client_ip = ips[0]
            else:
                # Check X-Real-IP
                x_real_ip = parsed_headers.get("x-real-ip")
                if x_real_ip:
                    client_ip = x_real_ip.strip()

        return direct_ip, client_ip

    async def parse_request(self, request: Request) -> ParsedHTTPRequest:
        """Asynchronously parse an incoming FastAPI request."""
        # 1. Headers
        raw_headers = list(request.headers.raw)
        parsed_headers = self.header_parser.parse(raw_headers)

        # 2. Client IP
        direct_ip, client_ip = self.extract_client_ip(request, parsed_headers)

        # 3. Query
        raw_query = request.url.query
        parsed_query = self.query_parser.parse(raw_query)

        # 4. Cookies
        cookie_header = parsed_headers.get("cookie", "")
        cookies = self.cookie_parser.parse(cookie_header)

        # 5. Body
        raw_body = await request.body()
        content_type = parsed_headers.get("content-type", "")
        parsed_body = self.body_parser.parse(raw_body, content_type)

        # 6. Content Length
        cl_str = parsed_headers.get("content-length")
        content_length: Optional[int] = None
        if cl_str and cl_str.isdigit():
            content_length = int(cl_str)

        # 7. Collect all string fragments for comprehensive rule inspection
        all_strings: List[str] = []
        all_strings.append(request.url.path)
        all_strings.extend(parsed_query.normalized_values)
        all_strings.extend(parsed_query.raw_values)
        all_strings.extend(parsed_body.extracted_strings)
        for c_k, c_v in cookies.items():
            all_strings.append(c_k)
            all_strings.append(c_v)

        return ParsedHTTPRequest(
            client_ip=client_ip,
            direct_ip=direct_ip,
            method=request.method.upper(),
            url=str(request.url),
            path=request.url.path,
            raw_query=raw_query,
            query=parsed_query,
            headers=parsed_headers,
            cookies=cookies,
            body=parsed_body,
            content_type=content_type,
            content_length=content_length,
            all_extracted_strings=all_strings,
        )

