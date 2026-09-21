"""Asynchronous Request Forwarder to Backend Application."""
import logging
from typing import Dict, List, Set
from fastapi import Response
import httpx

from web_firewall.config.settings import WAFSettings
from web_firewall.parsers.request_parser import ParsedHTTPRequest

logger = logging.getLogger("waf.forwarder")

import urllib.parse

# Standard HTTP Hop-by-Hop headers that should not be forwarded
HOP_BY_HOP_HEADERS: Set[str] = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


class RequestForwarder:
    """Forwards inspected and permitted HTTP requests to the upstream backend server."""

    def __init__(self, settings: WAFSettings):
        self.settings = settings
        self.backend_url = settings.BACKEND_URL.rstrip("/")
        parsed_backend = urllib.parse.urlparse(self.backend_url)
        self.backend_host = parsed_backend.netloc or parsed_backend.path
        self.backend_scheme = parsed_backend.scheme or "http"
        self.timeout = httpx.Timeout(settings.FORWARD_TIMEOUT_SECONDS)
        self._client: httpx.AsyncClient | None = None

    async def get_client(self) -> httpx.AsyncClient:
        """Get or initialize the reusable HTTPX client pool."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=True,
                limits=httpx.Limits(max_keepalive_connections=50, max_connections=100),
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTPX client pool on application shutdown."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def _prepare_headers(self, parsed_req: ParsedHTTPRequest) -> Dict[str, str]:
        """Filter hop-by-hop headers and attach forwarding proxy headers."""
        forward_headers: Dict[str, str] = {}

        for k, v in parsed_req.headers.headers.items():
            if k not in HOP_BY_HOP_HEADERS and k != "host":
                forward_headers[k] = v

        # Set upstream Host header to the target backend's hostname
        forward_headers["host"] = self.backend_host
        forward_headers["x-forwarded-host"] = parsed_req.headers.get("host", "localhost")

        # Append or set X-Forwarded-For
        existing_xff = forward_headers.get("x-forwarded-for")
        if existing_xff:
            forward_headers["x-forwarded-for"] = f"{existing_xff}, {parsed_req.client_ip}"
        else:
            forward_headers["x-forwarded-for"] = parsed_req.client_ip

        forward_headers["x-forwarded-proto"] = self.backend_scheme
        forward_headers["x-real-ip"] = parsed_req.client_ip

        return forward_headers

    async def forward(self, parsed_req: ParsedHTTPRequest) -> Response:
        """Execute async HTTP request to upstream backend and return FastAPI Response."""
        client = await self.get_client()

        # Build upstream target URL
        path = parsed_req.path
        target_url = f"{self.backend_url}{path}"
        if parsed_req.raw_query:
            target_url = f"{target_url}?{parsed_req.raw_query}"

        forward_headers = self._prepare_headers(parsed_req)

        try:
            upstream_response = await client.request(
                method=parsed_req.method,
                url=target_url,
                headers=forward_headers,
                content=parsed_req.body.raw_body if parsed_req.body.raw_body else None,
            )

            # Filter response headers before relaying back to client
            response_headers: Dict[str, str] = {}
            for k, v in upstream_response.headers.items():
                if k.lower() not in HOP_BY_HOP_HEADERS and k.lower() != "content-encoding":
                    response_headers[k] = v

            if "access-control-allow-origin" not in {k.lower() for k in response_headers.keys()}:
                response_headers["Access-Control-Allow-Origin"] = "*"
                response_headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
                response_headers["Access-Control-Allow-Headers"] = "*"

            return Response(
                content=upstream_response.content,
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
            )

        except (httpx.ConnectError, httpx.RemoteProtocolError) as e:
            logger.error(f"Backend connection or protocol error to {target_url}: {e}")
            return Response(
                content=b'{"error": "Bad Gateway", "message": "Failed to connect to upstream backend server. Ensure backend is running on port 8080."}',
                status_code=502,
                headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "*", "Access-Control-Allow-Headers": "*"},
                media_type="application/json",
            )
        except httpx.TimeoutException as e:
            logger.error(f"Backend request timed out for {target_url}: {e}")
            return Response(
                content=b'{"error": "Gateway Timeout", "message": "Upstream backend timed out"}',
                status_code=504,
                headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "*", "Access-Control-Allow-Headers": "*"},
                media_type="application/json",
            )
        except Exception as e:
            logger.error(f"Unexpected error during request forwarding: {e}")
            return Response(
                content=b'{"error": "Internal Gateway Error", "message": "An error occurred forwarding request"}',
                status_code=500,
                headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "*", "Access-Control-Allow-Headers": "*"},
                media_type="application/json",
            )

