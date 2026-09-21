"""Low-Level Raw TCP Socket Client for Protocol-Level & Header Evasion Testing.

High-level HTTP libraries (like httpx, requests, urllib, or browser fetch) validate
headers and reject raw CRLF (\\r\\n), missing User-Agent, or mismatched Content-Length.
This module provides byte-level socket transmission directly to port 80 / 8000.
"""
import socket
import json
from typing import Dict, Any, Tuple, Optional


class RawSocketClient:
    """Constructs and transmits raw HTTP/1.1 byte streams over a direct TCP socket."""

    def __init__(self, host: str = "127.0.0.1", port: int = 80, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def send_raw_http(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        body: str = "",
        override_request_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Send raw HTTP request string over TCP socket and return parsed response."""
        if override_request_bytes:
            raw_data = override_request_bytes
        else:
            # Build manual HTTP/1.1 payload
            lines = [f"{method} {path} HTTP/1.1"]
            if "Connection" not in headers and "connection" not in headers:
                lines.append("Connection: close")
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            lines.append(body)
            raw_data = "\r\n".join(lines).encode("latin-1")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((self.host, self.port))
            sock.sendall(raw_data)

            # Read response
            response_chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response_chunks.append(chunk)
                    combined = b"".join(response_chunks)
                    if b"\r\n\r\n" in combined:
                        header_data, body_data = combined.split(b"\r\n\r\n", 1)
                        # Check content length if available
                        for line in header_data.split(b"\r\n"):
                            if line.lower().startswith(b"content-length:"):
                                cl = int(line.split(b":", 1)[1].strip())
                                if len(body_data) >= cl:
                                    break
                except socket.timeout:
                    break

            raw_response = b"".join(response_chunks).decode("latin-1", errors="replace")
            return self._parse_raw_response(raw_response)

        except Exception as e:
            return {
                "status_code": 0,
                "error": f"Socket Connection Error: {str(e)}",
                "raw_response": "",
                "json": {},
            }
        finally:
            sock.close()

    def _parse_raw_response(self, raw_text: str) -> Dict[str, Any]:
        """Parses raw HTTP response string into status code, headers, and JSON body."""
        if not raw_text:
            return {"status_code": 0, "headers": {}, "body": "", "json": {}}

        parts = raw_text.split("\r\n\r\n", 1)
        header_part = parts[0]
        body_part = parts[1] if len(parts) > 1 else ""

        header_lines = header_part.split("\r\n")
        status_line = header_lines[0] if header_lines else ""
        
        status_code = 0
        status_parts = status_line.split(" ", 2)
        if len(status_parts) >= 2 and status_parts[1].isdigit():
            status_code = int(status_parts[1])

        parsed_headers = {}
        for line in header_lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                parsed_headers[k.strip().lower()] = v.strip()

        parsed_json = {}
        try:
            parsed_json = json.loads(body_part)
        except Exception:
            pass

        return {
            "status_code": status_code,
            "status_line": status_line,
            "headers": parsed_headers,
            "body": body_part,
            "json": parsed_json,
        }

    # ==========================================================================
    # Canned Raw-Socket Attack Generators
    # ==========================================================================
    def test_missing_user_agent(self, path: str = "/api/patients") -> Dict[str, Any]:
        """Fires an HTTP request with the User-Agent header entirely omitted."""
        raw = f"GET {path} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\nAccept: */*\r\n\r\n".encode("latin-1")
        return self.send_raw_http("GET", path, {}, override_request_bytes=raw)

    def test_crlf_header_injection(self, path: str = "/api/patients") -> Dict[str, Any]:
        """Fires an HTTP request with CRLF injection inside a header value (Rule HI-001)."""
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"X-Referral: medical\rSet-Cookie: admin=true\r\n"
            f"Connection: close\r\n"
            f"Accept: */*\r\n\r\n"
        ).encode("latin-1")
        return self.send_raw_http("GET", path, {}, override_request_bytes=raw)

    def test_content_length_mismatch(self, path: str = "/api/login") -> Dict[str, Any]:
        """Fires an HTTP request with Content-Length header mismatched to body length."""
        # Header claims 0 bytes but actual body is 25 bytes
        body = '{"user":"test_mismatch"}'
        headers = {
            "Host": self.host,
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/json",
            "Content-Length": "0",
            "Connection": "close"
        }
        return self.send_raw_http("POST", path, headers, body=body)
