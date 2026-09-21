"""WAF Configuration and Settings Module."""
from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class WAFSettings(BaseSettings):
    """Configuration settings for the Web Application Firewall."""

    model_config = SettingsConfigDict(
        env_prefix="WAF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 1
    RELOAD: bool = True
    DEBUG: bool = True
    BACKEND_URL: str = "http://127.0.0.1:8080"
    FORWARD_TIMEOUT_SECONDS: float = 30.0

    # Logging settings
    LOG_DIR: str = "logs"
    LOG_FILE: str = "logs/waf.log"
    LOG_LEVEL: str = "INFO"
    ENABLE_CONSOLE_LOGS: bool = True

    # Trusted reverse proxies for extracting real client IP (CIDRs or IPs)
    TRUSTED_PROXIES: List[str] = Field(
        default_factory=lambda: [
            "127.0.0.1",
            "::1",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )

    # IP Filter settings (Exact IP or CIDR)
    IP_ALLOWLIST: List[str] = Field(default_factory=list)
    IP_BLOCKLIST: List[str] = Field(default_factory=list)

    # Rate Limiting settings
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_ALGORITHM: str = "token_bucket"  # "token_bucket" or "sliding_window"
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 30
    RATE_LIMIT_REQUESTS_PER_HOUR: int = 1000
    RATE_LIMIT_REQUESTS_PER_DAY: int = 10000
    RATE_LIMIT_BURST: int = 10

    # Header Validation settings
    HEADER_VALIDATION_ENABLED: bool = True
    REQUIRED_HEADERS: List[str] = Field(
        default_factory=lambda: ["host", "user-agent"]
    )
    BLOCKED_USER_AGENTS: List[str] = Field(
        default_factory=lambda: [
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "w3af",
            "zgrab",
            "gobuster",
            "dirbuster",
            "acunetix",
            "havij",
            "nessus",
            "qualys",
        ]
    )
    ALLOWED_HOSTS: List[str] = Field(default_factory=list)  # Empty allows all valid hosts
    MAX_HEADER_SIZE: int = 16384  # 16 KB total header size limit
    MAX_HEADER_VALUE_LENGTH: int = 4096

    # Inspection settings
    URL_INSPECTION_ENABLED: bool = True
    BODY_INSPECTION_ENABLED: bool = True
    MAX_URL_LENGTH: int = 4096
    MAX_BODY_SIZE: int = 10 * 1024 * 1024  # 10 MB
    MAX_DECODE_ITERATIONS: int = 3
    STRICT_CONTENT_LENGTH: bool = True


@lru_cache()
def get_settings() -> WAFSettings:
    """Return cached application settings instance."""
    return WAFSettings()
