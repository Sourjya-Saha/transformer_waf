"""Rate Limiter Implementations.

Implements Token Bucket and Sliding Window algorithms with multi-tier
time-window limits (minute, hour, day).
"""
import asyncio
from dataclasses import dataclass, field
import time
from typing import Dict, List, Optional, Tuple


@dataclass
class RateLimitDecision:
    is_allowed: bool
    retry_after: float = 0.0
    current_count: int = 0
    limit: int = 0
    remaining: float = 0.0
    reason: str = ""


# ============================================================================
# 1. Token Bucket Algorithm
# ============================================================================
class TokenBucketLimiter:
    """Token Bucket rate limiter for smooth rate regulation with burst tolerance."""

    def __init__(self, rate_per_minute: float, burst_capacity: float):
        self.rate_per_second: float = rate_per_minute / 60.0
        self.burst_capacity: float = float(burst_capacity)
        # client_ip -> (current_tokens, last_refill_timestamp)
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def is_allowed(self, client_ip: str, tokens_requested: float = 1.0) -> RateLimitDecision:
        now = time.time()
        async with self._lock:
            tokens, last_refill = self._buckets.get(
                client_ip, (self.burst_capacity, now)
            )

            # Calculate refilled tokens based on elapsed time
            elapsed = max(0.0, now - last_refill)
            tokens = min(self.burst_capacity, tokens + elapsed * self.rate_per_second)

            if tokens >= tokens_requested:
                tokens -= tokens_requested
                self._buckets[client_ip] = (tokens, now)
                return RateLimitDecision(
                    is_allowed=True,
                    remaining=tokens,
                    limit=int(self.burst_capacity),
                    reason="Token acquired",
                )
            else:
                deficit = tokens_requested - tokens
                retry_after = deficit / self.rate_per_second if self.rate_per_second > 0 else 60.0
                self._buckets[client_ip] = (tokens, now)
                return RateLimitDecision(
                    is_allowed=False,
                    retry_after=round(retry_after, 2),
                    remaining=tokens,
                    limit=int(self.burst_capacity),
                    reason=f"Rate limit exceeded (Token Bucket). Retry in {retry_after:.1f}s",
                )


# ============================================================================
# 2. Sliding Window Algorithm (Log-based Window)
# ============================================================================
class SlidingWindowLimiter:
    """Sliding Window rate limiter tracking exact request timestamps per client IP."""

    def __init__(
        self,
        limits: Optional[List[Tuple[int, int]]] = None,
    ):
        """limits: list of (window_seconds, max_requests).

        Example: [(60, 100), (3600, 1000), (86400, 10000)]
        """
        self.limits: List[Tuple[int, int]] = limits or [(60, 100)]
        # client_ip -> list of epoch timestamps
        self._logs: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()

    async def is_allowed(self, client_ip: str) -> RateLimitDecision:
        now = time.time()
        async with self._lock:
            timestamps = self._logs.get(client_ip, [])

            # Largest window determines how long to retain records
            max_window = max(window for window, _ in self.limits)
            # Evict timestamps older than largest window
            cutoff = now - max_window
            timestamps = [t for t in timestamps if t > cutoff]

            # Check every configured window threshold
            for window_sec, max_req in self.limits:
                window_cutoff = now - window_sec
                count_in_window = sum(1 for t in timestamps if t > window_cutoff)

                if count_in_window >= max_req:
                    # Calculate when the oldest request in this window will expire
                    oldest_in_window = min(t for t in timestamps if t > window_cutoff)
                    retry_after = max(0.1, (oldest_in_window + window_sec) - now)
                    self._logs[client_ip] = timestamps
                    return RateLimitDecision(
                        is_allowed=False,
                        retry_after=round(retry_after, 2),
                        current_count=count_in_window,
                        limit=max_req,
                        reason=f"Exceeded {max_req} requests per {window_sec}s window. Retry after {retry_after:.1f}s",
                    )

            # Record current request
            timestamps.append(now)
            self._logs[client_ip] = timestamps
            return RateLimitDecision(
                is_allowed=True,
                current_count=len(timestamps),
                limit=self.limits[0][1],
                reason="Within sliding window rate limit",
            )


# ============================================================================
# 3. Unified Rate Limiter
# ============================================================================
class RateLimiter:
    """Unified Rate Limiter supporting multiple algorithm backends."""

    def __init__(
        self,
        algorithm: str = "token_bucket",
        requests_per_minute: int = 100,
        requests_per_hour: int = 1000,
        requests_per_day: int = 10000,
        burst_capacity: int = 20,
    ):
        self.algorithm = algorithm.lower()
        if self.algorithm == "token_bucket":
            self._limiter = TokenBucketLimiter(
                rate_per_minute=requests_per_minute,
                burst_capacity=burst_capacity,
            )
        else:
            self._limiter = SlidingWindowLimiter(
                limits=[
                    (60, requests_per_minute),
                    (3600, requests_per_hour),
                    (86400, requests_per_day),
                ]
            )

    async def evaluate(self, client_ip: str) -> RateLimitDecision:
        return await self._limiter.is_allowed(client_ip)
