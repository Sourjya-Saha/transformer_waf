"""Unit Tests for Rate Limiters (Token Bucket and Sliding Window)."""
import asyncio
import time
import pytest
from web_firewall.filters.rate_limiter import (
    TokenBucketLimiter,
    SlidingWindowLimiter,
    RateLimiter,
)


@pytest.mark.asyncio
async def test_token_bucket_burst_and_exhaustion():
    # 60 requests per minute = 1 req/sec, burst capacity = 3
    limiter = TokenBucketLimiter(rate_per_minute=60, burst_capacity=3)
    ip = "192.168.1.1"

    # Consume 3 burst tokens
    assert (await limiter.is_allowed(ip)).is_allowed is True
    assert (await limiter.is_allowed(ip)).is_allowed is True
    assert (await limiter.is_allowed(ip)).is_allowed is True

    # 4th request immediately should fail
    d4 = await limiter.is_allowed(ip)
    assert d4.is_allowed is False
    assert d4.retry_after > 0
    assert "Rate limit exceeded" in d4.reason


@pytest.mark.asyncio
async def test_token_bucket_refill():
    # 600 requests per minute = 10 req/sec, burst capacity = 1
    limiter = TokenBucketLimiter(rate_per_minute=600, burst_capacity=1)
    ip = "192.168.1.2"

    # Consume 1 token
    assert (await limiter.is_allowed(ip)).is_allowed is True
    # Immediate next request fails
    assert (await limiter.is_allowed(ip)).is_allowed is False

    # Wait for refill (0.15s is enough for 1 token at 10 tokens/sec)
    await asyncio.sleep(0.15)

    assert (await limiter.is_allowed(ip)).is_allowed is True


@pytest.mark.asyncio
async def test_token_bucket_ip_isolation():
    limiter = TokenBucketLimiter(rate_per_minute=60, burst_capacity=1)
    ip1 = "10.0.0.1"
    ip2 = "10.0.0.2"

    assert (await limiter.is_allowed(ip1)).is_allowed is True
    assert (await limiter.is_allowed(ip1)).is_allowed is False

    # ip2 still has full capacity
    assert (await limiter.is_allowed(ip2)).is_allowed is True


@pytest.mark.asyncio
async def test_sliding_window_limiter():
    # 3 requests per 2-second window
    limiter = SlidingWindowLimiter(limits=[(2, 3)])
    ip = "192.168.1.3"

    assert (await limiter.is_allowed(ip)).is_allowed is True
    assert (await limiter.is_allowed(ip)).is_allowed is True
    assert (await limiter.is_allowed(ip)).is_allowed is True

    # 4th request in same window fails
    d4 = await limiter.is_allowed(ip)
    assert d4.is_allowed is False
    assert "Exceeded 3 requests" in d4.reason


@pytest.mark.asyncio
async def test_sliding_window_expiration():
    # 2 requests per 1-second window
    limiter = SlidingWindowLimiter(limits=[(1, 2)])
    ip = "192.168.1.4"

    assert (await limiter.is_allowed(ip)).is_allowed is True
    assert (await limiter.is_allowed(ip)).is_allowed is True
    assert (await limiter.is_allowed(ip)).is_allowed is False

    # Wait for window to slide
    await asyncio.sleep(1.05)

    assert (await limiter.is_allowed(ip)).is_allowed is True


@pytest.mark.asyncio
async def test_unified_rate_limiter():
    limiter = RateLimiter(
        algorithm="sliding_window",
        requests_per_minute=5,
    )
    ip = "1.2.3.4"

    for _ in range(5):
        assert (await limiter.evaluate(ip)).is_allowed is True

    assert (await limiter.evaluate(ip)).is_allowed is False
