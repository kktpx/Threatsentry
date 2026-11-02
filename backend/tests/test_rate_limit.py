from fastapi.testclient import TestClient

from backend.core.config import Settings
from backend.core.rate_limit import SlidingWindowRateLimiter
from backend.main import create_app


def test_limiter_blocks_then_recovers_after_window() -> None:
    now = [0.0]
    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=10, clock=lambda: now[0])

    assert limiter.check("a") == (True, 0)
    assert limiter.check("a") == (True, 0)
    allowed, retry_after = limiter.check("a")
    assert not allowed and retry_after >= 1
    assert limiter.check("b") == (True, 0)  # keys are independent

    now[0] = 10.0
    assert limiter.check("a") == (True, 0)


def test_api_requests_are_limited_per_ip_but_health_is_not() -> None:
    client = TestClient(create_app(Settings(_env_file=None, RATE_LIMIT_IP_PER_MINUTE=3)))

    statuses = [client.get("/api/model").status_code for _ in range(5)]
    assert statuses[:3] != [429, 429, 429]
    assert statuses[-1] == 429
    limited = client.get("/api/model")
    assert limited.headers["retry-after"]

    assert client.get("/health").status_code == 200
