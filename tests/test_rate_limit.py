from backend.app.rate_limit import RateLimiter


class FakeClient:
    host = "127.0.0.1"


class FakeRequest:
    def __init__(self) -> None:
        self.client = FakeClient()
        self.headers = {}


def test_rate_limiter_allows_within_limit():
    limiter = RateLimiter(window_seconds=60, limit_per_minute=5)
    request = FakeRequest()

    for _ in range(3):
        limiter.check(request)


def test_rate_limiter_blocks_after_limit(monkeypatch):
    limiter = RateLimiter(window_seconds=60, limit_per_minute=2)
    request = FakeRequest()

    limiter.check(request)
    limiter.check(request)

    try:
        limiter.check(request)
    except Exception as exc:
        assert "Rate limit exceeded" in str(exc)
    else:
        raise AssertionError("Expected rate limit exception")
