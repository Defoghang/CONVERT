import pytest
from rate_limiter import SimpleRateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_passes_through():
    limiter = SimpleRateLimiter(per_second=100.0, per_chat_per_second=100.0)
    calls = []

    async def fake_callback(*args, **kwargs):
        calls.append((args, kwargs))
        return "ok"

    result = await limiter.process_request(fake_callback, (), {})
    assert result == "ok"
    assert len(calls) == 1
