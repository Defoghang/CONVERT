import asyncio
import time
from telegram.ext import BaseRateLimiter


class SimpleRateLimiter(BaseRateLimiter):
    def __init__(self, per_second=25.0, per_chat_per_second=0.8):
        self.per_second = per_second
        self.per_chat_per_second = per_chat_per_second
        self._global_tokens = per_second
        self._global_last = time.monotonic()
        self._chat_last = {}
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        return

    async def shutdown(self) -> None:
        return

    async def process_request(self, callback, args, kwargs, endpoint, data, rate_limit_args):
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._global_last
            self._global_tokens = min(
                self.per_second,
                self._global_tokens + elapsed * self.per_second,
            )
            self._global_last = now
            if self._global_tokens < 1:
                wait = (1 - self._global_tokens) / self.per_second
                await asyncio.sleep(wait)
                self._global_tokens = 0
            else:
                self._global_tokens -= 1

            chat_id = None
            if isinstance(data, dict):
                chat_id = data.get("chat_id")
            if chat_id is None and len(args) > 0:
                first = args[0]
                chat_id = getattr(first, "chat_id", None) or getattr(
                    getattr(first, "chat", None), "id", None
                )
            if chat_id is None and isinstance(kwargs, dict):
                chat_id = kwargs.get("chat_id")

            if chat_id is not None:
                last = self._chat_last.get(chat_id, 0.0)
                interval = 1.0 / self.per_chat_per_second
                delta = time.monotonic() - last
                if delta < interval:
                    await asyncio.sleep(interval - delta)
                self._chat_last[chat_id] = time.monotonic()

        return await callback(*args, **kwargs)
