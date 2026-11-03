"""A small in-memory sliding-window rate limiter for the collection endpoints.

In-process memory is enough for a single API container. With several replicas this would
need a shared store (e.g. Redis), which is deliberately out of scope here.
"""

import threading
import time
from collections import deque
from collections.abc import Callable


class SlidingWindowLimiter:
    """Allow at most `limit` calls per `window` seconds for each key (e.g. client IP)."""

    def __init__(
        self, limit: int, window: float = 60.0, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._limit = limit
        self._window = window
        self._clock = clock
        self._calls: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> float | None:
        """Record a call and return None if allowed, else the seconds until it would be."""
        with self._lock:
            now = self._clock()
            calls = self._calls.setdefault(key, deque())
            while calls and calls[0] <= now - self._window:
                calls.popleft()
            if len(calls) >= self._limit:
                return calls[0] + self._window - now
            calls.append(now)
            return None
