import time
from collections import defaultdict, deque
from collections.abc import Callable


class SlidingWindowRateLimiter:
    """In-memory sliding window limiter.

    State lives in this process only, so limits are per instance. That is acceptable for the
    single-instance deployment in render.yaml; use a shared store if the API is scaled out.
    """

    def __init__(self, *, limit: int, window_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, int]:
        """Records a hit for `key`. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        hits = self._hits[key]
        while hits and now - hits[0] >= self.window_seconds:
            hits.popleft()
        if len(hits) >= self.limit:
            return False, max(1, int(self.window_seconds - (now - hits[0])) + 1)
        hits.append(now)
        if not hits:  # pragma: no cover - defensive, keeps the dict from growing on empty deques
            self._hits.pop(key, None)
        return True, 0
