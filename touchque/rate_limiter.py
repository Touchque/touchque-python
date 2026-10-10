"""
A small in-memory fixed-window rate limiter for the relay handler's pre-auth
routes. It protects your own server (and your TouchQue quota) from scripted
abuse of routes anyone on the internet can call. It is per process: behind
several workers or instances each keeps its own counters, which still caps
abuse per process. Put your own shared limiter in front of the relay if you
need one global budget, and pass ``rate_limit=False``.
"""
import math
import threading
import time
from typing import Dict, List, Optional

MAX_KEYS = 50000


class FixedWindowLimiter:
    """Fixed-window counter keyed by an arbitrary string.

    ``window_ms``: window length in milliseconds (default 60000).
    ``per_ip``: requests per client IP per route per window (default 20).
    ``per_user``: requests per username per route per window (default 5).
    """

    def __init__(self, window_ms: Optional[int] = None, per_ip: Optional[int] = None,
                 per_user: Optional[int] = None):
        self.window_ms = 60000 if window_ms is None else window_ms
        self.per_ip = 20 if per_ip is None else per_ip
        self.per_user = 5 if per_user is None else per_user
        # key -> [count, reset_at_ms]; dicts keep insertion order, like a JS Map.
        self._entries = {}  # type: Dict[str, List[float]]
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, now: Optional[float] = None) -> int:
        """Counts one hit. Returns seconds to wait when over ``limit``, otherwise 0."""
        if now is None:
            now = time.time() * 1000
        with self._lock:
            e = self._entries.get(key)
            if e is None or e[1] <= now:
                if e is None and len(self._entries) >= MAX_KEYS:
                    self._prune(now)
                e = [0, now + self.window_ms]
                self._entries[key] = e
            e[0] += 1
            if e[0] > limit:
                return max(1, int(math.ceil((e[1] - now) / 1000.0)))
            return 0

    def _prune(self, now: float) -> None:
        for k in [k for k, v in self._entries.items() if v[1] <= now]:
            del self._entries[k]
        # Still full (a flood of distinct keys): drop the oldest half rather than grow without bound.
        if len(self._entries) >= MAX_KEYS:
            for k in list(self._entries.keys())[:MAX_KEYS // 2 + 1]:
                del self._entries[k]
