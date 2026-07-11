"""Event-time sliding-window counters for the rules engine.

Keyed by (rule_id, group_key). Windowing uses the *event* timestamp (not wall
clock) so evaluation is deterministic and replay-safe.
"""
from __future__ import annotations

from collections import defaultdict, deque


class SlidingWindows:
    def __init__(self):
        self._w: dict = defaultdict(deque)

    def _evict(self, dq, cutoff):
        while dq and dq[0] < cutoff:
            dq.popleft()

    def add_and_count(self, key, ts: float, window_s: int) -> int:
        dq = self._w[key]
        dq.append(ts)
        self._evict(dq, ts - window_s)
        return len(dq)

    def count(self, key, ts: float, window_s: int) -> int:
        dq = self._w.get(key)
        if not dq:
            return 0
        self._evict(dq, ts - window_s)
        return len(dq)

    def reset(self, key) -> None:
        self._w.pop(key, None)
