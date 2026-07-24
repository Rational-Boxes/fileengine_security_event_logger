# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
