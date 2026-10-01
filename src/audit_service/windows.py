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


class DistinctWindows:
    """Counts DISTINCT VALUES in a sliding window, not events.

    The fan-out detector (PROPOSAL_deployment_admin_signal.md §3.6). A volume
    threshold asks "how often", and an attacker can stay under it by being
    patient; this asks "how many different tenants did one source touch at all",
    and patience is no defence — probing the platform means touching many
    tenants by definition.

    Keeping only the LATEST timestamp per value is what makes it cheap and is
    also the right semantics: the question is "was this value seen inside the
    window", not "how many times". A source that hit one tenant a thousand times
    and seven others once each has a fan-out of eight, which is the number that
    matters.
    """

    def __init__(self):
        self._w: dict = defaultdict(dict)   # key -> {value: last_ts}

    def _evict(self, seen: dict, cutoff: float) -> None:
        for value in [v for v, ts in seen.items() if ts < cutoff]:
            del seen[value]

    def add_and_count(self, key, value, ts: float, window_s: int) -> int:
        seen = self._w[key]
        seen[value] = max(ts, seen.get(value, ts))
        self._evict(seen, ts - window_s)
        return len(seen)

    def count(self, key, ts: float, window_s: int) -> int:
        seen = self._w.get(key)
        if not seen:
            return 0
        self._evict(seen, ts - window_s)
        return len(seen)

    def values(self, key, ts: float, window_s: int) -> list:
        """The distinct values still inside the window, sorted.

        An incident that says "this source touched 8 tenants" without naming
        them leaves the administrator to go and find out which, which is the
        first thing they will want.
        """
        seen = self._w.get(key)
        if not seen:
            return []
        self._evict(seen, ts - window_s)
        return sorted(seen)

    def reset(self, key) -> None:
        self._w.pop(key, None)
