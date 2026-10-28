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

"""One chain walk, shared by the database verifier, the archiver and the
archive verifier.

Three places check the same two properties — linkage (``prev_hash`` is the
previous row's ``row_hash``) and integrity (``row_hash`` recomputes from the
content) — over rows that arrive in three shapes: a database record, a dict
about to be archived, and a dict read back out of an archive. Keeping one walker
and one row codec means an archived row is verified by exactly the rule that
verified it in Postgres, so the DB→archive boundary cannot quietly change what
"intact" means.
"""
from __future__ import annotations

from datetime import datetime

from .hashing import canonical_json, canonical_row, compute_row_hash

# Every column, in archive order. `recorded_at` is not hashed but is part of the
# record; `tenant` exists (and IS hashed) only on the global chain.
ROW_COLS = ("seq", "event_id", "ts", "recorded_at", "category", "action", "outcome",
            "actor", "actor_roles", "target_uid", "target_name", "target_type",
            "detail", "source_iface", "source_addr", "request_id", "prev_hash", "row_hash")


def select_cols(include_tenant: bool) -> str:
    cols = list(ROW_COLS)
    if include_tenant:
        cols.insert(cols.index("prev_hash"), "tenant")
    return ", ".join(cols)


def record_to_dict(rec, include_tenant: bool) -> dict:
    """A database record (selected with ``select_cols``) → the archived JSON row."""
    names = select_cols(include_tenant).split(", ")
    row = dict(zip(names, rec))
    row["event_id"] = str(row["event_id"])
    row["ts"] = row["ts"].isoformat()
    row["recorded_at"] = row["recorded_at"].isoformat() if row["recorded_at"] else None
    for k in ("prev_hash", "row_hash"):
        row[k] = bytes(row[k]).hex() if row[k] is not None else None
    return row


def _hash(v: str | None) -> bytes | None:
    return bytes.fromhex(v) if v is not None else None


def canonical_of(row: dict, include_tenant: bool) -> bytes:
    detail = row.get("detail")
    return canonical_row(
        event_id=row["event_id"], ts=datetime.fromisoformat(row["ts"]),
        category=row["category"], action=row["action"], outcome=row["outcome"],
        actor=row["actor"], actor_roles=row["actor_roles"], target_uid=row["target_uid"],
        target_name=row["target_name"], target_type=row["target_type"],
        detail=(canonical_json(detail) if detail is not None else None),
        source_iface=row["source_iface"], source_addr=row["source_addr"],
        request_id=row["request_id"], tenant=(row.get("tenant") if include_tenant else None))


class ChainWalker:
    """Walk rows in ``seq`` order from a starting link.

    ``start_hash`` is the anchor's ``last_row_hash`` (None for a chain whose
    first row is still present); ``after_seq`` is the anchor's ``last_seq`` — a
    row at or below it should not exist on this side of the boundary.
    """

    def __init__(self, start_hash: bytes | None = None, after_seq: int | None = None):
        self.prev = start_hash
        self.after_seq = after_seq
        self.last_seq = after_seq
        self.checked = 0
        self.broken_seq: int | None = None
        self.reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.broken_seq is None

    def step(self, *, seq: int, prev_hash: bytes | None, row_hash: bytes | None,
             canonical: bytes) -> bool:
        """Check one row; returns False (and records the first break) on failure.
        Keeps walking after a break so the caller can still archive faithfully,
        but only the FIRST break is reported."""
        reason = None
        if self.last_seq is not None and seq <= self.last_seq:
            reason = ("row predates the archive anchor" if seq <= (self.after_seq or -1)
                      else "seq is not ascending")
        elif prev_hash != self.prev:
            reason = "prev_hash does not match the previous row's row_hash"
        elif row_hash != compute_row_hash(prev_hash, canonical):
            reason = "row_hash does not match the recomputed hash"
        if reason and self.broken_seq is None:
            self.broken_seq, self.reason = seq, reason
        self.prev = row_hash
        self.last_seq = seq
        if not reason:
            self.checked += 1
        return reason is None

    def step_dict(self, row: dict, include_tenant: bool) -> bool:
        return self.step(seq=row["seq"], prev_hash=_hash(row["prev_hash"]),
                         row_hash=_hash(row["row_hash"]),
                         canonical=canonical_of(row, include_tenant))
