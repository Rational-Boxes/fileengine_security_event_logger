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

"""Per-tenant ``recorded_until`` cursors for the accountability pull (§4.3).

One row per chain, holding the watermark this service has durably appended. The
cursor is staged in the SAME transaction as the audit rows it corresponds to and
committed with them, so the pair can never disagree: a crash either loses both
(and the next drain re-reads those records, which the ``(event_id, ts)``
idempotency key absorbs) or keeps both.

The watermark is the ``ts`` of the last record appended, not a seq. See puller.py
for why: the precedence rule compares core records against events from subsystems
that have no seq, and time is the only axis they share.

``last_seq`` and ``last_hash`` ride along so the next batch can be checked for
contiguity and chain linkage without re-reading what we already recorded.
"""
from __future__ import annotations

from dataclasses import dataclass

DDL = """
CREATE TABLE IF NOT EXISTS accountability_cursor (
    tenant           VARCHAR(255) PRIMARY KEY,
    recorded_until   BIGINT      NOT NULL DEFAULT 0,   -- epoch microseconds
    last_seq         BIGINT      NOT NULL DEFAULT 0,
    last_hash        BYTEA,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


@dataclass
class CursorState:
    tenant: str
    recorded_until_micros: int = 0
    last_seq: int = 0
    last_hash: bytes | None = None

    def advance(self, seq: int, ts_micros: int, row_hash: bytes) -> None:
        self.last_seq = seq
        self.recorded_until_micros = ts_micros
        self.last_hash = row_hash


class CursorStore:
    """Reads and stages cursors. Never commits — the caller owns the transaction."""

    def ensure_schema(self, conn) -> None:
        with conn.cursor() as cur:
            cur.execute(DDL)

    def get(self, conn, tenant: str) -> CursorState:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT recorded_until, last_seq, last_hash "
                "FROM accountability_cursor WHERE tenant = %s", (tenant,))
            row = cur.fetchone()
        if row is None:
            # A fresh chain starts at zero, which replays the tenant's whole
            # history. That is the intended behaviour, not a fallback: resetting
            # a cursor is how this service is rebuilt from nothing.
            return CursorState(tenant=tenant)
        return CursorState(tenant=tenant,
                           recorded_until_micros=int(row[0]),
                           last_seq=int(row[1]),
                           last_hash=bytes(row[2]) if row[2] is not None else None)

    def stage(self, conn, tenant: str, state: CursorState) -> None:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO accountability_cursor "
                "  (tenant, recorded_until, last_seq, last_hash, updated_at) "
                "VALUES (%s, %s, %s, %s, now()) "
                "ON CONFLICT (tenant) DO UPDATE SET "
                "  recorded_until = EXCLUDED.recorded_until, "
                "  last_seq = EXCLUDED.last_seq, "
                "  last_hash = EXCLUDED.last_hash, "
                "  updated_at = now()",
                (tenant, state.recorded_until_micros, state.last_seq, state.last_hash))

    def reset(self, conn, tenant: str) -> None:
        """Rewind a chain to zero so the next drain replays it from the start."""
        with conn.cursor() as cur:
            cur.execute("DELETE FROM accountability_cursor WHERE tenant = %s", (tenant,))
