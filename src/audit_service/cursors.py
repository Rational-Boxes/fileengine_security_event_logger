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
    -- updated_at moves only when records are APPENDED; last_polled_at moves on
    -- every successful pass, including one that found nothing. The two answer
    -- different questions and conflating them was a bug: a tenant that is simply
    -- quiet has an ancient updated_at, which is indistinguishable from a drain
    -- that has stopped — so staleness measured on updated_at goes red for every
    -- idle tenant, and an alarm that is always on is an alarm nobody reads.
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_polled_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- The integrity halt. §4.3.2 requires that a break stops the cursor,
    -- alarms, and REQUIRES OPERATOR ACKNOWLEDGEMENT — which means it has to
    -- outlive the process that detected it. An alarm cleared by a restart is
    -- not an alarm; it is a service that quietly resumes draining past a gap it
    -- already decided was a missing record.
    halted_at        TIMESTAMPTZ,
    halted_seq       BIGINT,
    halted_reason    TEXT
);
"""

MIGRATIONS = (
    "ALTER TABLE accountability_cursor ADD COLUMN IF NOT EXISTS halted_at TIMESTAMPTZ",
    "ALTER TABLE accountability_cursor ADD COLUMN IF NOT EXISTS halted_seq BIGINT",
    "ALTER TABLE accountability_cursor ADD COLUMN IF NOT EXISTS halted_reason TEXT",
    "ALTER TABLE accountability_cursor "
    "ADD COLUMN IF NOT EXISTS last_polled_at TIMESTAMPTZ NOT NULL DEFAULT now()",
)


@dataclass
class CursorState:
    tenant: str
    recorded_until_micros: int = 0
    last_seq: int = 0
    last_hash: bytes | None = None
    halted_reason: str | None = None
    halted_seq: int | None = None

    @property
    def halted(self) -> bool:
        return self.halted_reason is not None

    def advance(self, seq: int, ts_micros: int, row_hash: bytes) -> None:
        self.last_seq = seq
        self.recorded_until_micros = ts_micros
        self.last_hash = row_hash


class CursorStore:
    """Reads and stages cursors. Never commits — the caller owns the transaction."""

    def ensure_schema(self, conn) -> None:
        with conn.cursor() as cur:
            cur.execute(DDL)
            # Idempotent, for a cursor table provisioned before the halt columns.
            for statement in MIGRATIONS:
                cur.execute(statement)

    def get(self, conn, tenant: str) -> CursorState:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT recorded_until, last_seq, last_hash, halted_reason, halted_seq "
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
                           last_hash=bytes(row[2]) if row[2] is not None else None,
                           halted_reason=row[3],
                           halted_seq=int(row[4]) if row[4] is not None else None)

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

    def touch_polled(self, conn, tenant: str) -> None:
        """Record that this chain was successfully polled, records or not.

        Called on every clean pass. A pass that RAISED must not reach here — an
        erroring drain is not a healthy drain, and letting it touch the
        heartbeat would hide exactly the condition the heartbeat exists to show.
        """
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO accountability_cursor (tenant, last_polled_at) "
                "VALUES (%s, now()) "
                "ON CONFLICT (tenant) DO UPDATE SET last_polled_at = now()",
                (tenant,))

    def reset(self, conn, tenant: str) -> None:
        """Rewind a chain to zero so the next drain replays it from the start.

        Also clears any halt, because a full replay re-verifies the chain from
        the beginning — if the break is still there it will be found again on the
        way past, and if it is not, the halt was about state that no longer
        exists.
        """
        with conn.cursor() as cur:
            cur.execute("DELETE FROM accountability_cursor WHERE tenant = %s", (tenant,))

    def halt(self, conn, tenant: str, seq: int | None, reason: str) -> None:
        """Record an integrity halt. Idempotent — the FIRST break is kept.

        Keeping the first matters: once a chain is broken every later row fails
        too, so overwriting would replace the diagnosis with a symptom, and the
        seq an operator needs to look at is the earliest one.
        """
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO accountability_cursor (tenant, halted_at, halted_seq, halted_reason) "
                "VALUES (%s, now(), %s, %s) "
                "ON CONFLICT (tenant) DO UPDATE SET "
                "  halted_at = COALESCE(accountability_cursor.halted_at, now()), "
                "  halted_seq = COALESCE(accountability_cursor.halted_seq, EXCLUDED.halted_seq), "
                "  halted_reason = COALESCE(accountability_cursor.halted_reason, EXCLUDED.halted_reason)",
                (tenant, seq, reason))

    def acknowledge(self, conn, tenant: str) -> bool:
        """Clear a halt after an operator has looked at it. Returns whether one
        was cleared.

        Deliberately a separate, explicit act rather than anything automatic:
        the point of the halt is that a human decides whether the chain is
        trustworthy again. Draining resumes from the cursor, which never moved.
        """
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE accountability_cursor "
                "SET halted_at = NULL, halted_seq = NULL, halted_reason = NULL "
                "WHERE tenant = %s AND halted_reason IS NOT NULL", (tenant,))
            return cur.rowcount > 0

    def halted(self, conn) -> list:
        """Every chain currently halted, as ``(tenant, halted_at, seq, reason)``."""
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tenant, halted_at, halted_seq, halted_reason "
                "FROM accountability_cursor WHERE halted_reason IS NOT NULL "
                "ORDER BY halted_at")
            return cur.fetchall()
