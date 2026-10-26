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

"""The archive catalog: where each scope's chain continues from, and every
archived object's key (SPEC_retention_and_archival.md §9).

It is load-bearing three ways. It holds the ANCHOR, without which the first row
left in Postgres looks like a tampered chain. It is the index ``audit-archive``
reads in ``seq`` order. And it is what the backup's restore manifest lists
alongside the ``versions`` keys — a restore copies only the keys the databases
reference, so an archive the catalog did not name would be silently left behind.

It lives in ``public`` so a decommissioned tenant's archive stays reachable after
its schema is dropped.
"""
from __future__ import annotations

from dataclasses import dataclass

SEGMENTS = "public.audit_archive_segments"
PARTS = "public.audit_archive_parts"

_DDL = f"""
CREATE TABLE IF NOT EXISTS {SEGMENTS} (
    segment_id      BIGSERIAL PRIMARY KEY,
    scope           TEXT        NOT NULL,
    scope_table     TEXT        NOT NULL,
    run_id          TEXT        NOT NULL,
    manifest_key    TEXT        NOT NULL UNIQUE,
    cutoff          DATE        NOT NULL,
    row_count       BIGINT      NOT NULL,
    first_seq       BIGINT      NOT NULL,
    last_seq        BIGINT      NOT NULL,
    first_prev_hash BYTEA,
    last_row_hash   BYTEA,
    min_ts          TIMESTAMPTZ,
    max_ts          TIMESTAMPTZ,
    partitions      TEXT[]      NOT NULL,
    chain_ok        BOOLEAN     NOT NULL,
    archived_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_archive_segments_scope ON {SEGMENTS} (scope_table, last_seq);
CREATE TABLE IF NOT EXISTS {PARTS} (
    segment_id  BIGINT      NOT NULL REFERENCES {SEGMENTS} (segment_id),
    part_no     INT         NOT NULL,
    object_key  TEXT        NOT NULL UNIQUE,
    row_count   INT         NOT NULL,
    first_seq   BIGINT      NOT NULL,
    last_seq    BIGINT      NOT NULL,
    min_ts      TIMESTAMPTZ NOT NULL,
    max_ts      TIMESTAMPTZ NOT NULL,
    sha256      BYTEA       NOT NULL,
    PRIMARY KEY (segment_id, part_no)
);
"""


def ensure_tables(conn) -> None:
    """Create the catalog if missing, and commit.

    ``CREATE TABLE IF NOT EXISTS`` is idempotent but NOT concurrency-safe: two
    runs racing would both find it missing and the loser would fail its whole
    transaction. The advisory lock serializes them.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext('audit_archive_catalog'))")
        cur.execute(_DDL)
    conn.commit()


def exists(conn) -> bool:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (SEGMENTS,))
        return cur.fetchone()[0] is not None


@dataclass
class Anchor:
    last_seq: int
    last_row_hash: bytes | None
    segment_id: int


def anchor(conn, scope_table: str) -> Anchor | None:
    """The newest archived link of a chain, or None if nothing was archived.

    Reads within the caller's transaction. A missing catalog means nothing was
    ever archived, which is the same answer — so a verifier on a deployment that
    has never run retention needs no table to exist."""
    if not exists(conn):
        return None
    with conn.cursor() as cur:
        cur.execute(f"SELECT last_seq, last_row_hash, segment_id FROM {SEGMENTS} "
                    "WHERE scope_table = %s ORDER BY last_seq DESC LIMIT 1", (scope_table,))
        rec = cur.fetchone()
    if rec is None:
        return None
    return Anchor(rec[0], bytes(rec[1]) if rec[1] is not None else None, rec[2])


def record_segment(cur, seg: dict, parts: list[dict]) -> int:
    cur.execute(
        f"INSERT INTO {SEGMENTS} (scope, scope_table, run_id, manifest_key, cutoff, "
        "row_count, first_seq, last_seq, first_prev_hash, last_row_hash, min_ts, max_ts, "
        "partitions, chain_ok) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
        "RETURNING segment_id",
        (seg["scope"], seg["scope_table"], seg["run_id"], seg["manifest_key"], seg["cutoff"],
         seg["row_count"], seg["first_seq"], seg["last_seq"], seg["first_prev_hash"],
         seg["last_row_hash"], seg["min_ts"], seg["max_ts"], seg["partitions"],
         seg["chain_ok"]))
    segment_id = cur.fetchone()[0]
    cur.executemany(
        f"INSERT INTO {PARTS} (segment_id, part_no, object_key, row_count, first_seq, "
        "last_seq, min_ts, max_ts, sha256) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
        [(segment_id, p["part_no"], p["object_key"], p["row_count"], p["first_seq"],
          p["last_seq"], p["min_ts"], p["max_ts"], p["sha256"]) for p in parts])
    return segment_id


def parts_in_order(conn, scope_table: str, *, ts_from=None, ts_to=None):
    """Every archived part of a chain in ``seq`` order (optionally only those
    whose ts range overlaps [ts_from, ts_to)), with its segment's link data."""
    if not exists(conn):
        return []
    where, args = ["s.scope_table = %s"], [scope_table]
    if ts_from is not None:
        where.append("p.max_ts >= %s")
        args.append(ts_from)
    if ts_to is not None:
        where.append("p.min_ts < %s")
        args.append(ts_to)
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT s.segment_id, s.run_id, s.manifest_key, s.first_prev_hash, "
            f"p.part_no, p.object_key, p.row_count, p.first_seq, p.last_seq, p.sha256 "
            f"FROM {PARTS} p JOIN {SEGMENTS} s USING (segment_id) "
            f"WHERE {' AND '.join(where)} ORDER BY p.first_seq", args)
        return cur.fetchall()
