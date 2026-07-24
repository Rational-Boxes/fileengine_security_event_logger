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

"""Write audit rows to Postgres: on-demand daily partitions + a deduplicating,
hash-chained insert (usage_logging_and_auditing §5, §7).

The writer is the *only* thing that writes ``audit_log``, so it owns partition
creation, row ordering, AND the per-tenant tamper-evidence hash chain. Each row
gets ``prev_hash`` (the previous row's ``row_hash``) and
``row_hash = SHA-256(prev_hash ‖ canonical(row))``. The chain is deterministic, so
at-least-once re-delivery recomputes identical hashes; ``INSERT … ON CONFLICT DO
NOTHING RETURNING row_hash`` lets the writer advance the chain head correctly
whether the row was freshly inserted or was a duplicate (adopting the stored hash
in the latter case). Because each row's hash depends on the previous, inserts are
serialized per tenant (row-by-row), not batched.

The head cache (``heads``) maps a chain key → the current head ``row_hash``; it is
seeded lazily from the DB (the max-``seq`` row's hash) and owned by the caller so
it survives across batches. Partition bounds are pinned to explicit UTC.

It never commits — the caller commits then acks, so an ack means "durably in the
DB with a valid chain link".
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta, timezone

from .envelope import AuditRow
from .hashing import canonical_row, compute_row_hash
from .naming import schema_for_tenant

_BASE_COLS = (
    "event_id", "ts", "category", "action", "outcome", "actor", "actor_roles",
    "target_uid", "target_name", "target_type", "detail", "source_iface",
    "source_addr", "request_id",
)
_BASE_PLACEHOLDERS = (
    "%s::uuid", "%s", "%s", "%s", "%s", "%s", "%s",
    "%s", "%s", "%s", "%s::jsonb", "%s", "%s", "%s",
)
GLOBAL_KEY = "__global__"


def _parent_table(row: AuditRow) -> str:
    if row.scope == "global":
        return "audit_log_global"
    return f'"{schema_for_tenant(row.tenant or "")}".audit_log'


def _partition_of(parent: str, day: date) -> str:
    return f"{parent}_p{day.strftime('%Y%m%d')}"


def _chain_key(row: AuditRow) -> str:
    return GLOBAL_KEY if row.scope == "global" else (row.tenant or "")


def _ensure_partition(cur, parent: str, day: date) -> None:
    start = f"{day.isoformat()} 00:00:00+00"
    end = f"{(day + timedelta(days=1)).isoformat()} 00:00:00+00"
    cur.execute(
        f"CREATE TABLE IF NOT EXISTS {_partition_of(parent, day)} "
        f"PARTITION OF {parent} FOR VALUES FROM ('{start}') TO ('{end}')"
    )


def _seed_head(cur, heads: dict, key: str, parent: str) -> bytes | None:
    if key in heads:
        return heads[key]
    cur.execute(f"SELECT row_hash FROM {parent} ORDER BY seq DESC LIMIT 1")
    r = cur.fetchone()
    head = bytes(r[0]) if r and r[0] is not None else None
    heads[key] = head
    return head


def _base_values(row: AuditRow) -> list:
    return [row.event_id, row.ts, row.category, row.action, row.outcome, row.actor,
            row.actor_roles, row.target_uid, row.target_name, row.target_type,
            row.detail, row.source_iface, row.source_addr, row.request_id]


def write_batch(conn, rows: list[AuditRow], heads: dict) -> int:
    """Insert ``rows`` (possibly spanning many tenants + global) in one
    transaction on ``conn``, chaining each per its tenant's head. ``heads`` is the
    caller-owned per-chain head cache (mutated). Does NOT commit.
    """
    if not rows:
        return 0

    partitions: set[tuple[str, date]] = set()
    for row in rows:
        partitions.add((_parent_table(row), row.ts.astimezone(timezone.utc).date()))

    with conn.cursor() as cur:
        for parent, day in sorted(partitions):
            _ensure_partition(cur, parent, day)

        # Row-by-row in stream order — the chain forbids reordering within a tenant.
        for row in rows:
            parent = _parent_table(row)
            include_tenant = row.scope == "global"
            key = _chain_key(row)
            head = _seed_head(cur, heads, key, parent)

            canon = canonical_row(
                event_id=row.event_id, ts=row.ts, category=row.category, action=row.action,
                outcome=row.outcome, actor=row.actor, actor_roles=row.actor_roles,
                target_uid=row.target_uid, target_name=row.target_name,
                target_type=row.target_type, detail=row.detail, source_iface=row.source_iface,
                source_addr=row.source_addr, request_id=row.request_id,
                tenant=(row.tenant if include_tenant else None))
            row_hash = compute_row_hash(head, canon)

            cols = _BASE_COLS + ("prev_hash", "row_hash") + (("tenant",) if include_tenant else ())
            ph = _BASE_PLACEHOLDERS + ("%s", "%s") + (("%s",) if include_tenant else ())
            vals = _base_values(row) + [head, row_hash] + ([row.tenant] if include_tenant else [])
            cur.execute(
                f"INSERT INTO {parent} ({', '.join(cols)}) VALUES ({', '.join(ph)}) "
                f"ON CONFLICT (event_id, ts) DO NOTHING RETURNING row_hash", vals)
            res = cur.fetchone()
            if res is not None:
                heads[key] = bytes(res[0])          # freshly inserted → our hash is the head
            else:
                # Duplicate (re-delivery): adopt the already-stored hash as the head.
                cur.execute(f"SELECT row_hash FROM {parent} WHERE event_id = %s::uuid AND ts = %s",
                            (row.event_id, row.ts))
                stored = cur.fetchone()
                if stored and stored[0] is not None:
                    heads[key] = bytes(stored[0])

    return len(rows)
