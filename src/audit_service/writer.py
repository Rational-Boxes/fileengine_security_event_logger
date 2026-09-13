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

The writer owns partition creation, row ordering, AND the per-tenant
tamper-evidence hash chain. It is not the only PROCESS doing so: the queue
consumer and the accountability poller both call it, from separate connections,
and in production from separate containers. Everything here that touches shared
state therefore takes a transaction-scoped advisory lock first — the partition
table (``_ensure_partition``) and the chain head (``_lock_chain``). Each row
gets ``prev_hash`` (the previous row's ``row_hash``) and
``row_hash = SHA-256(prev_hash ‖ canonical(row))``. The chain is deterministic, so
at-least-once re-delivery recomputes identical hashes; ``INSERT … ON CONFLICT DO
NOTHING RETURNING row_hash`` lets the writer advance the chain head correctly
whether the row was freshly inserted or was a duplicate (adopting the stored hash
in the latter case). Because each row's hash depends on the previous, inserts are
serialized per tenant (row-by-row), not batched.

The head cache (``heads``) maps a chain key → the current head ``row_hash``. It is
re-seeded from the DB at the start of every batch, under the chain lock, and is
scratch space for the row loop rather than a cache that survives across batches.
It used to survive, and that was the defect: a second writer appending between
two of this one's batches left the cached head pointing at a row that was no
longer the tail, so the next row chained onto the wrong predecessor and every row
after it was orphaned. Partition bounds are pinned to explicit UTC.

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
# Namespaced so a chain lock can never collide with a partition lock,
# which is keyed on the bare partition table name.
_CHAIN_LOCK_PREFIX = "audit_chain:"


def _parent_table(row: AuditRow) -> str:
    if row.scope == "global":
        return "audit_log_global"
    return f'"{schema_for_tenant(row.tenant or "")}".audit_log'


def _partition_of(parent: str, day: date) -> str:
    return f"{parent}_p{day.strftime('%Y%m%d')}"


def _chain_key(row: AuditRow) -> str:
    return GLOBAL_KEY if row.scope == "global" else (row.tenant or "")


def _ensure_partition(cur, parent: str, day: date) -> None:
    """Create the day's partition if it is missing, safely under concurrency.

    ``CREATE TABLE IF NOT EXISTS`` is idempotent but **not concurrency-safe**:
    two transactions can both find the table missing, both issue the CREATE, and
    the loser fails with DuplicateTable — which aborts its whole batch, not just
    the CREATE.

    That used to be impossible here because the audit writer was the single
    process that wrote these tables. It stopped being true when the
    accountability poller became a second writer, and the symptom was an
    intermittent "relation audit_log_pYYYYMMDD already exists" that rolled back a
    drain for a reason that had nothing to do with the drain.

    The advisory lock is transaction-scoped, so it releases on commit or
    rollback with no cleanup path to get wrong. Keying it on the PARTITION name
    rather than the parent keeps two tenants from serializing against each
    other, and callers take partitions in sorted order, so two processes acquire
    overlapping locks in the same sequence and cannot deadlock.
    """
    partition = _partition_of(parent, day)
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (partition,))
    start = f"{day.isoformat()} 00:00:00+00"
    end = f"{(day + timedelta(days=1)).isoformat()} 00:00:00+00"
    cur.execute(
        f"CREATE TABLE IF NOT EXISTS {partition} "
        f"PARTITION OF {parent} FOR VALUES FROM ('{start}') TO ('{end}')"
    )


def _lock_chain(cur, key: str) -> None:
    """Serialize appends to one chain, for the rest of this transaction.

    Reading the tail and appending to it is a read-modify-write on shared state,
    and the chain is only tamper-EVIDENT if the link is right — a wrong link is
    indistinguishable from a deletion when the log is later verified. Two writers
    that both read the same tail therefore both append to it, and the second one
    to commit is orphaned: permanent, silent, and detected only by a verification
    run long afterwards.

    That is not hypothetical. It is what this deployment does: the queue consumer
    and the accountability poller are separate containers writing the same
    per-tenant chain. MEASURED on the running system before this lock existed —
    every chain broken, always on linkage and never on integrity, first break at
    seq 8 of a six-minute-old tenant, with `acl.grant` (accountability) and
    `acl_grant` (queue) landing milliseconds apart and chaining onto the same
    predecessor.

    The lock is transaction-scoped: it releases on commit or rollback, with no
    cleanup path to get wrong, and it is held across the head read AND the
    inserts that depend on it. Keyed per chain so tenants never serialize against
    each other, and taken in sorted order AFTER the partition locks, so every
    caller acquires overlapping locks in the same sequence and cannot deadlock.
    """
    cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (_CHAIN_LOCK_PREFIX + key,))


def _seed_head(cur, heads: dict, key: str, parent: str) -> bytes | None:
    """Read the chain's tail from the DB. Call only while holding its lock.

    Deliberately NOT cache-first. The cached value is only knowable to be current
    while this transaction holds the chain lock, and it is re-read here under
    exactly that condition; trusting it across batches is what orphaned rows
    before. Within a transaction the re-read is free of surprises because it also
    sees this transaction's own uncommitted rows.
    """
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

        # Lock every chain this batch touches, then read each tail, BEFORE
        # appending anything. Both in sorted order and after the partition locks,
        # so all callers acquire overlapping locks in one consistent sequence.
        #
        # Up front rather than lazily per row: a lock taken mid-loop would leave
        # rows already appended to a chain this transaction had not yet claimed,
        # and the head those rows chained onto could have moved under us.
        chain_parents = {}
        for row in rows:
            chain_parents.setdefault(_chain_key(row), _parent_table(row))
        for key in sorted(chain_parents):
            _lock_chain(cur, key)
            _seed_head(cur, heads, key, chain_parents[key])

        # Row-by-row in stream order — the chain forbids reordering within a tenant.
        for row in rows:
            parent = _parent_table(row)
            include_tenant = row.scope == "global"
            key = _chain_key(row)
            head = heads[key]

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
