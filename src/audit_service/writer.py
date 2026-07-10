"""Write audit rows to Postgres: on-demand daily partitions + deduplicating
batch insert.

The writer is the *only* thing that writes ``audit_log`` (§5), so it owns
partition creation and row ordering. It never commits — the caller (the
consumer) commits and only then acks, so an ack always means "durably in the DB"
and a crash between commit and ack re-delivers safely (the ``(event_id, ts)``
unique key makes the re-insert a no-op).

Partition bounds are pinned to explicit UTC (``… 00:00:00+00``) and the day is
computed from the row's UTC timestamp, so daily partitions line up with UTC days
regardless of the connection's session TimeZone. Bounds are date-derived, never
user input, so inlining them as literals (required — DDL can't bind params) is
safe.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, timedelta, timezone

from .envelope import AuditRow
from .naming import schema_for_tenant

_BASE_COLS = (
    "event_id", "ts", "category", "action", "outcome", "actor", "actor_roles",
    "target_uid", "target_name", "target_type", "detail", "source_iface",
    "source_addr", "request_id",
)
# Placeholder i pairs with column i; event_id -> uuid cast, detail -> jsonb cast.
_BASE_PLACEHOLDERS = (
    "%s::uuid", "%s", "%s", "%s", "%s", "%s", "%s",
    "%s", "%s", "%s", "%s::jsonb", "%s", "%s", "%s",
)


def _parent_table(row: AuditRow) -> str:
    """Qualified parent table for this row's scope (partitions hang off it)."""
    if row.scope == "global":
        return "audit_log_global"
    return f'"{schema_for_tenant(row.tenant or "")}".audit_log'


def _partition_of(parent: str, day: date) -> str:
    # `"<schema>".audit_log` + `_p20260710` -> `"<schema>".audit_log_p20260710`;
    # `audit_log_global` + `_p20260710` -> `audit_log_global_p20260710`.
    return f"{parent}_p{day.strftime('%Y%m%d')}"


def _row_values(row: AuditRow, *, include_tenant: bool) -> tuple:
    vals = (
        row.event_id, row.ts, row.category, row.action, row.outcome, row.actor,
        row.actor_roles, row.target_uid, row.target_name, row.target_type,
        row.detail, row.source_iface, row.source_addr, row.request_id,
    )
    return vals + (row.tenant,) if include_tenant else vals


def _ensure_partition(cur, parent: str, day: date) -> None:
    start = f"{day.isoformat()} 00:00:00+00"
    end = f"{(day + timedelta(days=1)).isoformat()} 00:00:00+00"
    cur.execute(
        f"CREATE TABLE IF NOT EXISTS {_partition_of(parent, day)} "
        f"PARTITION OF {parent} FOR VALUES FROM ('{start}') TO ('{end}')"
    )


def write_batch(conn, rows: list[AuditRow]) -> int:
    """Insert ``rows`` (possibly spanning many tenants + global) in one
    transaction on ``conn``. Ensures every needed daily partition exists first.
    Returns the number of rows attempted. Does NOT commit — the caller owns
    commit/ack.
    """
    if not rows:
        return 0

    by_parent: dict[tuple[str, bool], list[AuditRow]] = defaultdict(list)
    partitions: set[tuple[str, date]] = set()
    for row in rows:
        parent = _parent_table(row)
        by_parent[(parent, row.scope == "global")].append(row)
        partitions.add((parent, row.ts.astimezone(timezone.utc).date()))

    with conn.cursor() as cur:
        for parent, day in sorted(partitions):
            _ensure_partition(cur, parent, day)

        for (parent, include_tenant), group in by_parent.items():
            cols = _BASE_COLS + (("tenant",) if include_tenant else ())
            placeholders = _BASE_PLACEHOLDERS + (("%s",) if include_tenant else ())
            sql = (
                f"INSERT INTO {parent} ({', '.join(cols)}) "
                f"VALUES ({', '.join(placeholders)}) "
                f"ON CONFLICT (event_id, ts) DO NOTHING"
            )
            cur.executemany(sql, [_row_values(r, include_tenant=include_tenant) for r in group])

    return len(rows)
