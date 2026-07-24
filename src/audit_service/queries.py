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

"""Filtered/paginated audit-log queries + NDJSON export (§9).

Reads the same tables the writer owns; SMALLINT codes are decoded back to their
envelope strings. Per-tenant isolation is structural — a query names exactly one
tenant's schema (or public.audit_log_global for the system-admin global view).
"""
from __future__ import annotations

import json

from . import codes
from .naming import schema_for_tenant

_COLS = ("seq, ts, category, action, outcome, actor, actor_roles, target_uid, "
         "target_name, target_type, detail, source_iface, source_addr, request_id")


def _parent(tenant: str | None) -> str:
    return "audit_log_global" if tenant is None else f'"{schema_for_tenant(tenant)}".audit_log'


def _build_where(filters: dict) -> tuple[str, list]:
    clauses, params = [], []

    def eq(col, val):
        if val:
            clauses.append(f"{col} = %s")
            params.append(val)

    eq("actor", filters.get("actor"))
    eq("target_uid", filters.get("target_uid"))
    eq("action", filters.get("action"))
    if filters.get("category"):
        code = codes.CATEGORY.get(filters["category"])
        if code is None:
            raise ValueError(f"unknown category: {filters['category']!r}")
        clauses.append("category = %s")
        params.append(code)
    if filters.get("outcome"):
        code = codes.OUTCOME.get(filters["outcome"])
        if code is None:
            raise ValueError(f"unknown outcome: {filters['outcome']!r}")
        clauses.append("outcome = %s")
        params.append(code)
    if filters.get("from_ts"):
        clauses.append("ts >= %s")
        params.append(filters["from_ts"])
    if filters.get("to_ts"):
        clauses.append("ts <= %s")
        params.append(filters["to_ts"])
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def _decode(rec) -> dict:
    (seq, ts, category, action, outcome, actor, actor_roles, target_uid, target_name,
     target_type, detail, source_iface, source_addr, request_id) = rec
    return {
        "seq": seq,
        "ts": ts.isoformat(),
        "category": codes.CATEGORY_NAME.get(category),
        "action": action,
        "outcome": codes.OUTCOME_NAME.get(outcome),
        "actor": actor,
        "actor_roles": actor_roles.split(",") if actor_roles else [],
        "target_uid": target_uid,
        "target_name": target_name,
        "target_type": codes.TARGET_TYPE_NAME.get(target_type) if target_type is not None else None,
        "detail": detail,
        "source_iface": source_iface,
        "source_addr": source_addr,
        "request_id": request_id,
    }


def query(conn, tenant: str | None, filters: dict, *, page: int = 0, page_size: int = 100) -> list[dict]:
    where, params = _build_where(filters)
    sql = (f"SELECT {_COLS} FROM {_parent(tenant)}{where} "
           f"ORDER BY seq DESC LIMIT %s OFFSET %s")
    with conn.cursor() as cur:
        cur.execute(sql, params + [page_size, max(0, page) * page_size])
        return [_decode(r) for r in cur.fetchall()]


def query_ascending(conn, tenant: str | None, filters: dict, limit: int = 5000) -> list[dict]:
    """Decoded rows in ascending seq order — used to replay a rule against history
    (windowing needs chronological order)."""
    where, params = _build_where(filters)
    sql = f"SELECT {_COLS} FROM {_parent(tenant)}{where} ORDER BY seq LIMIT %s"
    with conn.cursor() as cur:
        cur.execute(sql, params + [limit])
        return [_decode(r) for r in cur.fetchall()]


def export_ndjson(conn, tenant: str | None, filters: dict):
    """Yield NDJSON lines (ascending seq) for a compliance dump."""
    where, params = _build_where(filters)
    sql = f"SELECT {_COLS} FROM {_parent(tenant)}{where} ORDER BY seq"
    with conn.cursor() as cur:
        cur.execute(sql, params)
        for rec in cur:
            yield json.dumps(_decode(rec)) + "\n"
