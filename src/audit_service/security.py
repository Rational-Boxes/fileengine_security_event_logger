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

"""Security incidents + rule-config persistence (usage_logging §11).

The rules engine's incidents are persisted here (``public.security_incidents``),
and per-tenant rule configuration lives in ``public.security_rules`` (the rule
builder's store, seeded from the default pack). A rule row with ``tenant = '*'``
is a system default applying to every tenant; a tenant may override a default by
storing a rule with the same ``rule_id``. Both tables are read by the
AUDIT_READ-gated security API.
"""
from __future__ import annotations

import json
import logging

from .engine import Incident, IncidentStore
from .rules import Rule, default_rules

log = logging.getLogger("audit_service.security")

GLOBAL = "*"

_INCIDENTS_DDL = """
CREATE TABLE IF NOT EXISTS public.security_incidents (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    tenant       VARCHAR(255),
    rule_id      VARCHAR(64)  NOT NULL,
    group_by     VARCHAR(16)  NOT NULL,
    group_key    VARCHAR(255) NOT NULL,
    actor        VARCHAR(255),
    severity     VARCHAR(16)  NOT NULL,
    response     VARCHAR(16)  NOT NULL,
    match_count  INTEGER      NOT NULL,
    window_s     INTEGER      NOT NULL,
    action_taken VARCHAR(32)  NOT NULL,
    dry_run      BOOLEAN      NOT NULL DEFAULT false,
    description  TEXT,
    status       VARCHAR(16)  NOT NULL DEFAULT 'open',
    last_event_ts TEXT,
    -- §3.5/§3.6. `scope` says which windows produced the count and `audience`
    -- who may see it; `distinct_values` names what a fan-out incident touched,
    -- because "8 tenants" without naming them leaves the administrator to go
    -- and find out which.
    --
    -- Defaults match what every existing row means: rows written before this
    -- were all tenant-scoped and tenant-audience, so backfill is the default
    -- rather than a pass.
    scope        VARCHAR(16)  NOT NULL DEFAULT 'tenant',
    audience     VARCHAR(16)  NOT NULL DEFAULT 'tenant',
    distinct_values TEXT[]    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_ts ON public.security_incidents(tenant, ts DESC);
"""

# Added after the table already existed in deployments, so ALTERs rather than a
# changed CREATE. IF NOT EXISTS on each: the DDL runs on every store connect.
_INCIDENTS_MIGRATIONS = (
    "ALTER TABLE public.security_incidents "
    "ADD COLUMN IF NOT EXISTS scope VARCHAR(16) NOT NULL DEFAULT 'tenant'",
    "ALTER TABLE public.security_incidents "
    "ADD COLUMN IF NOT EXISTS audience VARCHAR(16) NOT NULL DEFAULT 'tenant'",
    "ALTER TABLE public.security_incidents "
    "ADD COLUMN IF NOT EXISTS distinct_values TEXT[] NOT NULL DEFAULT '{}'",
    # AFTER the ALTERs, not in the CREATE block above. Measured: putting it
    # there failed with `column "audience" does not exist` against an existing
    # deployment — CREATE TABLE IF NOT EXISTS is a no-op on a table that already
    # exists, so the index ran before the column was added. A fresh database
    # would have passed, which is why this only showed up running it for real.
    #
    # The cross-tenant view's own access path: audience-filtered, newest-first,
    # across every tenant. Without it that view table-scans as incidents pile up.
    "CREATE INDEX IF NOT EXISTS idx_incidents_audience_ts "
    "ON public.security_incidents(audience, ts DESC)",
)

_RULES_DDL = """
CREATE TABLE IF NOT EXISTS public.security_rules (
    tenant     VARCHAR(255) NOT NULL,
    rule_id    VARCHAR(64)  NOT NULL,
    definition JSONB        NOT NULL,
    enabled    BOOLEAN      NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, rule_id)
);
"""


#: Any stable 64-bit number; it only has to be the same in every process.
_DDL_LOCK = 0x5ECA_11D1


def ensure_tables(conn) -> None:
    """Create and migrate the security tables.

    SERIALISED ON AN ADVISORY LOCK, because idempotent DDL is not the same thing
    as concurrency-safe DDL. `audit-rules` and `audit-api` both call this on
    connect, and two backends running CREATE/ALTER ... IF NOT EXISTS
    concurrently race in Postgres — the loser gets a duplicate-object or
    tuple-concurrently-updated error rather than a no-op. The lock is session
    level and released with the transaction.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
        cur.execute(_INCIDENTS_DDL)
        cur.execute(_RULES_DDL)
        for stmt in _INCIDENTS_MIGRATIONS:
            cur.execute(stmt)
    conn.commit()


# --------------------------------------------------------------- incidents ----

class PgIncidentStore(IncidentStore):
    """Engine-side incident store. Best-effort: a write failure logs and drops the
    incident rather than crashing the engine loop."""

    def __init__(self, connect):
        self._connect = connect
        self._conn = None

    def _c(self):
        if self._conn is None or getattr(self._conn, "closed", False):
            self._conn = self._connect()
            ensure_tables(self._conn)
        return self._conn

    def close(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    def record(self, inc: Incident) -> None:
        try:
            conn = self._c()
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO public.security_incidents "
                    "(tenant, rule_id, group_by, group_key, actor, severity, response, "
                    " match_count, window_s, action_taken, dry_run, description, last_event_ts, "
                    " scope, audience, distinct_values) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (inc.tenant, inc.rule_id, inc.group_by, inc.group_key, inc.actor,
                     inc.severity, inc.response, inc.count, inc.window_s, inc.action_taken,
                     inc.dry_run, inc.description, inc.last_ts,
                     # getattr, not inc.scope: an Incident built by an older
                     # caller (or a test double) has no such field, and a store
                     # that raises here drops the incident entirely.
                     getattr(inc, "scope", "tenant"),
                     getattr(inc, "audience", "tenant"),
                     list(getattr(inc, "distinct_values", ()) or ())))
            conn.commit()
        except Exception:
            log.exception("failed to persist incident %s", inc.rule_id)
            try:
                self._conn.rollback()
            except Exception:
                self._conn = None


#: Ranked worst-first, so a severity-ordered view does not depend on the caller
#: knowing the order. Matches rules.SEVERITIES reversed; asserted in the tests
#: because the two drifting apart would silently reorder the console.
_SEVERITY_RANK = {"critical": 0, "serious": 1, "warn": 2, "info": 3}


def list_incidents(conn, tenant: str | None, *, status: str | None = None, limit: int = 100,
                   audience: str | None = None, scope: str | None = None,
                   min_severity: str | None = None,
                   order: str = "ts") -> list[dict]:
    """Incidents, filtered.

    ``tenant=None`` means EVERY tenant, which is what the deployment tier reads
    and what a tenant caller must never be given — the gate in api.py decides
    that, not this function.

    ``order="severity"`` ranks worst-first then newest-first, for the aggregated
    view: a page of 100 ordered only by time can be entirely `info` while a
    `critical` sits on page two.
    """
    clauses, params = [], []
    if tenant is not None:
        clauses.append("tenant = %s")
        params.append(tenant)
    if status:
        clauses.append("status = %s")
        params.append(status)
    if audience:
        clauses.append("audience = %s")
        params.append(audience)
    if scope:
        clauses.append("scope = %s")
        params.append(scope)
    if min_severity:
        rank = _SEVERITY_RANK.get(min_severity)
        if rank is None:
            raise ValueError(f"bad min_severity: {min_severity!r}")
        keep = [s for s, r in _SEVERITY_RANK.items() if r <= rank]
        clauses.append("severity = ANY(%s)")
        params.append(keep)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    if order == "severity":
        order_sql = ("ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'serious' THEN 1 "
                     "WHEN 'warn' THEN 2 ELSE 3 END, ts DESC")
    else:
        order_sql = "ORDER BY ts DESC"

    cols = ("id, ts, tenant, rule_id, group_by, group_key, actor, severity, response, "
            "match_count, window_s, action_taken, dry_run, description, status, "
            "scope, audience, distinct_values")
    with conn.cursor() as cur:
        cur.execute(f"SELECT {cols} FROM public.security_incidents{where} {order_sql} LIMIT %s",
                    params + [limit])
        rows = cur.fetchall()
    keys = ["id", "ts", "tenant", "rule_id", "group_by", "group_key", "actor", "severity",
            "response", "match_count", "window_s", "action_taken", "dry_run", "description",
            "status", "scope", "audience", "distinct_values"]
    out = []
    for r in rows:
        d = dict(zip(keys, r))
        d["ts"] = d["ts"].isoformat()
        d["distinct_values"] = list(d.get("distinct_values") or [])
        out.append(d)
    return out


def set_incident_status(conn, incident_id: int, status: str) -> bool:
    with conn.cursor() as cur:
        cur.execute("UPDATE public.security_incidents SET status = %s WHERE id = %s",
                    (status, incident_id))
        updated = cur.rowcount
    conn.commit()
    return updated > 0


# ------------------------------------------------------------------ rules -----

class RulesStore:
    def __init__(self, connect):
        self._connect = connect
        self._conn = None

    def _c(self):
        if self._conn is None or getattr(self._conn, "closed", False):
            self._conn = self._connect()
            ensure_tables(self._conn)
        return self._conn

    def close(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    def list_rules(self, tenant: str) -> list[dict]:
        """Raw rows for a specific tenant scope (use '*' for the global defaults)."""
        with self._c().cursor() as cur:
            cur.execute("SELECT rule_id, definition, enabled, updated_at "
                        "FROM public.security_rules WHERE tenant = %s ORDER BY rule_id", (tenant,))
            return [{"rule_id": rid, "definition": d, "enabled": en, "updated_at": ua.isoformat()}
                    for rid, d, en, ua in cur.fetchall()]

    def rules_for(self, tenant: str | None) -> list[Rule]:
        """Effective rules for a tenant: global defaults ('*') overridden by the
        tenant's own rows with the same rule_id; disabled rules dropped."""
        scopes = [GLOBAL] if tenant is None else [GLOBAL, tenant]
        merged: dict[str, tuple[int, dict, bool]] = {}   # rule_id -> (rank, definition, enabled)
        with self._c().cursor() as cur:
            cur.execute("SELECT tenant, rule_id, definition, enabled FROM public.security_rules "
                        "WHERE tenant = ANY(%s)", (scopes,))
            for t, rid, definition, enabled in cur.fetchall():
                rank = 0 if t == GLOBAL else 1           # a tenant row (1) overrides global (0)
                if rid not in merged or rank >= merged[rid][0]:
                    merged[rid] = (rank, definition, enabled)
        rules = []
        for rid, (_rank, definition, enabled) in merged.items():
            if not enabled:
                continue
            try:
                rules.append(Rule.from_dict({**definition, "id": rid}))
            except Exception:
                log.exception("bad rule definition for %s", rid)
        return rules

    def upsert_rule(self, tenant: str, rule: dict) -> None:
        rid = rule["id"]
        enabled = rule.get("enabled", True)
        with self._c().cursor() as cur:
            cur.execute(
                "INSERT INTO public.security_rules (tenant, rule_id, definition, enabled, updated_at) "
                "VALUES (%s,%s,%s::jsonb,%s, now()) "
                "ON CONFLICT (tenant, rule_id) DO UPDATE SET definition = EXCLUDED.definition, "
                "enabled = EXCLUDED.enabled, updated_at = now()",
                (tenant, rid, json.dumps(rule), enabled))
        self._c().commit()

    def delete_rule(self, tenant: str, rule_id: str) -> bool:
        with self._c().cursor() as cur:
            cur.execute("DELETE FROM public.security_rules WHERE tenant = %s AND rule_id = %s",
                        (tenant, rule_id))
            deleted = cur.rowcount
        self._c().commit()
        return deleted > 0

    def seed_defaults(self, tenant: str = GLOBAL) -> int:
        """Insert the default pack for a scope if a rule_id is absent. Returns count added."""
        existing = {r["rule_id"] for r in self.list_rules(tenant)}
        added = 0
        for rule in default_rules():
            if rule.id in existing:
                continue
            self.upsert_rule(tenant, _rule_to_dict(rule))
            added += 1
        return added


def _rule_to_dict(rule: Rule) -> dict:
    import dataclasses
    return dataclasses.asdict(rule)
