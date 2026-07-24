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

"""Live writer tests against a real Postgres (skipped if unreachable)."""
from __future__ import annotations

import uuid

import pytest

from audit_service.envelope import parse_envelope
from audit_service.naming import schema_for_tenant
from audit_service.writer import write_batch

pytestmark = pytest.mark.live


def _env(tenant, event_id, ts="2026-07-10T12:00:00Z", **extra):
    return {"event_id": event_id, "ts": ts, "tenant": tenant, "category": "access",
            "action": "read", "outcome": "ok", "actor": "alice", **extra}


def _count(conn, schema):
    with conn.cursor() as cur:
        cur.execute(f'SELECT count(*) FROM "{schema}".audit_log')
        return cur.fetchone()[0]


def test_write_lands_in_daily_partition(pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    eid = str(uuid.uuid4())
    row = parse_envelope(_env(audit_schema, eid, target_uid="f1", target_type="file",
                              detail={"bytes": 10}, source_iface="grpc", source_addr="1.2.3.4"))
    write_batch(pg_conn, [row], {})
    pg_conn.commit()

    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT event_id, actor, category, detail, source_addr '
                    f'FROM "{schema}".audit_log WHERE event_id = %s::uuid', (eid,))
        got = cur.fetchone()
    assert got is not None
    assert str(got[0]) == eid and got[1] == "alice" and got[2] == 0
    assert got[3] == {"bytes": 10} and got[4] == "1.2.3.4"

    # The daily partition was created on demand.
    with pg_conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (f'"{schema}".audit_log_p20260710',))
        assert cur.fetchone()[0] is not None


def test_redelivery_is_idempotent(pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    eid = str(uuid.uuid4())
    row = parse_envelope(_env(audit_schema, eid))
    write_batch(pg_conn, [row], {})
    pg_conn.commit()
    assert _count(pg_conn, schema) == 1

    # Same event_id + ts again → ON CONFLICT DO NOTHING, still one row.
    write_batch(pg_conn, [parse_envelope(_env(audit_schema, eid))], {})
    pg_conn.commit()
    assert _count(pg_conn, schema) == 1


def test_global_scope_writes_to_audit_log_global(pg_conn, global_table):
    eid = str(uuid.uuid4())
    env = {"event_id": eid, "ts": "2026-07-10T08:00:00Z", "scope": "global",
           "category": "auth", "action": "password_reset_request", "outcome": "ok",
           "actor": "user@example.com", "source_iface": "ldapadmin", "source_addr": "1.2.3.4"}
    write_batch(pg_conn, [parse_envelope(env)], {})
    pg_conn.commit()
    try:
        with pg_conn.cursor() as cur:
            cur.execute("SELECT actor, category, action, source_iface, tenant "
                        "FROM audit_log_global WHERE event_id = %s::uuid", (eid,))
            got = cur.fetchone()
        assert got == ("user@example.com", 4, "password_reset_request", "ldapadmin", None)
    finally:
        with pg_conn.cursor() as cur:
            cur.execute("DELETE FROM audit_log_global WHERE event_id = %s::uuid", (eid,))
        pg_conn.commit()


def test_batch_spans_multiple_days(pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    rows = [
        parse_envelope(_env(audit_schema, str(uuid.uuid4()), ts="2026-07-10T23:59:00Z")),
        parse_envelope(_env(audit_schema, str(uuid.uuid4()), ts="2026-07-11T00:01:00Z")),
    ]
    write_batch(pg_conn, rows, {})
    pg_conn.commit()
    assert _count(pg_conn, schema) == 2
    with pg_conn.cursor() as cur:
        for part in ("audit_log_p20260710", "audit_log_p20260711"):
            cur.execute("SELECT to_regclass(%s)", (f'"{schema}".{part}',))
            assert cur.fetchone()[0] is not None, part
