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

"""Live tamper-evidence tests: the hash chain links, verifies, and detects edits,
deletions, and reordering (skipped if Postgres is unreachable)."""
from __future__ import annotations

import uuid

import pytest

from audit_service.envelope import parse_envelope
from audit_service.naming import schema_for_tenant
from audit_service.verify import verify_chain
from audit_service.writer import write_batch

pytestmark = pytest.mark.live


def _env(tenant, eid, i):
    return {"event_id": eid, "ts": f"2026-07-10T12:00:{i:02d}Z", "tenant": tenant,
            "category": "access", "action": "read", "outcome": "ok",
            "actor": f"u{i}", "detail": {"i": i}}


def _write_seq(conn, tenant, n):
    rows = [parse_envelope(_env(tenant, str(uuid.uuid4()), i)) for i in range(n)]
    write_batch(conn, rows, {})
    conn.commit()
    return rows


def test_chain_links_and_verifies(pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    _write_seq(pg_conn, audit_schema, 5)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq, prev_hash, row_hash FROM "{schema}".audit_log ORDER BY seq')
        rows = cur.fetchall()
    assert rows[0][1] is None                       # genesis prev_hash is NULL
    assert all(r[2] is not None for r in rows)      # every row_hash populated
    for i in range(1, len(rows)):
        assert bytes(rows[i][1]) == bytes(rows[i - 1][2])   # prev links to previous row_hash
    res = verify_chain(pg_conn, audit_schema)
    assert res.ok and res.checked == 5 and res.first_broken_seq is None


def test_edit_breaks_chain(pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    _write_seq(pg_conn, audit_schema, 4)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq FROM "{schema}".audit_log ORDER BY seq OFFSET 2 LIMIT 1')
        target = cur.fetchone()[0]
        # A privileged UPDATE (the append-only role would forbid this) — the row's
        # content no longer matches its stored row_hash.
        cur.execute(f'UPDATE "{schema}".audit_log SET actor = %s WHERE seq = %s', ("evil", target))
    pg_conn.commit()
    res = verify_chain(pg_conn, audit_schema)
    assert not res.ok and res.first_broken_seq == target


def test_delete_breaks_chain(pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    _write_seq(pg_conn, audit_schema, 4)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq FROM "{schema}".audit_log ORDER BY seq OFFSET 1 LIMIT 1')
        gap = cur.fetchone()[0]
        cur.execute(f'DELETE FROM "{schema}".audit_log WHERE seq = %s', (gap,))
        cur.execute(f'SELECT min(seq) FROM "{schema}".audit_log WHERE seq > %s', (gap,))
        after = cur.fetchone()[0]
    pg_conn.commit()
    res = verify_chain(pg_conn, audit_schema)
    # The row after the gap still links to the removed row's hash -> linkage fails there.
    assert not res.ok and res.first_broken_seq == after


def test_redelivery_preserves_chain(pg_conn, audit_schema):
    rows = [parse_envelope(_env(audit_schema, str(uuid.uuid4()), i)) for i in range(3)]
    write_batch(pg_conn, rows, {})
    pg_conn.commit()
    # Re-deliver the same rows with a fresh head cache (reseeds from DB).
    write_batch(pg_conn, rows, {})
    pg_conn.commit()
    schema = schema_for_tenant(audit_schema)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT count(*) FROM "{schema}".audit_log')
        assert cur.fetchone()[0] == 3               # no duplicates
    res = verify_chain(pg_conn, audit_schema)
    assert res.ok and res.checked == 3               # chain intact after re-delivery


def test_global_chain_verifies(pg_conn, global_table):
    # Isolate the shared global table so cleanup deletes elsewhere don't perturb it.
    with pg_conn.cursor() as cur:
        cur.execute("TRUNCATE audit_log_global")
    pg_conn.commit()
    rows = [parse_envelope({"event_id": str(uuid.uuid4()), "ts": f"2026-07-10T07:00:0{i}Z",
                            "scope": "global", "category": "admin", "action": "tenant_create",
                            "outcome": "ok", "actor": "root", "tenant": f"t{i}"}) for i in range(3)]
    write_batch(pg_conn, rows, {})
    pg_conn.commit()
    res = verify_chain(pg_conn, None)
    assert res.ok and res.checked == 3
