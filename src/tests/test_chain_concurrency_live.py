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

"""Two writers, one chain (§7).

The queue consumer and the accountability poller are separate processes writing
the same per-tenant chain. Appending is a read-modify-write on the chain tail, so
without serialization both read the same tail, both append to it, and the second
to commit is orphaned — a break that is permanent, silent, and indistinguishable
from a deleted row when the log is verified months later.

These tests are written against the failure as it actually presented in
production: every chain broken, always on linkage and never on integrity, with
the first break early in a tenant's life where provisioning events cluster.
"""
from __future__ import annotations

import uuid

import pytest

from audit_service.envelope import parse_envelope
from audit_service.naming import schema_for_tenant
from audit_service.verify import verify_chain
from audit_service.writer import write_batch


def _env(tenant, event_id=None, action="acl_grant", ts="2026-07-10T12:00:00Z", **extra):
    e = {"event_id": event_id or str(uuid.uuid4()), "tenant": tenant, "ts": ts,
         "category": "permission", "action": action, "outcome": "ok",
         "actor": "james", "scope": "tenant"}
    e.update(extra)
    return parse_envelope(e)


@pytest.fixture()
def second_conn(config):
    """A SECOND connection — the whole point. One process's cache cannot be
    reasoned about from another's, which is exactly what broke."""
    from audit_service import db
    conn = db.connect(config)
    yield conn
    try:
        conn.rollback(); conn.close()
    except Exception:
        pass


def _append(conn, tenant, heads, action="acl_grant"):
    write_batch(conn, [_env(tenant, action=action)], heads)
    conn.commit()


def test_second_writer_cannot_orphan_the_first(pg_conn, second_conn, audit_schema):
    """The production shape, minimally: A appends, B appends, A appends again
    holding a head cache from before B existed.

    Before the fix A's third row chained onto its own second row, skipping B's —
    seq 8 pointing at seq 5 with seq 6 in between, exactly as measured on the
    deployment.
    """
    heads_a, heads_b = {}, {}
    _append(pg_conn, audit_schema, heads_a, action="acl.grant")
    _append(second_conn, audit_schema, heads_b, action="acl_grant")
    _append(pg_conn, audit_schema, heads_a, action="acl.grant")   # stale cache

    r = verify_chain(pg_conn, audit_schema)
    assert r.ok, f"chain broken at seq {r.first_broken_seq}: {r.reason}"
    assert r.checked == 3


def test_every_row_links_to_its_immediate_predecessor(pg_conn, second_conn, audit_schema):
    """Linkage is the property that broke, so assert it directly rather than
    trusting verify_chain to be the only witness."""
    heads_a, heads_b = {}, {}
    for i in range(12):
        _append(pg_conn if i % 2 == 0 else second_conn, audit_schema,
                heads_a if i % 2 == 0 else heads_b)

    schema = schema_for_tenant(audit_schema)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq, prev_hash, row_hash FROM "{schema}".audit_log ORDER BY seq')
        rows = cur.fetchall()
    assert len(rows) == 12
    prev = None
    for seq, ph, rh in rows:
        ph = bytes(ph) if ph is not None else None
        assert ph == prev, f"seq {seq} chains onto the wrong row"
        prev = bytes(rh)


def test_interleaved_batches_verify(pg_conn, second_conn, audit_schema):
    """Multi-row batches from both writers, alternating — the poller drains in
    batches while the consumer writes its own."""
    heads_a, heads_b = {}, {}
    for i in range(6):
        conn, heads = (pg_conn, heads_a) if i % 2 == 0 else (second_conn, heads_b)
        write_batch(conn, [_env(audit_schema) for _ in range(4)], heads)
        conn.commit()
    r = verify_chain(pg_conn, audit_schema)
    assert r.ok, f"broken at seq {r.first_broken_seq}: {r.reason}"
    assert r.checked == 24


def test_stale_cached_head_is_ignored(pg_conn, second_conn, audit_schema):
    """A cached head is only knowable to be current under the chain lock, so the
    writer re-reads it there. Feed it a deliberate lie and check the lie loses."""
    heads = {}
    _append(pg_conn, audit_schema, heads)
    schema = schema_for_tenant(audit_schema)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT row_hash FROM "{schema}".audit_log ORDER BY seq DESC LIMIT 1')
        real_head = bytes(cur.fetchone()[0])

    write_batch(pg_conn, [_env(audit_schema)], {audit_schema: b"\xde\xad\xbe\xef" * 8})
    pg_conn.commit()

    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT prev_hash FROM "{schema}".audit_log ORDER BY seq DESC LIMIT 1')
        assert bytes(cur.fetchone()[0]) == real_head
    assert verify_chain(pg_conn, audit_schema).ok


def test_writers_on_one_chain_serialize_across_different_days(pg_conn, second_conn, audit_schema):
    """The lock must be held across the tail read AND the insert, and it must be
    keyed on the CHAIN.

    Deliberately writes the two rows into different daily partitions. The
    partition lock that already existed would serialize two writers aiming at the
    same day, which masks a missing chain lock entirely — this test passed before
    the chain lock existed for exactly that reason, and proved nothing. Different
    days take different partition locks, so if the second writer still waits, it
    is waiting on the chain.

    Not contrived: the accountability poller draining yesterday's backlog while
    the consumer records today is this case exactly.

    Both partitions are created and committed FIRST. Attaching a new partition
    takes ACCESS EXCLUSIVE on the parent, which blocks any concurrent writer on
    its own — a second way this test can appear to pass while proving nothing.
    With both partitions already present, the chain lock is the only thing left
    that can make the second writer wait.
    """
    import psycopg
    for day in ("2026-07-10T06:00:00Z", "2026-07-11T06:00:00Z"):
        write_batch(pg_conn, [_env(audit_schema, ts=day)], {})
        pg_conn.commit()

    write_batch(pg_conn, [_env(audit_schema, ts="2026-07-10T12:00:00Z")], {})
    with second_conn.cursor() as cur:
        cur.execute("SET LOCAL lock_timeout = '400ms'")
        cur.execute("SET LOCAL statement_timeout = '900ms'")
    with pytest.raises((psycopg.errors.LockNotAvailable, psycopg.errors.QueryCanceled)):
        write_batch(second_conn, [_env(audit_schema, ts="2026-07-11T12:00:00Z")], {})
    second_conn.rollback()
    pg_conn.commit()
    assert verify_chain(pg_conn, audit_schema).ok


def test_a_batch_spanning_days_still_links_correctly(pg_conn, second_conn, audit_schema):
    """One batch crossing midnight, with a second writer appending in between
    batches — the partition loop and the chain loop must not disagree about
    order."""
    heads_a, heads_b = {}, {}
    write_batch(pg_conn, [_env(audit_schema, ts="2026-07-10T23:59:00Z"),
                          _env(audit_schema, ts="2026-07-11T00:01:00Z")], heads_a)
    pg_conn.commit()
    _append(second_conn, audit_schema, heads_b)
    write_batch(pg_conn, [_env(audit_schema, ts="2026-07-11T02:00:00Z")], heads_a)
    pg_conn.commit()
    r = verify_chain(pg_conn, audit_schema)
    assert r.ok, f"broken at seq {r.first_broken_seq}: {r.reason}"
    assert r.checked == 4


def test_different_tenants_do_not_serialize(pg_conn, second_conn, audit_schema, config):
    """The lock is per chain. If it were per table or global, one busy tenant
    would stall every other one — a throughput regression disguised as a fix.
    """
    import psycopg
    other = f"{audit_schema}_b"
    schema = schema_for_tenant(other)
    with pg_conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        cur.execute(f'CREATE SCHEMA "{schema}"')
        from .conftest import AUDIT_LOG_DDL
        cur.execute(AUDIT_LOG_DDL.format(schema=schema))
    pg_conn.commit()
    try:
        write_batch(pg_conn, [_env(audit_schema)], {})      # holds tenant A's lock
        with second_conn.cursor() as cur:
            cur.execute("SET LOCAL lock_timeout = '2s'")
        write_batch(second_conn, [_env(other)], {})         # tenant B must not wait
        second_conn.commit()
        pg_conn.commit()
        assert verify_chain(pg_conn, other).ok
    finally:
        with pg_conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        pg_conn.commit()


def test_global_chain_is_locked_too(pg_conn, second_conn, global_table):
    """The global chain has the same two writers and broke the same way
    (first break at seq 207 on the deployment)."""
    ids = [str(uuid.uuid4()) for _ in range(6)]
    heads_a, heads_b = {}, {}
    for i, eid in enumerate(ids):
        conn, heads = (pg_conn, heads_a) if i % 2 == 0 else (second_conn, heads_b)
        env = {"event_id": eid, "ts": "2026-07-10T12:00:00Z", "category": "admin",
               "action": "tenant.create", "outcome": "ok", "actor": "james",
               "scope": "global"}
        write_batch(conn, [parse_envelope(env)], heads)
        conn.commit()
    try:
        r = verify_chain(pg_conn, None)
        assert r.ok, f"global chain broken at seq {r.first_broken_seq}: {r.reason}"
    finally:
        with pg_conn.cursor() as cur:
            cur.execute("DELETE FROM audit_log_global WHERE event_id = ANY(%s::uuid[])", (ids,))
        pg_conn.commit()


def test_redelivery_under_concurrency_keeps_the_chain_intact(pg_conn, second_conn, audit_schema):
    """At-least-once delivery plus two writers: the duplicate must adopt the
    STORED hash, and the row after it must still chain onto the real tail."""
    heads_a, heads_b = {}, {}
    dup = _env(audit_schema)
    write_batch(pg_conn, [dup], heads_a); pg_conn.commit()
    _append(second_conn, audit_schema, heads_b)
    write_batch(pg_conn, [dup], heads_a); pg_conn.commit()          # re-delivery
    _append(second_conn, audit_schema, heads_b)

    schema = schema_for_tenant(audit_schema)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT count(*) FROM "{schema}".audit_log')
        assert cur.fetchone()[0] == 3, "the duplicate must not be stored twice"
    r = verify_chain(pg_conn, audit_schema)
    assert r.ok, f"broken at seq {r.first_broken_seq}: {r.reason}"
