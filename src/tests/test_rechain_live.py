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

"""Repairing a chain broken by the concurrent-writer defect.

The tests that matter here are the ones about what the tool REFUSES to do. A
re-linker that also quietly fixes edited content would turn every future
verification into theatre.
"""
from __future__ import annotations

import uuid

import pytest

from audit_service.envelope import parse_envelope
from audit_service.hashing import canonical_json, canonical_row, compute_row_hash
from audit_service.naming import schema_for_tenant
from audit_service.rechain import IntegrityMismatch, rechain, record_repair
from audit_service.verify import verify_chain
from audit_service.writer import write_batch


def _env(tenant, action="acl_grant", ts="2026-07-10T12:00:00Z", **extra):
    e = {"event_id": str(uuid.uuid4()), "tenant": tenant, "ts": ts,
         "category": "permission", "action": action, "outcome": "ok",
         "actor": "james", "scope": "tenant"}
    e.update(extra)
    return parse_envelope(e)


def _content(conn, schema):
    with conn.cursor() as cur:
        cur.execute(f'SELECT seq, event_id, ts, action, actor, detail, source_addr '
                    f'FROM "{schema}".audit_log ORDER BY seq')
        return cur.fetchall()


def _break_the_chain(conn, schema, at_seq):
    """Reproduce the production breakage exactly: an orphaned link whose row is
    still self-consistent.

    This has to be built carefully or it tests the wrong thing. A racing writer
    read a STALE tail and then hashed its row against that stale tail, so the row
    it wrote satisfies row_hash == SHA-256(prev_hash ‖ content) — it is internally
    perfect and merely attached in the wrong place. That is why the production
    failures were all "prev_hash does not match" and never "row_hash does not
    match".

    Rewriting prev_hash alone would instead produce a row inconsistent with its
    own hash, which is the signature of EDITED CONTENT — a different fault, one
    the repair tool is required to refuse. Simulating the bug that way tests the
    refusal path while appearing to test the repair path.
    """
    with conn.cursor() as cur:
        cur.execute(f'SELECT row_hash FROM "{schema}".audit_log ORDER BY seq LIMIT 1')
        stale_head = bytes(cur.fetchone()[0])
        cur.execute(f'SELECT event_id, ts, category, action, outcome, actor, actor_roles, '
                    f'target_uid, target_name, target_type, detail, source_iface, '
                    f'source_addr, request_id FROM "{schema}".audit_log WHERE seq = %s',
                    (at_seq,))
        (event_id, ts, category, action, outcome, actor, actor_roles, target_uid,
         target_name, target_type, detail, source_iface, source_addr, request_id) = cur.fetchone()
        canon = canonical_row(
            event_id=str(event_id), ts=ts, category=category, action=action,
            outcome=outcome, actor=actor, actor_roles=actor_roles,
            target_uid=target_uid, target_name=target_name, target_type=target_type,
            detail=(canonical_json(detail) if detail is not None else None),
            source_iface=source_iface, source_addr=source_addr,
            request_id=request_id, tenant=None)
        cur.execute(f'UPDATE "{schema}".audit_log SET prev_hash = %s, row_hash = %s '
                    f'WHERE seq = %s', (stale_head, compute_row_hash(stale_head, canon), at_seq))
    conn.commit()


def _seqs(conn, schema):
    with conn.cursor() as cur:
        cur.execute(f'SELECT seq FROM "{schema}".audit_log ORDER BY seq')
        return [r[0] for r in cur.fetchall()]


@pytest.fixture()
def broken_chain(pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    write_batch(pg_conn, [_env(audit_schema) for _ in range(6)], {})
    pg_conn.commit()
    seqs = _seqs(pg_conn, schema)
    _break_the_chain(pg_conn, schema, seqs[3])
    assert not verify_chain(pg_conn, audit_schema).ok
    return audit_schema, schema, seqs[3]


def test_repairs_a_chain_broken_on_linkage(pg_conn, broken_chain):
    tenant, schema, broken_at = broken_chain
    res = rechain(pg_conn, tenant)
    pg_conn.commit()
    assert res.ok_before is False
    assert res.was_broken_at == broken_at
    assert res.ok_after is True
    assert verify_chain(pg_conn, tenant).ok


def test_repair_never_alters_row_content(pg_conn, broken_chain):
    """The point of the trade: links are counterfeit, content is not touched."""
    tenant, schema, _ = broken_chain
    before = _content(pg_conn, schema)
    rechain(pg_conn, tenant)
    pg_conn.commit()
    assert _content(pg_conn, schema) == before


def test_only_the_rows_that_need_it_are_rewritten(pg_conn, broken_chain):
    """Rows before the break are already correctly linked and must be left
    alone — a repair that rewrites everything cannot be reviewed."""
    tenant, schema, broken_at = broken_chain
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq, row_hash FROM "{schema}".audit_log ORDER BY seq')
        before = {s: bytes(h) for s, h in cur.fetchall()}
    res = rechain(pg_conn, tenant)
    pg_conn.commit()
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq, row_hash FROM "{schema}".audit_log ORDER BY seq')
        after = {s: bytes(h) for s, h in cur.fetchall()}
    unchanged = [s for s in before if before[s] == after[s]]
    assert broken_at not in unchanged
    assert len(unchanged) >= 3, "rows before the break should keep their hashes"
    assert res.relinked == len([s for s in before if before[s] != after[s]])


def test_refuses_when_a_row_s_content_was_edited(pg_conn, audit_schema):
    """The one case that must never be papered over: content that no longer
    matches its own stored hash is evidence of an edit, not of a bad link."""
    schema = schema_for_tenant(audit_schema)
    write_batch(pg_conn, [_env(audit_schema) for _ in range(4)], {})
    pg_conn.commit()
    seqs = _seqs(pg_conn, schema)
    with pg_conn.cursor() as cur:
        cur.execute(f'UPDATE "{schema}".audit_log SET actor = %s WHERE seq = %s',
                    ("mallory", seqs[2]))
    pg_conn.commit()

    with pytest.raises(IntegrityMismatch) as e:
        rechain(pg_conn, audit_schema)
    assert str(seqs[2]) in str(e.value)
    pg_conn.rollback()
    # and it really did not repair anything
    assert not verify_chain(pg_conn, audit_schema).ok


def test_dry_run_changes_nothing(pg_conn, broken_chain):
    tenant, schema, _ = broken_chain
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq, prev_hash, row_hash FROM "{schema}".audit_log ORDER BY seq')
        before = cur.fetchall()
    res = rechain(pg_conn, tenant, dry_run=True)
    pg_conn.rollback()
    assert res.relinked > 0, "a dry run still reports what it would do"
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT seq, prev_hash, row_hash FROM "{schema}".audit_log ORDER BY seq')
        assert cur.fetchall() == before
    assert not verify_chain(pg_conn, tenant).ok


def test_is_idempotent(pg_conn, broken_chain):
    tenant, _, _ = broken_chain
    rechain(pg_conn, tenant); pg_conn.commit()
    second = rechain(pg_conn, tenant); pg_conn.commit()
    assert second.ok_before is True
    assert second.relinked == 0


def test_a_healthy_chain_is_left_alone(pg_conn, audit_schema):
    write_batch(pg_conn, [_env(audit_schema) for _ in range(3)], {})
    pg_conn.commit()
    res = rechain(pg_conn, audit_schema)
    assert res.ok_before and res.relinked == 0 and res.rows == 3


def test_repair_is_recorded_in_the_chain_it_repaired(pg_conn, broken_chain):
    """A counterfeit that declares itself is a different object from one that
    does not."""
    tenant, schema, broken_at = broken_chain
    res = rechain(pg_conn, tenant)
    record_repair(pg_conn, tenant, res, actor="tester")
    pg_conn.commit()

    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT action, actor, detail FROM "{schema}".audit_log '
                    f'ORDER BY seq DESC LIMIT 1')
        action, actor, detail = cur.fetchone()
    assert action == "chain.repair"
    assert actor == "tester"
    assert detail["relinked"] == res.relinked
    assert detail["was_broken_at_seq"] == broken_at
    assert verify_chain(pg_conn, tenant).ok, "the marker must not break the chain"


def test_repair_holds_the_chain_against_concurrent_appends(pg_conn, second_conn, broken_chain):
    """A writer appending to the old tail mid-repair would leave a fresh break
    behind the moment the repair finished."""
    import psycopg
    tenant, _, _ = broken_chain
    rechain(pg_conn, tenant)          # transaction open, chain lock held
    with second_conn.cursor() as cur:
        cur.execute("SET LOCAL lock_timeout = '400ms'")
        cur.execute("SET LOCAL statement_timeout = '900ms'")
    with pytest.raises((psycopg.errors.LockNotAvailable, psycopg.errors.QueryCanceled)):
        write_batch(second_conn, [_env(tenant)], {})
    second_conn.rollback()
    pg_conn.commit()
    assert verify_chain(pg_conn, tenant).ok


def test_other_tenants_are_untouched(pg_conn, broken_chain, config):
    from .conftest import AUDIT_LOG_DDL
    tenant, _, _ = broken_chain
    other = f"{tenant}_other"
    oschema = schema_for_tenant(other)
    with pg_conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{oschema}" CASCADE')
        cur.execute(f'CREATE SCHEMA "{oschema}"')
        cur.execute(AUDIT_LOG_DDL.format(schema=oschema))
    pg_conn.commit()
    try:
        write_batch(pg_conn, [_env(other) for _ in range(3)], {})
        pg_conn.commit()
        before = _content(pg_conn, oschema)
        rechain(pg_conn, tenant)
        pg_conn.commit()
        assert _content(pg_conn, oschema) == before
    finally:
        with pg_conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{oschema}" CASCADE')
        pg_conn.commit()


@pytest.fixture()
def second_conn(config):
    from audit_service import db
    conn = db.connect(config)
    yield conn
    try:
        conn.rollback(); conn.close()
    except Exception:
        pass


# --- lock ordering -----------------------------------------------------------
#
# These exist because the first production run deadlocked on the fifth chain.
# The repair held the chain lock and then asked for a partition lock, while every
# writer asks for them the other way round.

def test_marker_is_written_after_the_relink_commits(pg_conn, broken_chain):
    """repair() must not still hold the chain lock when it writes the marker."""
    from audit_service.rechain import repair
    tenant, schema, _ = broken_chain
    res = repair(pg_conn, tenant, actor="tester")
    assert res.ok_after
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT action FROM "{schema}".audit_log ORDER BY seq DESC LIMIT 1')
        assert cur.fetchone()[0] == "chain.repair"
    assert verify_chain(pg_conn, tenant).ok


def test_the_repair_survives_a_marker_that_cannot_be_written(pg_conn, broken_chain, monkeypatch):
    """The relink is the part that matters and is committed before the marker is
    attempted, so a marker failure must not take the repair with it."""
    from audit_service import rechain as rc
    tenant, schema, _ = broken_chain

    def boom(*a, **k):
        raise RuntimeError("marker write failed")
    monkeypatch.setattr(rc, "record_repair", boom)

    with pytest.raises(RuntimeError):
        rc.repair(pg_conn, tenant, actor="tester")
    pg_conn.rollback()
    assert verify_chain(pg_conn, tenant).ok, "the relink must have been committed"


def test_repair_does_not_hold_the_chain_lock_while_taking_a_partition_lock(
        pg_conn, second_conn, broken_chain):
    """The deadlock, encoded.

    Hold the partition lock a writer would take, from another connection, then
    run the repair. If the repair still held the chain lock at that point,
    Postgres would report a deadlock — each process waiting on the other's
    advisory lock. Correct behaviour is for the relink to commit and only the
    MARKER to wait, so a lock_timeout surfaces as a plain timeout and the repair
    itself survives.
    """
    import psycopg
    from audit_service.rechain import repair
    from audit_service.writer import _partition_of, _parent_table
    from audit_service.envelope import parse_envelope
    tenant, schema, _ = broken_chain

    row = parse_envelope({"event_id": str(uuid.uuid4()), "tenant": tenant,
                          "ts": "2026-07-10T12:00:00Z", "category": "permission",
                          "action": "acl_grant", "outcome": "ok", "actor": "james",
                          "scope": "tenant"})
    partition = _partition_of(_parent_table(row), row.ts.date())
    with second_conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (partition,))

    with pg_conn.cursor() as cur:
        cur.execute("SET lock_timeout = '600ms'")
    try:
        repair(pg_conn, tenant, actor="tester")
    except psycopg.errors.LockNotAvailable:
        pg_conn.rollback()          # the MARKER timed out, never a deadlock
    except psycopg.errors.DeadlockDetected:
        pytest.fail("repair still holds the chain lock when it takes a partition lock")
    finally:
        second_conn.rollback()
        with pg_conn.cursor() as cur:
            cur.execute("SET lock_timeout = 0")

    assert verify_chain(pg_conn, tenant).ok, "the relink must survive regardless"
