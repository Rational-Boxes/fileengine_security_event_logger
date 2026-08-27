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

"""The drain loop, the cursor, and the precedence rule — against real Postgres.

Postgres is real here (the cursor, the audit chain and the interleave all live in
it) but the CORE is faked. That split is deliberate: standing up a core would
make these tests about deployment, and the properties under test — that the
cursor advances exactly once per record, that a break stops the drain instead of
skipping it, that a queue event is never recorded ahead of an older core record —
are properties of this service's logic, not of the core's.

The end-to-end pairing against a real core is ``scripts/e2e_accountability.py``.
"""
from __future__ import annotations

import json
import os
import uuid

import pytest

from audit_service.accountability import (GLOBAL_CHAIN_KEY, CoreRecord, IntegrityBreak,
                                          StaleRead, canonical_json, micros_to_datetime)
from audit_service.cursors import CursorStore
from audit_service.naming import schema_for_tenant
from audit_service.puller import AccountabilityPuller

pytestmark = pytest.mark.live

BASE_TS = 1756296000000000


class FakeCore:
    """Serves a scripted chain, page by page, the way the core's endpoint does."""

    def __init__(self, chains: dict, page_size: int | None = None):
        self.chains = chains          # {tenant_key: [CoreRecord]}
        self.page_size = page_size
        self.calls = []               # (tenant, cursor) — so tests can assert order

    def fetch(self, tenant: str, newer_than_ts_micros: int, limit: int):
        self.calls.append((tenant, newer_than_ts_micros))
        records = [r for r in self.chains.get(tenant, [])
                   if r.ts_micros > newer_than_ts_micros]
        limit = self.page_size or limit
        page, has_more = records[:limit], len(records) > limit
        head = self.chains.get(tenant, [])
        return page, has_more, (head[-1].seq if head else 0)


class UnreachableCore:
    def fetch(self, *args, **kwargs):
        raise RuntimeError("core unavailable")


def build_chain(n, *, tenant_key="", start_seq=1, start_ts=BASE_TS, action="acl.grant",
                category="authorization", target_type="acl"):
    records, prev = [], None
    for i in range(n):
        rec = CoreRecord(
            seq=start_seq + i,
            ts_micros=start_ts + i,
            ts=micros_to_datetime(start_ts + i),
            actor="alice",
            actor_roles=["editors"],
            source_iface="grpc",
            source_addr="10.0.0.7",
            category=category,
            action=action,
            target_uid=f"res-{i}",
            target_type=target_type,
            principal="bob",
            detail=canonical_json({"mask": 1024}),
            prev_hash=prev,
            global_tenant=tenant_key,
        )
        rec.hash = rec.recompute_hash(prev)
        records.append(rec)
        prev = rec.hash
    return records


@pytest.fixture()
def cursor_store(pg_conn):
    store = CursorStore()
    store.ensure_schema(pg_conn)
    pg_conn.commit()
    yield store
    with pg_conn.cursor() as cur:
        # LIKE pattern passed as a parameter: psycopg reads a bare %' in the
        # SQL text as a malformed placeholder.
        cur.execute("DELETE FROM accountability_cursor "
                    "WHERE tenant LIKE %s OR tenant = %s",
                    ("audit_it_%", GLOBAL_CHAIN_KEY))
    pg_conn.commit()


def _rows(pg_conn, tenant):
    """(action, detail) per row in insert order. psycopg hands JSONB back already
    parsed, so detail is a dict here, not text."""
    schema = schema_for_tenant(tenant)
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT action, detail FROM "{schema}".audit_log ORDER BY seq')
        return cur.fetchall()


# ── the drain ──────────────────────────────────────────────────────────────

def test_drain_appends_every_record_and_advances_the_cursor(
        config, pg_conn, audit_schema, cursor_store):
    core = FakeCore({audit_schema: build_chain(5)})
    puller = AccountabilityPuller(config, core, cursor_store)

    assert puller.drain(pg_conn, audit_schema, {}) == 5
    pg_conn.commit()

    rows = _rows(pg_conn, audit_schema)
    assert len(rows) == 5
    assert all(r[0] == "acl.grant" for r in rows)
    # The seq travels into detail, so a row can be traced back to its core record.
    assert [r[1]["accountability_seq"] for r in rows] == [1, 2, 3, 4, 5]

    state = cursor_store.get(pg_conn, audit_schema)
    assert state.last_seq == 5
    assert state.recorded_until_micros == BASE_TS + 4


def test_a_second_drain_delivers_nothing_new(config, pg_conn, audit_schema, cursor_store):
    core = FakeCore({audit_schema: build_chain(3)})
    puller = AccountabilityPuller(config, core, cursor_store)
    assert puller.drain(pg_conn, audit_schema, {}) == 3
    pg_conn.commit()

    # Exactly-once: the cursor is a strictly-greater-than watermark, so a
    # caught-up consumer re-reading sees nothing rather than the last record again.
    assert puller.drain(pg_conn, audit_schema, {}) == 0
    pg_conn.commit()
    assert len(_rows(pg_conn, audit_schema)) == 3


def test_drain_pages_through_a_backlog(config, pg_conn, audit_schema, cursor_store):
    core = FakeCore({audit_schema: build_chain(7)}, page_size=3)
    puller = AccountabilityPuller(config, core, cursor_store)
    assert puller.drain(pg_conn, audit_schema, {}) == 7
    pg_conn.commit()
    assert len(_rows(pg_conn, audit_schema)) == 7
    # Each page resumed from the previous page's watermark, not from zero.
    cursors = [c for _t, c in core.calls]
    assert cursors == sorted(cursors) and cursors[0] == 0


def test_a_reset_cursor_replays_the_whole_history(
        config, pg_conn, audit_schema, cursor_store):
    """Rebuild-from-zero — impossible when the record's only home was a stream
    that trims. Re-appending is a no-op because (event_id, ts) is derived from
    (tenant, seq)."""
    core = FakeCore({audit_schema: build_chain(4)})
    puller = AccountabilityPuller(config, core, cursor_store)
    puller.drain(pg_conn, audit_schema, {})
    pg_conn.commit()

    cursor_store.reset(pg_conn, audit_schema)
    pg_conn.commit()
    assert puller.drain(pg_conn, audit_schema, {}) == 4
    pg_conn.commit()
    assert len(_rows(pg_conn, audit_schema)) == 4, "replay must not duplicate rows"


# ── integrity: raised, not absorbed ────────────────────────────────────────

def test_a_gap_halts_the_tenant_and_does_not_advance(
        config, pg_conn, audit_schema, cursor_store):
    chain = build_chain(4)
    del chain[2]                                  # a record went missing
    core = FakeCore({audit_schema: chain})
    puller = AccountabilityPuller(config, core, cursor_store)

    with pytest.raises(IntegrityBreak):
        puller.drain(pg_conn, audit_schema, {})
    pg_conn.rollback()

    # Nothing was recorded and the cursor did not move: draining past an
    # unacknowledged break is what turns a detectable failure into silent loss.
    state = cursor_store.get(pg_conn, audit_schema)
    assert state.last_seq == 0
    # The halt SURVIVED the rollback, because it was committed on its own
    # connection. Staging it in the doomed transaction would have lost the alarm
    # at the exact moment it was raised.
    assert state.halted and "contiguous" in state.halted_reason
    assert state.halted_seq == 4

    # And it stays halted — a later clean read does not quietly resume.
    core.chains[audit_schema] = build_chain(4)
    assert puller.drain(pg_conn, audit_schema, {}) == 0


def test_a_halt_outlives_the_process_that_raised_it(
        config, pg_conn, audit_schema, cursor_store):
    """An alarm a restart clears is not an alarm.

    A fresh puller — standing in for the service coming back up — must still
    refuse to drain, because the halt is a row rather than a dictionary that
    died with the last process.
    """
    chain = build_chain(3)
    del chain[1]
    core = FakeCore({audit_schema: chain})
    with pytest.raises(IntegrityBreak):
        AccountabilityPuller(config, core, cursor_store).drain(pg_conn, audit_schema, {})
    pg_conn.rollback()

    restarted = AccountabilityPuller(config, FakeCore({audit_schema: build_chain(3)}),
                                     CursorStore())
    assert restarted.drain(pg_conn, audit_schema, {}) == 0
    assert _rows(pg_conn, audit_schema) == []


def test_only_an_explicit_acknowledgement_resumes_the_drain(
        config, pg_conn, audit_schema, cursor_store):
    """The point of the halt is that a human decides the chain is trustworthy
    again. Nothing else clears it, and draining resumes from the cursor — which
    never moved, so nothing was skipped."""
    broken = build_chain(3)
    del broken[1]
    core = FakeCore({audit_schema: broken})
    puller = AccountabilityPuller(config, core, cursor_store)
    with pytest.raises(IntegrityBreak):
        puller.drain(pg_conn, audit_schema, {})
    pg_conn.rollback()

    core.chains[audit_schema] = build_chain(3)     # the underlying issue is resolved
    assert puller.drain(pg_conn, audit_schema, {}) == 0, "still halted"

    assert puller.acknowledge(pg_conn, audit_schema) is True
    pg_conn.commit()
    assert puller.drain(pg_conn, audit_schema, {}) == 3
    pg_conn.commit()
    assert len(_rows(pg_conn, audit_schema)) == 3
    # Acknowledging a chain that is not halted is a no-op, not an error.
    assert puller.acknowledge(pg_conn, audit_schema) is False


def test_the_first_break_is_the_one_kept(config, pg_conn, audit_schema, cursor_store):
    """Once a chain is broken every later row fails too. Overwriting would
    replace the diagnosis with a symptom and move the seq an operator needs.

    Exercised against the store directly: the drain itself short-circuits on an
    existing halt, so a second break can only reach the store by another route
    (a second consumer instance, a concurrent poll) — which is exactly the case
    the COALESCE is there for.
    """
    cursor_store.halt(pg_conn, audit_schema, 3, "seq is not contiguous (expected 2)")
    cursor_store.halt(pg_conn, audit_schema, 4, "prev_hash does not match")
    cursor_store.halt(pg_conn, audit_schema, 5, "hash does not recompute")
    pg_conn.commit()

    state = cursor_store.get(pg_conn, audit_schema)
    assert state.halted_seq == 3, "the earliest break, not the latest"
    assert "contiguous" in state.halted_reason, "the diagnosis, not a later symptom"


def test_a_halted_chain_short_circuits_before_it_reads_the_core(
        config, pg_conn, audit_schema, cursor_store):
    """A halt stops the drain at the door. It does not fetch, verify and then
    decline — a halted chain should cost nothing per poll."""
    cursor_store.halt(pg_conn, audit_schema, 2, "prev_hash does not match")
    pg_conn.commit()
    core = FakeCore({audit_schema: build_chain(3)})
    puller = AccountabilityPuller(config, core, cursor_store)
    assert puller.drain(pg_conn, audit_schema, {}) == 0
    assert core.calls == [], "no read was issued for a halted chain"


def test_a_halted_tenant_does_not_stop_the_others(
        config, pg_conn, audit_schema, cursor_store):
    other = f"audit_it_other_{os.getpid()}"
    schema = schema_for_tenant(other)
    with pg_conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        cur.execute(f'CREATE SCHEMA "{schema}"')
        from .conftest import AUDIT_LOG_DDL
        cur.execute(AUDIT_LOG_DDL.format(schema=schema))
        cur.execute("INSERT INTO tenants (tenant_id, schema_name) VALUES (%s, %s) "
                    "ON CONFLICT (tenant_id) DO NOTHING", (other, schema))
    pg_conn.commit()
    try:
        broken = build_chain(3)
        del broken[1]
        core = FakeCore({audit_schema: broken, other: build_chain(2)})
        puller = AccountabilityPuller(config, core, cursor_store)
        cursor_store.halt(pg_conn, audit_schema, 2, "pre-halted")
        pg_conn.commit()

        # Per-tenant isolation applies to failures too.
        assert puller.drain(pg_conn, other, {}) == 2
        pg_conn.commit()
        assert len(_rows(pg_conn, other)) == 2
    finally:
        with pg_conn.cursor() as cur:
            cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (other,))
            cur.execute("DELETE FROM accountability_cursor WHERE tenant = %s", (other,))
        pg_conn.commit()


def test_a_hint_the_read_cannot_see_raises_rather_than_advancing(
        config, pg_conn, audit_schema, cursor_store):
    core = FakeCore({audit_schema: build_chain(2)})
    puller = AccountabilityPuller(config, core, cursor_store)
    with pytest.raises(StaleRead):
        puller.drain(pg_conn, audit_schema, {}, asserted_seq=5)
    pg_conn.rollback()
    state = cursor_store.get(pg_conn, audit_schema)
    assert state.last_seq == 0
    # Stale is NOT tampering, so the chain is not halted — it retries. Halting
    # here would take a tenant offline for ordinary replication lag.
    assert not state.halted


# ── tenant destruction (§7.3) ──────────────────────────────────────────────

def test_a_tenant_deletion_drops_the_cursor_and_purges_retained_records(
        config, pg_conn, audit_schema, cursor_store, global_table):
    """Without this the service polls a vanished schema forever and silently
    retains history the platform believes it destroyed."""
    doomed = f"audit_it_doomed_{os.getpid()}"
    # Something we retained for that tenant, plus its cursor.
    cursor_store.stage(pg_conn, doomed, cursor_store.get(pg_conn, doomed))
    with pg_conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS audit_log_global_p20260827 PARTITION OF "
            "audit_log_global FOR VALUES FROM ('2026-08-27 00:00:00+00') "
            "TO ('2026-08-28 00:00:00+00')")
        for action in ("acl_grant", "tenant.create"):
            cur.execute(
                "INSERT INTO audit_log_global "
                "(event_id, ts, category, action, outcome, actor, tenant) "
                "VALUES (%s::uuid, '2026-08-27 10:00:00+00', 5, %s, 0, 'root', %s)",
                (str(uuid.uuid4()), action, doomed))
    pg_conn.commit()

    core = FakeCore({GLOBAL_CHAIN_KEY: build_chain(
        1, tenant_key=doomed, action="tenant.delete", category="destruction",
        target_type="tenant")})
    puller = AccountabilityPuller(config, core, cursor_store)
    assert puller.drain(pg_conn, None, {}) == 1
    pg_conn.commit()

    with pg_conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM accountability_cursor WHERE tenant = %s",
                    (doomed,))
        assert cur.fetchone()[0] == 0, "the cursor is dropped, so polling stops"
        cur.execute("SELECT action FROM audit_log_global WHERE tenant = %s "
                    "ORDER BY action", (doomed,))
        remaining = [r[0] for r in cur.fetchall()]
    # The contents are gone; the fact that the tenant existed and was removed is
    # what survives, in a place the deleter cannot reach.
    assert "acl_grant" not in remaining
    assert "tenant.create" in remaining and "tenant.delete" in remaining

    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM audit_log_global WHERE tenant = %s", (doomed,))
    pg_conn.commit()


# ── precedence (§4.3.3) ────────────────────────────────────────────────────

def test_core_records_are_recorded_ahead_of_a_queue_event(
        config, pg_conn, audit_schema, cursor_store):
    """The core is the anchor everything else is sequenced against.

    A tamper-evident chain records the order in which it was written and cannot
    be re-sorted afterwards, so appending a subsystem event while older core
    records are still unread would place them out of order permanently.
    """
    from audit_service.consumer import AuditConsumer
    from audit_service.envelope import parse_envelope

    core = FakeCore({audit_schema: build_chain(3)})
    puller = AccountabilityPuller(config, core, cursor_store)
    consumer = AuditConsumer(config, connect_fn=lambda: pg_conn, puller=puller)

    queue_event = parse_envelope({
        "event_id": str(uuid.uuid4()), "ts": "2026-08-27T10:00:00Z",
        "tenant": audit_schema, "category": "auth", "action": "login_failure",
        "outcome": "denied", "actor": "mallory"})

    consumer._drain_core_first(pg_conn, [queue_event])
    from audit_service.writer import write_batch
    write_batch(pg_conn, [queue_event], consumer._heads)
    pg_conn.commit()

    actions = [r[0] for r in _rows(pg_conn, audit_schema)]
    assert actions == ["acl.grant", "acl.grant", "acl.grant", "login_failure"], \
        "all pending core records precede the queue event — a full drain, not a partial one"


def test_an_unreachable_core_blocks_recording_rather_than_reordering(
        config, pg_conn, audit_schema, cursor_store):
    """Recording without draining would break the ordering guarantee.

    This costs nothing in practice: a core outage already stops the platform —
    feature services fail closed without it and the bridges have nothing to
    serve — so there is no work being lost that the sink would otherwise record.
    """
    from audit_service.consumer import AuditConsumer
    from audit_service.envelope import parse_envelope

    puller = AccountabilityPuller(config, UnreachableCore(), cursor_store)
    consumer = AuditConsumer(config, connect_fn=lambda: pg_conn, puller=puller)
    queue_event = parse_envelope({
        "event_id": str(uuid.uuid4()), "ts": "2026-08-27T10:00:00Z",
        "tenant": audit_schema, "category": "auth", "action": "login_failure",
        "outcome": "denied", "actor": "mallory"})

    with pytest.raises(Exception):
        consumer._drain_core_first(pg_conn, [queue_event])
    pg_conn.rollback()
    assert _rows(pg_conn, audit_schema) == []


def test_the_global_chain_is_drained_before_tenant_chains(
        config, pg_conn, audit_schema, cursor_store):
    """It carries tenant deletions, so acting on one before draining a tenant we
    are about to forget avoids re-creating that cursor moments after dropping it."""
    from audit_service.consumer import AuditConsumer
    from audit_service.envelope import parse_envelope

    core = FakeCore({audit_schema: build_chain(1), GLOBAL_CHAIN_KEY: []})
    puller = AccountabilityPuller(config, core, cursor_store)
    consumer = AuditConsumer(config, connect_fn=lambda: pg_conn, puller=puller)
    queue_event = parse_envelope({
        "event_id": str(uuid.uuid4()), "ts": "2026-08-27T10:00:00Z",
        "tenant": audit_schema, "category": "auth", "action": "login_failure",
        "outcome": "denied", "actor": "mallory"})
    consumer._drain_core_first(pg_conn, [queue_event])
    pg_conn.commit()
    assert core.calls[0][0] == GLOBAL_CHAIN_KEY
