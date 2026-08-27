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

"""The consumer side of the core's accountability record (§4.3).

Two things are under test, and the first matters more than it looks:

1. **The canonical form and chain hash are a cross-repo contract.** The core
   computes them in C++; we recompute them here to verify every record we read.
   If the two ever disagree, nothing fails subtly — every verification in the
   platform starts failing. Both sides pin the SAME literal digest, computed
   independently, so a drift shows up as a test failure on whichever side moved.

2. **Integrity breaks must be raised, not absorbed.** A consumer that skips a gap
   to keep draining converts a detectable failure into silent data loss, which is
   the exact failure the record exists to prevent. Every §4.3.2 check is tested
   for the alarm, not just for the happy path.
"""
from __future__ import annotations

import json

import pytest

from audit_service.accountability import (GLOBAL_CHAIN_KEY, CoreRecord, IntegrityBreak,
                                          StaleRead, canonical_json, canonical_record,
                                          chain_hash, datetime_to_micros,
                                          micros_to_datetime, verify_batch)

# The same record the core's tests pin, field for field.
SAMPLE_DETAIL = canonical_json({"effect": "allow", "mask": 1024, "mask_after": 1024,
                                "mask_before": 0, "principal_type": 0})
SAMPLE_TS_MICROS = 1756296000123456


def make_record(seq=1, ts_micros=SAMPLE_TS_MICROS, prev_hash=None, **overrides):
    """Build a record and give it the hash the core would have computed."""
    rec = CoreRecord(
        seq=seq,
        ts_micros=ts_micros,
        ts=micros_to_datetime(ts_micros),
        actor=overrides.pop("actor", "alice"),
        actor_roles=overrides.pop("actor_roles", ["editors", "tenant_admin"]),
        source_iface=overrides.pop("source_iface", "grpc"),
        source_addr=overrides.pop("source_addr", "10.0.0.7"),
        category=overrides.pop("category", "authorization"),
        action=overrides.pop("action", "acl.grant"),
        target_uid=overrides.pop("target_uid", "f4c1a2"),
        target_type=overrides.pop("target_type", "acl"),
        principal=overrides.pop("principal", "bob"),
        detail=overrides.pop("detail", SAMPLE_DETAIL),
        prev_hash=prev_hash,
        global_tenant=overrides.pop("global_tenant", ""),
    )
    rec.hash = rec.recompute_hash(prev_hash)
    return rec


def make_chain(n: int, start_seq: int = 1, start_ts: int = SAMPLE_TS_MICROS):
    records, prev = [], None
    for i in range(n):
        rec = make_record(seq=start_seq + i, ts_micros=start_ts + i, prev_hash=prev)
        records.append(rec)
        prev = rec.hash
    return records


# ── the cross-repo contract ────────────────────────────────────────────────

def test_canonical_form_is_pinned():
    canonical = canonical_record(
        seq=1, ts_micros=SAMPLE_TS_MICROS, actor="alice",
        actor_roles=["editors", "tenant_admin"], source_iface="grpc",
        source_addr="10.0.0.7", category="authorization", action="acl.grant",
        target_uid="f4c1a2", target_type="acl", principal="bob",
        detail=SAMPLE_DETAIL, tenant=None)
    assert canonical == (
        b'[1,1756296000123456,"alice","editors,tenant_admin","grpc","10.0.0.7",'
        b'"authorization","acl.grant","f4c1a2","acl","bob",'
        b'"{\\"effect\\":\\"allow\\",\\"mask\\":1024,\\"mask_after\\":1024,'
        b'\\"mask_before\\":0,\\"principal_type\\":0}",null]')


def test_chain_hash_matches_the_cores_pinned_value():
    """The same digest ``tests/accountability_tests.cpp`` asserts in the core.

    This is the single assertion that catches a drift between the C++ and Python
    derivations before it reaches production as a wall of failed verifications.
    """
    canonical = canonical_record(
        seq=1, ts_micros=SAMPLE_TS_MICROS, actor="alice",
        actor_roles=["editors", "tenant_admin"], source_iface="grpc",
        source_addr="10.0.0.7", category="authorization", action="acl.grant",
        target_uid="f4c1a2", target_type="acl", principal="bob",
        detail=SAMPLE_DETAIL, tenant=None)
    assert chain_hash(None, canonical).hex() == (
        "fca7490691846d76f9b76ce67b29c266e7da09ca7f5adeb0c6ad2e06ff7eeb54")


def test_absent_fields_are_null_not_empty_string():
    """"No principal" and "the principal named empty-string" must not collide."""
    with_none = canonical_record(
        seq=1, ts_micros=1, actor="a", actor_roles=[], source_iface=None,
        source_addr=None, category="identity", action="role.create",
        target_uid=None, target_type=None, principal=None, detail=None, tenant=None)
    assert with_none == b'[1,1,"a",null,null,null,"identity","role.create",null,null,null,null,null]'


def test_tenant_is_hashed_only_for_global_rows():
    """A tenant-scoped chain must be verifiable from its own data alone.

    Its tenant is implicit in the schema it lives in, and the schema name is not
    reversible to the tenant id — so hashing it there would make the chain
    unverifiable. The global chain spans tenants, so there it is a real column.
    """
    scoped = canonical_record(
        seq=1, ts_micros=1, actor="root", actor_roles=[], source_iface=None,
        source_addr=None, category="lifecycle", action="tenant.create",
        target_uid=None, target_type="tenant", principal=None,
        detail=None, tenant=None)
    glob = canonical_record(
        seq=1, ts_micros=1, actor="root", actor_roles=[], source_iface=None,
        source_addr=None, category="lifecycle", action="tenant.create",
        target_uid=None, target_type="tenant", principal=None,
        detail=None, tenant="acme")
    assert scoped != glob
    assert glob.endswith(b'"acme"]')


def test_micros_round_trip():
    ts = micros_to_datetime(SAMPLE_TS_MICROS)
    assert datetime_to_micros(ts) == SAMPLE_TS_MICROS


def test_event_id_is_deterministic_per_tenant_and_seq():
    """(tenant, seq) is the idempotency key, so a re-drain must re-derive it.

    That is what makes redelivery after a crash a no-op instead of a duplicate
    row — the audit table's UNIQUE (event_id, ts) absorbs it.
    """
    a = make_record(seq=5)
    b = make_record(seq=5)
    assert a.event_id == b.event_id
    assert make_record(seq=6).event_id != a.event_id
    # Different chains with the same seq are different records.
    assert make_record(seq=5, global_tenant="acme").event_id != a.event_id


# ── verification: the happy path ───────────────────────────────────────────

def test_a_clean_batch_verifies():
    verify_batch("acme", make_chain(5), last_seq=None, last_hash=None,
                 last_ts_micros=None)


def test_verification_resumes_from_a_stored_cursor():
    """The second page must chain onto the first without re-reading it."""
    first = make_chain(3)
    prev = first[-1]
    second = []
    prev_hash = prev.hash
    for i in range(3):
        rec = make_record(seq=4 + i, ts_micros=prev.ts_micros + 1 + i, prev_hash=prev_hash)
        second.append(rec)
        prev_hash = rec.hash
    verify_batch("acme", second, last_seq=prev.seq, last_hash=prev.hash,
                 last_ts_micros=prev.ts_micros)


def test_an_empty_batch_verifies():
    verify_batch("acme", [], last_seq=7, last_hash=b"x" * 32, last_ts_micros=100)


# ── verification: every break is an alarm ──────────────────────────────────

def test_a_gap_in_seq_is_an_integrity_break():
    """Under the core's chain lock a gap CANNOT occur naturally.

    A rolled-back transaction releases the lock without advancing last_seq, so
    numbers are never burned — which is exactly what makes a missing number an
    unambiguous alarm rather than routine noise to be tolerated.
    """
    records = make_chain(3)
    del records[1]
    with pytest.raises(IntegrityBreak) as e:
        verify_batch("acme", records, last_seq=None, last_hash=None, last_ts_micros=None)
    assert "contiguous" in str(e.value)
    assert e.value.tenant == "acme"


def test_a_non_increasing_ts_is_an_integrity_break():
    """ts is the cursor axis; if it stops increasing the cursor stops being exact."""
    records = make_chain(3)
    records[2].ts_micros = records[1].ts_micros      # duplicate, not increasing
    records[2].hash = records[2].recompute_hash(records[1].hash)
    with pytest.raises(IntegrityBreak) as e:
        verify_batch("acme", records, last_seq=None, last_hash=None, last_ts_micros=None)
    assert "did not increase" in str(e.value)


def test_a_broken_link_is_an_integrity_break():
    records = make_chain(3)
    records[2].prev_hash = b"\x00" * 32
    with pytest.raises(IntegrityBreak) as e:
        verify_batch("acme", records, last_seq=None, last_hash=None, last_ts_micros=None)
    assert "prev_hash" in str(e.value)


def test_an_altered_row_is_an_integrity_break():
    """Editing a committed row after the fact must not survive the next read."""
    records = make_chain(3)
    records[1].actor = "mallory"                     # hash left as it was
    with pytest.raises(IntegrityBreak) as e:
        verify_batch("acme", records, last_seq=None, last_hash=None, last_ts_micros=None)
    assert "does not recompute" in str(e.value)


def test_a_reordered_batch_is_an_integrity_break():
    """A transport that reorders is caught by the same mechanism as tampering."""
    records = make_chain(3)
    records[1], records[2] = records[2], records[1]
    with pytest.raises(IntegrityBreak):
        verify_batch("acme", records, last_seq=None, last_hash=None, last_ts_micros=None)


def test_a_duplicated_record_is_an_integrity_break():
    records = make_chain(3)
    records.insert(2, records[1])
    with pytest.raises(IntegrityBreak):
        verify_batch("acme", records, last_seq=None, last_hash=None, last_ts_micros=None)


def test_a_hint_the_read_cannot_see_is_a_stale_read_not_a_break():
    """Stale is not tampering, and must not be treated as one.

    A hint asserts "at least seq N exists". If the read does not show N we are
    reading state that has not caught up — a replica behind the primary being the
    obvious case. Retry; do not advance. Without the assertion this is invisible,
    because it looks identical to "no new records".
    """
    records = make_chain(3)
    with pytest.raises(StaleRead):
        verify_batch("acme", records, last_seq=None, last_hash=None,
                     last_ts_micros=None, asserted_seq=9)
    # And a satisfied assertion passes.
    verify_batch("acme", records, last_seq=None, last_hash=None,
                 last_ts_micros=None, asserted_seq=3)


def test_a_stale_read_with_no_records_at_all_is_still_raised():
    """The case the assertion exists for: an empty read that should not be empty."""
    with pytest.raises(StaleRead):
        verify_batch("acme", [], last_seq=None, last_hash=None,
                     last_ts_micros=None, asserted_seq=4)


# ── mapping onto the audit chain ───────────────────────────────────────────

def test_core_record_maps_onto_an_audit_row():
    from audit_service import codes
    from audit_service.puller import _to_audit_row

    row = _to_audit_row(make_record(), "acme")
    assert row.scope == "tenant" and row.tenant == "acme"
    assert row.category == codes.CATEGORY["permission"]   # authorization -> permission
    assert row.action == "acl.grant"
    assert row.outcome == codes.OUTCOME["ok"]
    assert row.actor == "alice"
    assert row.actor_roles == "editors,tenant_admin"
    assert row.target_uid == "f4c1a2"
    assert row.target_type == codes.TARGET_TYPE["acl"]
    # The seq travels, so an auditor can go from an audit row back to the exact
    # core record and re-verify it independently.
    detail = json.loads(row.detail)
    assert detail["accountability_seq"] == 1
    assert detail["principal"] == "bob"
    assert detail["detail"]["mask"] == 1024


def test_the_mapped_row_carries_no_name():
    """§5.4.7: the chain records identifiers and structure, never payload.

    A filename is party data, and this log is immutable and long-lived, so a name
    recorded here is one the platform has committed to keeping and cannot easily
    remove on request. The uid travels; a viewer resolves the name at read time,
    and after an erasure that join finds nothing.
    """
    from audit_service.puller import _to_audit_row
    row = _to_audit_row(make_record(), "acme")
    assert row.target_name is None
    # And nothing name-shaped leaked into detail either.
    assert "name" not in json.loads(row.detail)


def test_every_core_category_maps_somewhere():
    from audit_service.puller import _CATEGORY
    from audit_service import codes
    for core_category in ("authorization", "identity", "destruction", "lifecycle"):
        assert core_category in _CATEGORY
        assert _CATEGORY[core_category] in codes.CATEGORY


def test_global_records_map_to_the_global_scope():
    from audit_service.puller import _to_audit_row
    rec = make_record(category="lifecycle", action="tenant.create",
                      target_type="tenant", global_tenant="acme", principal="")
    row = _to_audit_row(rec, None)
    assert row.scope == "global"
    # The global table carries the tenant as a column — the record is ABOUT a
    # tenant, it does not belong to one.
    assert row.tenant == "acme"


def test_the_global_chain_key_is_reserved():
    """No real tenant can collide with it: the core strips '*' from schema names."""
    from audit_service.naming import schema_for_tenant
    assert "*" in GLOBAL_CHAIN_KEY
    assert "*" not in schema_for_tenant(GLOBAL_CHAIN_KEY)
