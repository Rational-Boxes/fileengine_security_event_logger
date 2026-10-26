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

"""Accountability retention without a database (SPEC §14): the row mapping must
reproduce the core's hash exactly, and the walker must catch every break."""
from datetime import datetime, timedelta, timezone

from audit_service.accountability import canonical_json, canonical_record, chain_hash
from audit_service.accountability_retention import (AccWalker, acc_scope_for, record_from_dict,
                                                     row_to_dict, table_for_cursor_key)
from audit_service.config import Config

T0 = datetime(2026, 6, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


def core_rows(n, *, tenant=None, details=None):
    """Rows as Postgres returns them, hashed the way the core hashes them."""
    out, prev = [], None
    for i in range(n):
        seq, ts = i + 1, T0 + timedelta(seconds=i, microseconds=i)
        detail = (details or {}).get(seq, {"permissions": 7, "recursive": True})
        micros = (ts - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(microseconds=1)
        h = chain_hash(prev, canonical_record(
            seq=seq, ts_micros=micros, actor="alice", actor_roles=["admin", "user"],
            source_iface="grpc", source_addr=None, category="authorization",
            action="acl.grant", target_uid=f"uid{seq}", target_type="file", principal="bob",
            detail=canonical_json(detail) if detail else None, tenant=tenant))
        row = (seq, ts, "alice", ["admin", "user"], "grpc", None, "authorization", "acl.grant",
               f"uid{seq}", "file", "bob", detail, prev, h)
        out.append(row + ((tenant,) if tenant is not None else ()))
        prev = h
    return out


def test_db_rows_recompute_the_core_hash():
    rows = [row_to_dict(r, False) for r in core_rows(4)]
    walker = AccWalker("t", None, 0)
    assert all(walker.step(r) for r in rows)
    assert walker.prev == bytes.fromhex(rows[-1]["row_hash"])


def test_global_rows_hash_the_tenant_column():
    rows = [row_to_dict(r, True) for r in core_rows(3, tenant="acme")]
    assert rows[0]["tenant"] == "acme"
    walker = AccWalker("*global*", None, 0)
    assert all(walker.step(r) for r in rows)


def test_an_empty_detail_is_the_cores_null():
    rows = [row_to_dict(r, False) for r in core_rows(2, details={1: {}})]
    assert record_from_dict(rows[0]).detail == ""
    walker = AccWalker("t", None, 0)
    assert all(walker.step(r) for r in rows)


def test_the_walker_catches_a_gap_an_edit_and_a_missing_genesis():
    rows = [row_to_dict(r, False) for r in core_rows(5)]
    gap = AccWalker("t", None, 0)
    for r in rows[:2] + rows[3:]:
        gap.step(r)
    assert not gap.ok and gap.broken_seq == 4 and "contiguous" in gap.reason

    edited = dict(rows[2], actor="mallory")
    w = AccWalker("t", None, 0)
    for r in rows[:2] + [edited] + rows[3:]:
        w.step(r)
    assert w.broken_seq == 3 and "recompute" in w.reason

    # Starting mid-chain without the anchor's link is a break, not a genesis.
    headless = AccWalker("t", None, 0)
    headless.step(rows[2])
    assert not headless.ok


def test_the_walker_continues_from_an_anchor():
    rows = [row_to_dict(r, False) for r in core_rows(5)]
    w = AccWalker("t", bytes.fromhex(rows[1]["row_hash"]), 2, rows[1]["ts_micros"])
    assert all(w.step(r) for r in rows[2:])


def test_scopes_and_cursor_keys():
    cfg = Config()
    s = acc_scope_for("acme", cfg)
    assert (s.scope_id, s.table, s.cursor_key) == ("acme", '"tenant_acme".accountability_record',
                                                   "acme")
    g = acc_scope_for(None, cfg)
    assert (g.scope_id, g.table, g.cursor_key) == ("_global", "accountability_record_global",
                                                   "*global*")
    assert table_for_cursor_key("acme") == s.table
    assert table_for_cursor_key("*global*") == g.table
