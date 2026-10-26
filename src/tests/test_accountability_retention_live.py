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

"""The accountability record's lifecycle, simulated (SPEC §14).

A throwaway tenant schema gets the core's own ``accountability_record`` DDL and
rows hashed exactly as the core hashes them; retention then runs on simulated
1sts. Checked: only aged rows the puller has copied go; a halted, absent or
lagging cursor holds rows back; a tampered row refuses the whole scope; the
archive and the surviving table verify end to end from the anchor; a puller
rebuilt from an empty cursor resumes from that anchor.

Uses the ``cfg`` fixture of the audit lifecycle suite (local + S3 variants).
"""
from __future__ import annotations

from datetime import date, datetime, timezone

import pytest

from audit_service import catalog
from audit_service import accountability_retention as acc
from audit_service.accountability import canonical_json, canonical_record, chain_hash
from audit_service.archive import ArchiveError, make_archive, make_cipher
from audit_service.cursors import CursorState, CursorStore
from audit_service.naming import schema_for_tenant
from audit_service.puller import AccountabilityPuller
from audit_service.retention import run_all

from .test_retention_lifecycle_live import _clear_catalog, cfg  # noqa: F401  (fixture)

pytestmark = pytest.mark.live

ACC_DDL = """
CREATE TABLE IF NOT EXISTS "{schema}".accountability_record (
    seq          BIGINT       PRIMARY KEY,
    ts           TIMESTAMPTZ  NOT NULL,
    actor        VARCHAR(255) NOT NULL,
    actor_roles  TEXT[],
    source_iface VARCHAR(32),
    source_addr  VARCHAR(64),
    category     VARCHAR(32)  NOT NULL,
    action       VARCHAR(64)  NOT NULL,
    target_uid   VARCHAR(64),
    target_type  VARCHAR(32),
    principal    VARCHAR(255),
    detail       JSONB        NOT NULL DEFAULT '{{}}'::jsonb,
    prev_hash    BYTEA,
    hash         BYTEA        NOT NULL
)"""


@pytest.fixture()
def acc_tenant(pg_conn, audit_schema, config):
    """The throwaway tenant (from ``audit_schema``) with an accountability table,
    a clean catalog and no puller cursor."""
    scope = acc.acc_scope_for(audit_schema, config)
    CursorStore().ensure_schema(pg_conn)
    with pg_conn.cursor() as cur:
        cur.execute(ACC_DDL.format(schema=schema_for_tenant(audit_schema)))
        cur.execute("DELETE FROM accountability_cursor WHERE tenant = %s", (audit_schema,))
    pg_conn.commit()
    _clear_catalog(pg_conn, scope.table)
    yield audit_schema
    _clear_catalog(pg_conn, scope.table)
    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM accountability_cursor WHERE tenant = %s", (audit_schema,))
    pg_conn.commit()


def append(conn, table, day_iso, n):
    """Append n records the way the core does: next seq, strictly later ts,
    hash = SHA-256(prev ‖ canonical)."""
    with conn.cursor() as cur:
        cur.execute(f"SELECT seq, hash FROM {table} ORDER BY seq DESC LIMIT 1")
        last = cur.fetchone()
        seq, prev = (last[0], bytes(last[1])) if last else (0, None)
        for i in range(n):
            seq += 1
            ts = datetime.fromisoformat(f"{day_iso}T10:00:{i:02d}.{seq:06d}+00:00")
            micros = acc._micros(ts)
            detail = {"permissions": 7, "recursive": i % 2 == 0}
            h = chain_hash(prev, canonical_record(
                seq=seq, ts_micros=micros, actor="alice", actor_roles=["admin"],
                source_iface="grpc", source_addr="10.0.0.1", category="authorization",
                action="acl.grant", target_uid=f"u{seq}", target_type="file",
                principal="bob", detail=canonical_json(detail), tenant=None))
            cur.execute(f"INSERT INTO {table} (seq, ts, actor, actor_roles, source_iface, "
                        "source_addr, category, action, target_uid, target_type, principal, "
                        "detail, prev_hash, hash) VALUES (%s,%s,'alice',ARRAY['admin'],'grpc',"
                        "'10.0.0.1','authorization','acl.grant',%s,'file','bob',%s,%s,%s)",
                        (seq, ts, f"u{seq}", canonical_json(detail), prev, h))
            prev = h
    conn.commit()
    return seq


def set_cursor(conn, tenant, last_seq, halted=None):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO accountability_cursor (tenant, last_seq, halted_reason) "
                    "VALUES (%s, %s, %s) ON CONFLICT (tenant) DO UPDATE SET "
                    "last_seq = EXCLUDED.last_seq, halted_reason = EXCLUDED.halted_reason",
                    (tenant, last_seq, halted))
    conn.commit()


def seqs(conn, table):
    with conn.cursor() as cur:
        cur.execute(f"SELECT seq FROM {table} ORDER BY seq")
        out = [r[0] for r in cur.fetchall()]
    conn.rollback()
    return out


def run(conn, cfg, tenant, today, **kw):
    results, failures = run_all(conn, cfg, today=today, scopes=[],
                                acc_scopes=[acc.acc_scope_for(tenant, cfg)], **kw)
    assert not failures, failures
    return results[0]


def verify(conn, cfg, scope):
    return acc.verify_acc_archive(conn, make_archive(cfg), make_cipher(cfg.archive_key), scope)


def test_monthly_lifecycle(pg_conn, acc_tenant, cfg):
    scope = acc.acc_scope_for(acc_tenant, cfg)
    append(pg_conn, scope.table, "2026-06-10", 3)     # seq 1-3
    append(pg_conn, scope.table, "2026-07-15", 2)     # 4-5
    append(pg_conn, scope.table, "2026-08-20", 2)     # 6-7
    head = append(pg_conn, scope.table, "2026-09-02", 1)  # 8
    set_cursor(pg_conn, acc_tenant, head)

    r = run(pg_conn, cfg, acc_tenant, date(2026, 9, 1))   # cutoff 2026-07-01
    assert (r["rows"], r["first_seq"], r["last_seq"], r["held"]) == (3, 1, 3, None)
    assert r["parts"] == 2                                 # part_rows=2
    assert seqs(pg_conn, scope.table) == [4, 5, 6, 7, 8]
    a = catalog.anchor(pg_conn, scope.table)
    pg_conn.rollback()
    assert a.last_seq == 3
    v = verify(pg_conn, cfg, scope)
    assert v.ok and v.starts_at_genesis and v.rows == 3 and v.db["ok"], v

    r = run(pg_conn, cfg, acc_tenant, date(2026, 10, 1))  # cutoff 2026-08-01
    assert (r["rows"], r["first_seq"], r["last_seq"]) == (2, 4, 5)
    assert seqs(pg_conn, scope.table) == [6, 7, 8]
    assert run(pg_conn, cfg, acc_tenant, date(2026, 10, 1))["rows"] == 0   # idempotent
    v = verify(pg_conn, cfg, scope)
    assert v.ok and v.rows == 5 and v.db["ok"] and v.db["checked"] == 3, v

    exported = list(acc.export_acc_rows(pg_conn, make_archive(cfg),
                                        make_cipher(cfg.archive_key), scope))
    assert [x["seq"] for x in exported] == [1, 2, 3, 4, 5]
    assert exported[0]["detail"] == {"permissions": 7, "recursive": True}


def test_only_rows_the_puller_copied_may_go(pg_conn, acc_tenant, cfg):
    scope = acc.acc_scope_for(acc_tenant, cfg)
    append(pg_conn, scope.table, "2026-06-10", 4)

    r = run(pg_conn, cfg, acc_tenant, date(2026, 9, 1))   # no cursor at all
    assert r["rows"] == 0 and "never read" in r["held"]["reason"]
    set_cursor(pg_conn, acc_tenant, 4, halted="seq gap")
    r = run(pg_conn, cfg, acc_tenant, date(2026, 9, 1))
    assert r["rows"] == 0 and "HALTED" in r["held"]["reason"]
    assert seqs(pg_conn, scope.table) == [1, 2, 3, 4]

    set_cursor(pg_conn, acc_tenant, 2)                     # lagging puller
    r = run(pg_conn, cfg, acc_tenant, date(2026, 9, 1))
    assert (r["rows"], r["last_seq"]) == (2, 2)
    assert r["held"] == {"from_seq": 3, "to_seq": 4, "reason": "not yet copied into the audit log"}
    assert seqs(pg_conn, scope.table) == [3, 4]

    set_cursor(pg_conn, acc_tenant, 4)                     # caught up: the rest goes
    assert run(pg_conn, cfg, acc_tenant, date(2026, 9, 1))["rows"] == 2
    assert seqs(pg_conn, scope.table) == []
    assert verify(pg_conn, cfg, scope).ok


def test_a_tampered_row_refuses_the_scope_and_deletes_nothing(pg_conn, acc_tenant, cfg):
    scope = acc.acc_scope_for(acc_tenant, cfg)
    head = append(pg_conn, scope.table, "2026-06-10", 3)
    set_cursor(pg_conn, acc_tenant, head)
    with pg_conn.cursor() as cur:
        cur.execute(f"UPDATE {scope.table} SET principal = 'mallory' WHERE seq = 2")
    pg_conn.commit()
    results, failures = run_all(pg_conn, cfg, today=date(2026, 9, 1), scopes=[],
                                acc_scopes=[scope])
    assert len(failures) == 1 and "seq 2" in failures[0][1]
    assert seqs(pg_conn, scope.table) == [1, 2, 3]
    assert catalog.anchor(pg_conn, scope.table) is None
    pg_conn.rollback()


def test_dry_run_and_a_missing_table_change_nothing(pg_conn, acc_tenant, cfg):
    scope = acc.acc_scope_for(acc_tenant, cfg)
    head = append(pg_conn, scope.table, "2026-06-10", 3)
    set_cursor(pg_conn, acc_tenant, head)
    r = run(pg_conn, cfg, acc_tenant, date(2026, 9, 1), dry_run=True)
    assert (r["rows"], r["last_seq"], r["parts"]) == (3, 3, 0)
    assert seqs(pg_conn, scope.table) == [1, 2, 3]
    ghost = acc.acc_scope_for("nosuchtenant", cfg)
    results, failures = run_all(pg_conn, cfg, today=date(2026, 9, 1), scopes=[],
                                acc_scopes=[ghost])
    assert not failures and results[0]["rows"] == 0


def test_a_rebuilt_puller_resumes_from_the_anchor(pg_conn, acc_tenant, cfg):
    scope = acc.acc_scope_for(acc_tenant, cfg)
    append(pg_conn, scope.table, "2026-06-10", 3)
    head = append(pg_conn, scope.table, "2026-09-02", 2)
    set_cursor(pg_conn, acc_tenant, head)
    run(pg_conn, cfg, acc_tenant, date(2026, 9, 1))

    # The operator resets the cursor ("rebuild from zero").
    state = CursorState(tenant=acc_tenant)
    AccountabilityPuller._resume_from_anchor(pg_conn, acc_tenant, state)
    pg_conn.rollback()
    assert state.last_seq == 3
    # The surviving rows verify from exactly that state, as the puller's next
    # fetch (ts > recorded_until) would present them.
    w = acc.AccWalker(acc_tenant, state.last_hash, state.last_seq, state.recorded_until_micros)
    with pg_conn.cursor() as cur:
        cur.execute(f"SELECT {acc._COLS} FROM {scope.table} "
                    "WHERE ts > to_timestamp(%s / 1e6) ORDER BY seq",
                    (state.recorded_until_micros,))
        rows = [acc.row_to_dict(r, False) for r in cur.fetchall()]
    pg_conn.rollback()
    assert [r["seq"] for r in rows] == [4, 5]
    assert all(w.step(r) for r in rows)


def test_discovery_finds_the_tenant(pg_conn, acc_tenant, cfg):
    found = {s.scope_id for s in acc.discover_acc_scopes(pg_conn, cfg)}
    assert schema_for_tenant(acc_tenant)[len("tenant_"):] in found


def test_an_unsafe_folder_is_refused(pg_conn, acc_tenant, cfg):
    cfg.archive_accountability_folder = cfg.archive_folder
    with pytest.raises(ArchiveError):
        run_all(pg_conn, cfg, today=date(2026, 9, 1), scopes=[], acc_scopes=[])


def test_timestamps_survive_to_the_microsecond(pg_conn, acc_tenant, cfg):
    scope = acc.acc_scope_for(acc_tenant, cfg)
    append(pg_conn, scope.table, "2026-06-10", 1)
    with pg_conn.cursor() as cur:
        cur.execute(f"SELECT ts FROM {scope.table}")
        ts = cur.fetchone()[0]
    pg_conn.rollback()
    assert ts.tzinfo is not None and ts.microsecond == 1
    assert acc._micros(ts) == int(datetime(2026, 6, 10, 10, 0, 0, 1,
                                           tzinfo=timezone.utc).timestamp()) * 1_000_000 + 1
