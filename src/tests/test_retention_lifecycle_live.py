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

"""The audit data lifecycle, simulated (SPEC_retention_and_archival.md §12).

Months of history are replayed in seconds: events are seeded "in" past months
(the writer partitions on the envelope's ts), and retention runs on each
simulated 1st through its date override. After every step the suite checks what
production depends on — partitions kept and dropped, the catalog, the database
chain from its anchor, the archive chain end to end, export round trips — plus
late arrivals, quiet tenants, injected storage failures and tampering.

Runs against a real Postgres (skips without one) and, for the s3 variant, a real
S3-compatible store given by AUDIT_TEST_S3_ENDPOINT / _BUCKET / _ACCESS_KEY /
_SECRET_KEY (skips without one). The global-chain test drops partitions of the
SHARED public.audit_log_global, so it runs only when AUDIT_TEST_DISPOSABLE_DB=1.
"""
from __future__ import annotations

import os
import uuid
from datetime import date, datetime, timezone

import pytest

from audit_service import catalog, retention
from audit_service.archive import ArchiveError, make_archive, make_cipher
from audit_service.archive_cli import export_rows, verify_archive
from audit_service.config import Config
from audit_service.envelope import parse_envelope
from audit_service.naming import schema_for_tenant
from audit_service.verify import verify_chain
from audit_service.writer import write_batch

pytestmark = pytest.mark.live


# --------------------------------------------------------------------------- fixtures

@pytest.fixture(params=["local", "s3"])
def cfg(request, tmp_path):
    from cryptography.fernet import Fernet
    c = Config()
    c.archive_key = Fernet.generate_key().decode()
    c.retention_months = 2
    c.archive_part_rows = 2          # many small parts: exercises every boundary
    if request.param == "local":
        c.archive_backend, c.archive_dir = "local", str(tmp_path)
    else:
        need = ("AUDIT_TEST_S3_ENDPOINT", "AUDIT_TEST_S3_BUCKET",
                "AUDIT_TEST_S3_ACCESS_KEY", "AUDIT_TEST_S3_SECRET_KEY")
        if not all(os.environ.get(k) for k in need):
            pytest.skip("no S3 test store (AUDIT_TEST_S3_*)")
        c.archive_backend = "s3"
        c.archive_s3_endpoint = os.environ["AUDIT_TEST_S3_ENDPOINT"]
        c.archive_s3_bucket = os.environ["AUDIT_TEST_S3_BUCKET"]
        c.archive_s3_access_key = os.environ["AUDIT_TEST_S3_ACCESS_KEY"]
        c.archive_s3_secret_key = os.environ["AUDIT_TEST_S3_SECRET_KEY"]
        c.archive_s3_region = os.environ.get("AUDIT_TEST_S3_REGION", "us-east-1")
        c.archive_s3_path_style = True
        c.archive_s3_prefix = f"it-{uuid.uuid4().hex[:12]}"   # isolates this test's objects
    return c


def _clear_catalog(conn, scope_table):
    if catalog.exists(conn):
        with conn.cursor() as cur:
            cur.execute(f"DELETE FROM {catalog.PARTS} WHERE segment_id IN (SELECT segment_id "
                        f"FROM {catalog.SEGMENTS} WHERE scope_table = %s)", (scope_table,))
            cur.execute(f"DELETE FROM {catalog.SEGMENTS} WHERE scope_table = %s", (scope_table,))
    conn.commit()


@pytest.fixture()
def tenant(pg_conn, audit_schema, config):
    """The throwaway tenant, with no catalog rows left over from an earlier test
    that used the same schema name."""
    scope = retention.scope_for(audit_schema, config)
    _clear_catalog(pg_conn, scope.parent)
    yield audit_schema
    _clear_catalog(pg_conn, scope.parent)


# --------------------------------------------------------------------------- helpers

def seed(conn, tenant, day_iso, n, *, scope="tenant"):
    ids = [str(uuid.uuid4()) for _ in range(n)]
    rows = [parse_envelope({"event_id": e, "ts": f"{day_iso}T12:00:{i:02d}Z", "scope": scope,
                            "tenant": tenant, "category": "access", "action": "read",
                            "outcome": "ok", "actor": f"u{i}", "detail": {"i": i}})
            for i, e in enumerate(ids)]
    write_batch(conn, rows, {})
    conn.commit()
    return ids


def partitions(conn, scope):
    return {name for name, _ in retention.list_partitions(conn, scope)}


def archived_ids(conn, cfg, scope, **kw):
    out = [r["event_id"] for r in export_rows(conn, make_archive(cfg), make_cipher(cfg.archive_key),
                                              scope, **kw)]
    return out


def assert_whole_chain_ok(conn, cfg, scope, tenant):
    db = verify_chain(conn, tenant)
    conn.rollback()
    assert db.ok, db
    arch = verify_archive(conn, make_archive(cfg), make_cipher(cfg.archive_key), scope)
    assert arch.ok, arch
    assert arch.db["ok"]
    return db, arch


def run(conn, cfg, tenant, today):
    return retention.run(conn, tenant, cfg, today=today)


# --------------------------------------------------------------------------- the lifecycle

def test_multi_month_lifecycle(pg_conn, tenant, cfg):
    scope = retention.scope_for(tenant, cfg)
    june = seed(pg_conn, tenant, "2026-06-10", 3) + seed(pg_conn, tenant, "2026-06-20", 2)
    july = seed(pg_conn, tenant, "2026-07-05", 4) + seed(pg_conn, tenant, "2026-07-25", 1)
    aug = seed(pg_conn, tenant, "2026-08-03", 5) + seed(pg_conn, tenant, "2026-08-30", 2)
    sep = seed(pg_conn, tenant, "2026-09-02", 3)

    # Aug 1: cutoff Jun 1 — nothing is old enough yet.
    assert run(pg_conn, cfg, tenant, date(2026, 8, 1)) == []
    assert len(partitions(pg_conn, scope)) == 7

    # Sep 1: cutoff Jul 1 — June (5 rows) is archived as 3 parts and dropped.
    [r] = run(pg_conn, cfg, tenant, date(2026, 9, 1))
    assert r["dropped"] == ["audit_log_p20260610", "audit_log_p20260620"]
    assert (r["rows"], r["parts"], r["chain_ok"], r["held"]) == (5, 3, True, [])
    assert "audit_log_p20260610" not in partitions(pg_conn, scope)
    assert r["manifest_key"].split("/")[-6:-1] == [scope.scope_id, "_audit", "2026", "09",
                                                   r["run_id"]]
    db, arch = assert_whole_chain_ok(pg_conn, cfg, scope, tenant)
    assert db.anchored_at_seq is not None and arch.rows == 5 and arch.starts_at_genesis
    assert archived_ids(pg_conn, cfg, scope) == june

    # A second run in the same month changes nothing.
    assert run(pg_conn, cfg, tenant, date(2026, 9, 15)) == []

    # A late event for a June day arrives after June was archived: the writer
    # recreates that day's partition, with a seq newer than everything else.
    late = seed(pg_conn, tenant, "2026-06-15", 1)

    # Oct 1: cutoff Aug 1 — July goes; the late June row is held, not dropped,
    # because dropping it now would cut the chain between July and August.
    [r] = run(pg_conn, cfg, tenant, date(2026, 10, 1))
    assert r["dropped"] == ["audit_log_p20260705", "audit_log_p20260725"]
    assert [h["partition"] for h in r["held"]] == ["audit_log_p20260615"]
    assert "audit_log_p20260615" in partitions(pg_conn, scope)
    assert_whole_chain_ok(pg_conn, cfg, scope, tenant)
    assert archived_ids(pg_conn, cfg, scope) == june + july

    # Activity continues; Dec 1: cutoff Oct 1 — Aug, Sep and the late row all
    # go, in seq order, and only October stays.
    octo = seed(pg_conn, tenant, "2026-10-02", 2)
    [r] = run(pg_conn, cfg, tenant, date(2026, 12, 1))
    assert set(r["dropped"]) == {"audit_log_p20260615", "audit_log_p20260803",
                                 "audit_log_p20260830", "audit_log_p20260902"}
    assert r["held"] == [] and r["rows"] == 11
    assert partitions(pg_conn, scope) == {"audit_log_p20261002"}

    db, arch = assert_whole_chain_ok(pg_conn, cfg, scope, tenant)
    assert arch.rows == 21 and db.checked == 2
    assert archived_ids(pg_conn, cfg, scope) == june + july + aug + sep + late

    # The ts filter reads only overlapping parts and returns only that range.
    got = archived_ids(pg_conn, cfg, scope, ts_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
                       ts_to=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert got == aug

    # Write-once: every catalogued object exists, and none was ever reused.
    archive = make_archive(cfg)
    with pg_conn.cursor() as cur:
        cur.execute(f"SELECT object_key FROM {catalog.PARTS} JOIN {catalog.SEGMENTS} "
                    "USING (segment_id) WHERE scope_table = %s UNION ALL "
                    f"SELECT manifest_key FROM {catalog.SEGMENTS} WHERE scope_table = %s",
                    (scope.parent, scope.parent))
        keys = [k for (k,) in cur.fetchall()]
    pg_conn.rollback()
    assert len(keys) == len(set(keys)) == 3 + 1 + 3 + 1 + 6 + 1
    assert all(archive.get_object(k) for k in keys)
    assert octo  # still live in Postgres, not archived


def test_a_quiet_tenant_archived_to_empty_keeps_one_chain(pg_conn, tenant, cfg):
    """Every row archived, then a new event: it must link to the archived tail,
    not start a fresh chain at NULL."""
    scope = retention.scope_for(tenant, cfg)
    seed(pg_conn, tenant, "2026-03-01", 3)
    [r] = run(pg_conn, cfg, tenant, date(2026, 6, 1))
    assert r["rows"] == 3 and partitions(pg_conn, scope) == set()
    seed(pg_conn, tenant, "2026-06-02", 2)
    db, arch = assert_whole_chain_ok(pg_conn, cfg, scope, tenant)
    assert db.checked == 2 and arch.rows == 3


def test_a_storage_failure_drops_nothing(pg_conn, tenant, cfg):
    scope = retention.scope_for(tenant, cfg)
    seed(pg_conn, tenant, "2026-01-05", 5)
    seed(pg_conn, tenant, "2026-04-05", 1)
    before = partitions(pg_conn, scope)

    real = make_archive(cfg)

    class Flaky:
        def __init__(self):
            self.puts = 0

        def put(self, key, data):
            self.puts += 1
            if self.puts == 2:
                raise OSError("injected: storage unavailable")
            real.put(key, data)

        def __getattr__(self, name):
            return getattr(real, name)

    catalog.ensure_tables(pg_conn)
    with pytest.raises(OSError):
        retention.run_scope(pg_conn, scope, cfg, today=date(2026, 4, 1), archive=Flaky(),
                            cipher=make_cipher(cfg.archive_key))
    assert partitions(pg_conn, scope) == before
    assert catalog.anchor(pg_conn, scope.parent) is None
    pg_conn.rollback()

    # The retry succeeds and never reuses the orphaned part's key.
    [r] = run(pg_conn, cfg, tenant, date(2026, 4, 1))
    assert r["rows"] == 5 and r["parts"] == 3
    assert_whole_chain_ok(pg_conn, cfg, scope, tenant)


def test_tampering_with_an_archived_object_is_detected(pg_conn, tenant, cfg):
    scope = retention.scope_for(tenant, cfg)
    seed(pg_conn, tenant, "2026-01-05", 4)
    [r] = run(pg_conn, cfg, tenant, date(2026, 4, 1))
    archive = make_archive(cfg)
    [(*_, object_key, _rc, _fs, _ls, _sha)] = catalog.parts_in_order(pg_conn, scope.parent)[:1]
    pg_conn.rollback()
    blob = bytearray(archive.get_object(object_key))
    blob[-5] ^= 0x01
    # Re-put under the same logical key (the catalog stores the bucket key).
    logical = object_key[len(cfg.archive_s3_prefix) + 1:] if cfg.archive_backend == "s3" else object_key
    archive.put(logical, bytes(blob))
    res = verify_archive(pg_conn, archive, make_cipher(cfg.archive_key), scope)
    assert not res.ok and "sha256" in res.reason


def test_a_missing_key_refuses_before_reading_anything(pg_conn, tenant, cfg):
    cfg.archive_key = ""
    seed(pg_conn, tenant, "2026-01-05", 1)
    with pytest.raises(ArchiveError):
        run(pg_conn, cfg, tenant, date(2026, 4, 1))
    assert partitions(pg_conn, retention.scope_for(tenant, cfg))


def test_dry_run_reports_the_plan_and_changes_nothing(pg_conn, tenant, cfg):
    scope = retention.scope_for(tenant, cfg)
    seed(pg_conn, tenant, "2026-01-05", 2)
    before = partitions(pg_conn, scope)
    [r] = retention.run(pg_conn, tenant, cfg, today=date(2026, 4, 1), dry_run=True)
    assert r["dropped"] == ["audit_log_p20260105"] and r["rows"] == 2 and r["parts"] == 0
    assert partitions(pg_conn, scope) == before
    assert catalog.anchor(pg_conn, scope.parent) is None


@pytest.mark.skipif(os.environ.get("AUDIT_TEST_DISPOSABLE_DB") != "1",
                    reason="drops partitions of the shared global table")
def test_global_chain_lifecycle(pg_conn, global_table, cfg):
    scope = retention.scope_for(None, cfg)
    with pg_conn.cursor() as cur:   # a clean global chain on the disposable DB
        cur.execute("TRUNCATE audit_log_global")
    pg_conn.commit()
    _clear_catalog(pg_conn, scope.parent)
    old = seed(pg_conn, "acme", "2026-01-05", 3, scope="global")
    seed(pg_conn, "acme", "2026-04-02", 1, scope="global")
    [r] = run(pg_conn, cfg, None, date(2026, 4, 1))
    assert r["rows"] == 3 and r["manifest_key"].split("/")[-6] == "_global"
    # tenant is part of the GLOBAL row hash; the archive must carry it to verify.
    assert_whole_chain_ok(pg_conn, cfg, scope, None)
    assert [r["tenant"] for r in export_rows(pg_conn, make_archive(cfg),
                                             make_cipher(cfg.archive_key), scope)] == ["acme"] * 3
    assert archived_ids(pg_conn, cfg, scope) == old
    # Leave the shared table as an empty chain: its remaining row links to an
    # anchor this test is about to delete, and would read as tampered.
    with pg_conn.cursor() as cur:
        cur.execute("TRUNCATE audit_log_global")
    pg_conn.commit()
    _clear_catalog(pg_conn, scope.parent)


def test_run_all_discovers_tenants_and_isolates_failures(pg_conn, tenant, cfg, monkeypatch):
    seed(pg_conn, tenant, "2026-01-05", 2)
    real_run_scope = retention.run_scope

    def failing_first(conn, scope, *a, **kw):
        if scope.scope_id == "brokentenant":
            raise RuntimeError("injected")
        return real_run_scope(conn, scope, *a, **kw)

    monkeypatch.setattr(retention, "run_scope", failing_first)
    scopes = [retention.scope_for("brokentenant", cfg), retention.scope_for(tenant, cfg),
              retention.scope_for("nosuchtenant", cfg)]
    results, failures = retention.run_all(pg_conn, cfg, today=date(2026, 4, 1), scopes=scopes)
    # The failing scope does not stop the next; a tenant with no schema is a no-op.
    assert [f[0] for f in failures] == ["brokentenant"]
    assert [(r["scope"], r["rows"]) for r in results] == [
        (schema_for_tenant(tenant)[len("tenant_"):], 2), ("nosuchtenant", 0)]
    found = {s.scope_id for s in retention.discover_scopes(pg_conn, cfg)}
    assert schema_for_tenant(tenant)[len("tenant_"):] in found


def test_rechain_after_archival_relinks_from_the_anchor(pg_conn, tenant, cfg):
    """A retained chain broken the way the concurrent-writer defect broke them
    (a row chained onto the wrong predecessor, self-consistently) is repaired by
    audit-rechain WITHOUT severing it from its archive."""
    from audit_service.chain import canonical_of, record_to_dict, select_cols
    from audit_service.hashing import compute_row_hash
    from audit_service.rechain import rechain

    scope = retention.scope_for(tenant, cfg)
    seed(pg_conn, tenant, "2026-01-05", 3)
    seed(pg_conn, tenant, "2026-04-02", 3)
    run(pg_conn, cfg, tenant, date(2026, 4, 1))
    with pg_conn.cursor() as cur:
        cur.execute(f"SELECT {select_cols(False)} FROM {scope.parent} ORDER BY seq OFFSET 1 LIMIT 1")
        row = record_to_dict(cur.fetchone(), False)
        wrong = os.urandom(32)
        cur.execute(f"UPDATE {scope.parent} SET prev_hash = %s, row_hash = %s WHERE seq = %s",
                    (wrong, compute_row_hash(wrong, canonical_of(row, False)), row["seq"]))
    pg_conn.commit()
    assert not verify_chain(pg_conn, tenant).ok
    pg_conn.rollback()

    res = rechain(pg_conn, tenant)
    pg_conn.commit()
    assert res.ok_after and res.relinked >= 1
    db, arch = assert_whole_chain_ok(pg_conn, cfg, scope, tenant)
    assert db.anchored_at_seq is not None and arch.rows == 3
