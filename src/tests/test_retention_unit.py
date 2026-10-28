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

"""Pure retention rules (no database): the window, the date-override guard, the
chain-prefix rule, the key layout, the cipher and the shared chain walker."""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

import pytest

from audit_service import retention
from audit_service.archive import (ArchiveError, LocalArchive, make_cipher, manifest_key,
                                   part_key, segment_prefix, validate_reserved)
from audit_service.chain import ChainWalker, canonical_of
from audit_service.config import Config
from audit_service.hashing import compute_row_hash
from audit_service.retention import PartStat, cutoff_for, select_droppable


# ---- the window -------------------------------------------------------------

@pytest.mark.parametrize("today,months,cutoff", [
    (date(2026, 11, 1), 2, date(2026, 9, 1)),    # the monthly run: keep Sep + Oct
    (date(2026, 11, 30), 2, date(2026, 9, 1)),   # a late run in the month: same cutoff
    (date(2026, 1, 1), 2, date(2025, 11, 1)),    # across the year boundary
    (date(2026, 2, 15), 1, date(2026, 1, 1)),
    (date(2026, 3, 1), 12, date(2025, 3, 1)),
    (date(2026, 12, 31), 14, date(2025, 10, 1)),
])
def test_cutoff_is_the_first_of_the_month_n_months_back(today, months, cutoff):
    assert cutoff_for(today, months) == cutoff


def test_cutoff_refuses_a_zero_window():
    with pytest.raises(ValueError):
        cutoff_for(date(2026, 1, 1), 0)


# ---- the simulation clock ---------------------------------------------------

def test_no_override_means_the_real_date():
    cfg = Config()
    cfg.retention_today, cfg.allow_date_override = "", False
    assert retention.resolve_today(cfg) == datetime.now(timezone.utc).date()


def test_override_is_refused_without_the_explicit_flag():
    cfg = Config()
    cfg.allow_date_override = False
    with pytest.raises(ArchiveError):
        retention.resolve_today(cfg, "2030-01-01")
    cfg.retention_today = "2030-01-01"
    with pytest.raises(ArchiveError):
        retention.resolve_today(cfg)


def test_override_is_honoured_with_the_flag():
    cfg = Config()
    cfg.allow_date_override = True
    assert retention.resolve_today(cfg, "2030-01-01") == date(2030, 1, 1)
    cfg.retention_today = "2031-05-01"
    assert retention.resolve_today(cfg) == date(2031, 5, 1)


# ---- the chain-prefix rule --------------------------------------------------

def _p(day, lo, hi, rows=None):
    return PartStat(f"audit_log_p{day:%Y%m%d}", day, rows if rows is not None else hi - lo + 1, lo, hi)


def test_in_order_partitions_are_all_droppable():
    aged = [_p(date(2026, 6, 1), 1, 10), _p(date(2026, 6, 2), 11, 20)]
    drop, held = select_droppable(aged, kept_min=21)
    assert [p.day.day for p in drop] == [1, 2] and held == []


def test_a_late_row_holds_its_partition_back():
    # June 1 received a late event (seq 25) after the kept rows began (seq 21).
    aged = [_p(date(2026, 6, 1), 1, 25), _p(date(2026, 6, 2), 11, 20)]
    drop, held = select_droppable(aged, kept_min=21)
    # June 1 is held for its late row; June 2's rows (11..20) then sit above the
    # held partition's lowest seq (1), so dropping June 2 would cut the chain
    # between seq 10 and 11 — it is held too, and nothing is dropped.
    assert [p.name for p in held] == ["audit_log_p20260601", "audit_log_p20260602"]
    assert drop == []


def test_holding_cascades_until_stable():
    aged = [_p(date(2026, 6, 1), 1, 5), _p(date(2026, 6, 2), 6, 30), _p(date(2026, 6, 3), 8, 9)]
    drop, held = select_droppable(aged, kept_min=21)
    # June 2 is late (30 > 21) → bound drops to 6 → June 3 (8..9) is held as well.
    assert [p.day.day for p in drop] == [1]
    assert sorted(p.day.day for p in held) == [2, 3]


def test_nothing_kept_means_everything_aged_is_droppable():
    aged = [_p(date(2026, 6, 1), 5, 9), _p(date(2026, 6, 2), 1, 4)]
    drop, held = select_droppable(aged, kept_min=None)
    assert len(drop) == 2 and held == []


def test_empty_partitions_are_always_droppable():
    empty = PartStat("audit_log_p20260601", date(2026, 6, 1), 0, None, None)
    drop, held = select_droppable([empty, _p(date(2026, 6, 2), 50, 60)], kept_min=21)
    assert [p.name for p in drop] == ["audit_log_p20260601"]
    assert [p.name for p in held] == ["audit_log_p20260602"]


# ---- layout and names -------------------------------------------------------

def test_key_layout_is_the_tenant_virtual_folder():
    seg = segment_prefix("rationalboxes", "_audit", 2026, 11, "20261101T033000Z-ab12cd34")
    assert seg == "rationalboxes/_audit/2026/11/20261101T033000Z-ab12cd34"
    assert part_key(seg, 7) == seg + "/part-00007.ndjson.enc"
    assert manifest_key(seg) == seg + "/manifest.json.enc"


@pytest.mark.parametrize("name", ["_audit", "_global", "_a.b-c"])
def test_reserved_names_accepted(name):
    assert validate_reserved(name, "x") == name


@pytest.mark.parametrize("name", ["audit", "global", "default", "", "_", "_a/b", "_" + "x" * 63])
def test_reserved_names_that_could_collide_are_refused(name):
    with pytest.raises(ArchiveError):
        validate_reserved(name, "x")


def test_run_ids_are_unique():
    assert len({retention.new_run_id() for _ in range(200)}) == 200


def test_s3_settings_default_to_the_main_store(monkeypatch):
    for k in ("AUDIT_ARCHIVE_S3_BUCKET", "AUDIT_ARCHIVE_S3_ENDPOINT", "AUDIT_ARCHIVE_S3_REGION",
              "AUDIT_ARCHIVE_S3_ACCESS_KEY", "AUDIT_ARCHIVE_S3_SECRET_KEY",
              "AUDIT_ARCHIVE_S3_PATH_STYLE", "AUDIT_ARCHIVE_BACKEND"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("FILEENGINE_S3_BUCKET", "mainstore")
    monkeypatch.setenv("FILEENGINE_S3_ENDPOINT", "https://sfo3.example")
    monkeypatch.setenv("FILEENGINE_S3_REGION", "sfo3")
    monkeypatch.setenv("FILEENGINE_S3_ACCESS_KEY", "ak")
    monkeypatch.setenv("FILEENGINE_S3_SECRET_KEY", "sk")
    monkeypatch.setenv("FILEENGINE_S3_PATH_STYLE", "true")
    cfg = Config()
    assert (cfg.archive_backend, cfg.archive_s3_bucket, cfg.archive_s3_endpoint,
            cfg.archive_s3_region, cfg.archive_s3_access_key, cfg.archive_s3_secret_key,
            cfg.archive_s3_path_style) == ("s3", "mainstore", "https://sfo3.example", "sfo3",
                                           "ak", "sk", True)
    monkeypatch.setenv("AUDIT_ARCHIVE_S3_BUCKET", "dedicated")
    assert Config().archive_s3_bucket == "dedicated"


def test_scope_ids():
    cfg = Config()
    assert retention.scope_for("rationalboxes", cfg).scope_id == "rationalboxes"
    assert retention.scope_for("rationalboxes", cfg).parent == '"tenant_rationalboxes".audit_log'
    g = retention.scope_for(None, cfg)
    assert (g.scope_id, g.parent, g.include_tenant) == ("_global", "audit_log_global", True)


# ---- stores and cipher ------------------------------------------------------

def test_local_archive_refuses_a_relative_root():
    # The original defect: a relative directory inside a --rm container.
    with pytest.raises(ArchiveError):
        LocalArchive("audit-archive")


def test_local_archive_refuses_keys_that_escape_the_root(tmp_path):
    with pytest.raises(ArchiveError):
        LocalArchive(str(tmp_path)).put("../outside", b"x")


def test_cipher_requires_a_key():
    with pytest.raises(ArchiveError):
        make_cipher("")
    with pytest.raises(ArchiveError):
        make_cipher("not-a-fernet-key")


def test_cipher_rotation_decrypts_with_any_key_and_encrypts_with_the_first():
    from cryptography.fernet import Fernet
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    token_old = make_cipher(old).encrypt(b"archived last year")
    rotated = make_cipher(f"{new},{old}")
    assert rotated.decrypt(token_old) == b"archived last year"
    assert make_cipher(new).decrypt(rotated.encrypt(b"now")) == b"now"


# ---- the chain walker -------------------------------------------------------

def _row(seq, prev):
    row = {"seq": seq, "event_id": str(uuid.uuid4()),
           "ts": datetime(2026, 6, 1, 12, 0, seq, tzinfo=timezone.utc).isoformat(),
           "category": 1, "action": "read", "outcome": 0, "actor": "u", "actor_roles": None,
           "target_uid": None, "target_name": None, "target_type": None, "detail": {"i": seq},
           "source_iface": None, "source_addr": None, "request_id": None,
           "prev_hash": prev.hex() if prev else None}
    row["row_hash"] = compute_row_hash(prev, canonical_of(row, False)).hex()
    return row


def _chain(n, start=None, first_seq=1):
    rows, prev = [], start
    for i in range(n):
        r = _row(first_seq + i, prev)
        rows.append(r)
        prev = bytes.fromhex(r["row_hash"])
    return rows


def test_walker_accepts_an_intact_chain_from_genesis():
    w = ChainWalker()
    assert all(w.step_dict(r, False) for r in _chain(5)) and w.ok and w.checked == 5


def test_walker_continues_from_an_anchor():
    archived = _chain(3)
    anchor_hash = bytes.fromhex(archived[-1]["row_hash"])
    w = ChainWalker(anchor_hash, after_seq=3)
    assert all(w.step_dict(r, False) for r in _chain(4, start=anchor_hash, first_seq=4))
    # ...and the same rows walked from NULL look tampered: the pre-fix behaviour.
    assert not ChainWalker().step_dict(_chain(4, start=anchor_hash, first_seq=4)[0], False)


def test_walker_detects_content_tamper_and_reports_the_first_break():
    rows = _chain(5)
    rows[2]["actor"] = "someone-else"
    w = ChainWalker()
    for r in rows:
        w.step_dict(r, False)
    assert not w.ok and w.broken_seq == 3 and "recomputed" in w.reason


def test_walker_flags_a_row_that_predates_the_anchor():
    rows = _chain(5)
    w = ChainWalker(bytes.fromhex(rows[2]["row_hash"]), after_seq=3)
    assert not w.step_dict(rows[1], False) and w.reason == "row predates the archive anchor"


def test_the_cli_refuses_a_date_override_without_the_flag():
    """The guard holds at the process boundary, before any database is touched."""
    import os
    import subprocess
    import sys
    env = {k: v for k, v in os.environ.items() if k != "AUDIT_ALLOW_DATE_OVERRIDE"}
    env["FILEENGINE_PG_HOST"] = "203.0.113.1"   # unroutable: proves it never connects
    p = subprocess.run([sys.executable, "-m", "audit_service.retention", "--today", "2030-01-01"],
                       env=env, capture_output=True, text=True, timeout=30,
                       cwd=os.path.dirname(os.path.dirname(__file__)))
    assert p.returncode == 2 and "AUDIT_ALLOW_DATE_OVERRIDE" in p.stderr
