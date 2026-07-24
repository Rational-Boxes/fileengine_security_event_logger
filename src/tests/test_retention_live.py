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

"""Live retention tests: aged partitions are encrypted-archived then dropped,
recent partitions are kept (skipped if Postgres is unreachable)."""
from __future__ import annotations

import json
import uuid
from datetime import date

import pytest

from audit_service import retention
from audit_service.archive import LocalArchive, make_cipher
from audit_service.config import Config
from audit_service.envelope import parse_envelope
from audit_service.naming import schema_for_tenant
from audit_service.writer import write_batch

pytestmark = pytest.mark.live


def _seed_day(pg_conn, tenant, day_iso, n):
    rows = [parse_envelope({"event_id": str(uuid.uuid4()), "ts": f"{day_iso}T12:00:{i:02d}Z",
                            "tenant": tenant, "category": "access", "action": "read",
                            "outcome": "ok", "actor": f"u{i}", "detail": {"i": i}})
            for i in range(n)]
    write_batch(pg_conn, rows, {})
    pg_conn.commit()


def _cfg(tmp_path):
    from cryptography.fernet import Fernet
    cfg = Config()
    cfg.archive_backend = "local"
    cfg.archive_dir = str(tmp_path)
    cfg.archive_key = Fernet.generate_key().decode()
    cfg.retention_days = 30
    return cfg


def test_aged_partition_archived_and_dropped(pg_conn, audit_schema, tmp_path):
    schema = schema_for_tenant(audit_schema)
    _seed_day(pg_conn, audit_schema, "2020-01-01", 3)   # old
    _seed_day(pg_conn, audit_schema, "2020-06-15", 2)   # recent relative to `today`
    cfg = _cfg(tmp_path)

    results = retention.run(pg_conn, audit_schema, cfg, today=date(2020, 2, 1))
    assert len(results) == 1 and results[0]["count"] == 3
    assert results[0]["dropped"] == "audit_log_p20200101"

    # The old partition is gone; the recent one survives.
    with pg_conn.cursor() as cur:
        cur.execute("SELECT to_regclass(%s)", (f'"{schema}".audit_log_p20200101',))
        assert cur.fetchone()[0] is None
        cur.execute("SELECT to_regclass(%s)", (f'"{schema}".audit_log_p20200615',))
        assert cur.fetchone()[0] is not None

    # The archive exists, decrypts, and holds the manifest + 3 rows with hash linkage.
    archive = LocalArchive(str(tmp_path))
    key = f"{audit_schema}/audit_log_p20200101.ndjson.enc"
    assert archive.exists(key)
    cipher = make_cipher(cfg.archive_key)
    lines = cipher.decrypt(archive.get(key)).decode().splitlines()
    manifest = json.loads(lines[0])["manifest"]
    assert manifest["count"] == 3 and manifest["last_row_hash"]
    assert len(lines) == 4  # manifest + 3 rows
    assert all("row_hash" in json.loads(ln) for ln in lines[1:])


def test_nothing_aged_is_a_noop(pg_conn, audit_schema, tmp_path):
    _seed_day(pg_conn, audit_schema, "2026-07-10", 2)
    cfg = _cfg(tmp_path)
    # today just after the data, well within the 30-day window.
    results = retention.run(pg_conn, audit_schema, cfg, today=date(2026, 7, 11))
    assert results == []


def test_archive_requires_encryption_key(pg_conn, audit_schema, tmp_path):
    from audit_service.archive import ArchiveError
    cfg = _cfg(tmp_path)
    cfg.archive_key = ""  # refuse to archive unencrypted
    _seed_day(pg_conn, audit_schema, "2020-01-01", 1)
    with pytest.raises(ArchiveError):
        retention.run(pg_conn, audit_schema, cfg, today=date(2020, 3, 1))
