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

"""Live tests for the query/export/verify API (skipped if Postgres is
unreachable). A fake publisher is injected so the audit-the-auditors emit never
touches the real Redis stream."""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient

from audit_service.api import create_app
from audit_service.config import Config
from audit_service.envelope import parse_envelope
from audit_service.writer import write_batch

from .test_auth import SECRET, sign

pytestmark = pytest.mark.live


class _FakePub:
    def __init__(self):
        self.calls = []

    def publish(self, **fields):
        self.calls.append(fields)
        return True


def _client(jwt_secret=SECRET):
    config = Config()
    config.jwt_secret = jwt_secret
    app = create_app(config)
    fake = app.state.publisher = _FakePub()
    return TestClient(app), fake


def _seed(pg_conn, tenant, n):
    rows = [parse_envelope({"event_id": str(uuid.uuid4()), "ts": f"2026-07-10T12:00:{i:02d}Z",
                            "tenant": tenant, "category": "access", "action": "read",
                            "outcome": "ok", "actor": f"u{i}", "target_uid": f"f{i}"})
            for i in range(n)]
    write_batch(pg_conn, rows, {})
    pg_conn.commit()


def _admin_token(tenant):
    return sign({"sub": "admin", "roles": {tenant: ["administrators"]}, "exp": time.time() + 60})


def test_query_returns_rows_and_audits_the_read(pg_conn, audit_schema):
    _seed(pg_conn, audit_schema, 3)
    client, fake = _client()
    r = client.get(f"/v1/audit/query?tenant={audit_schema}",
                   headers={"Authorization": f"Bearer {_admin_token(audit_schema)}"})
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 3
    assert data["rows"][0]["category"] == "access" and data["rows"][0]["outcome"] == "ok"
    # audit-the-auditors: the read itself was recorded.
    assert any(c["category"] == "admin" and c["action"] == "audit_read" for c in fake.calls)


def test_query_filter_by_actor(pg_conn, audit_schema):
    _seed(pg_conn, audit_schema, 3)
    client, _ = _client()
    r = client.get(f"/v1/audit/query?tenant={audit_schema}&actor=u1",
                   headers={"Authorization": f"Bearer {_admin_token(audit_schema)}"})
    assert r.status_code == 200
    rows = r.json()["rows"]
    assert len(rows) == 1 and rows[0]["actor"] == "u1"


def test_query_requires_audit_read(pg_conn, audit_schema):
    client, _ = _client()
    tok = sign({"sub": "bob", "roles": {audit_schema: ["editors"]}, "exp": time.time() + 60})
    r = client.get(f"/v1/audit/query?tenant={audit_schema}", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_query_no_token_is_401(pg_conn, audit_schema):
    client, _ = _client()
    r = client.get(f"/v1/audit/query?tenant={audit_schema}")
    assert r.status_code == 401


def test_bad_category_is_400(pg_conn, audit_schema):
    client, _ = _client()
    r = client.get(f"/v1/audit/query?tenant={audit_schema}&category=bogus",
                   headers={"Authorization": f"Bearer {_admin_token(audit_schema)}"})
    assert r.status_code == 400


def test_export_streams_ndjson(pg_conn, audit_schema):
    _seed(pg_conn, audit_schema, 3)
    client, fake = _client()
    r = client.get(f"/v1/audit/export?tenant={audit_schema}",
                   headers={"Authorization": f"Bearer {_admin_token(audit_schema)}"})
    assert r.status_code == 200
    lines = [ln for ln in r.text.splitlines() if ln.strip()]
    assert len(lines) == 3
    assert any(c["action"] == "audit_export" for c in fake.calls)


def test_verify_endpoint_ok(pg_conn, audit_schema):
    _seed(pg_conn, audit_schema, 4)
    client, _ = _client()
    r = client.get(f"/v1/audit/verify?tenant={audit_schema}",
                   headers={"Authorization": f"Bearer {_admin_token(audit_schema)}"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "checked": 4, "first_broken_seq": None, "reason": None}
