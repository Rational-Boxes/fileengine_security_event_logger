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

"""Live tests for the security incident + rules stores and API (skipped if
Postgres is unreachable). Each test isolates its rows by a unique tenant scope."""
from __future__ import annotations

import os
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from audit_service import rules, security
from audit_service.api import create_app
from audit_service.config import Config
from audit_service.engine import Incident

from .test_auth import SECRET, sign

pytestmark = pytest.mark.live


@pytest.fixture()
def sec(pg_conn):
    security.ensure_tables(pg_conn)
    tenant = f"sec_it_{os.getpid()}_{uuid.uuid4().hex[:6]}"
    yield pg_conn, tenant
    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM public.security_incidents WHERE tenant = %s", (tenant,))
        cur.execute("DELETE FROM public.security_rules WHERE tenant = %s", (tenant,))
    pg_conn.commit()


def _incident(tenant):
    return Incident(rule_id="brute_force_login", tenant=tenant, group_by="actor",
                    group_key="mallory", severity="serious", response="alert", count=5,
                    window_s=300, actor="mallory", last_ts="2026-07-10T12:00:00Z",
                    dry_run=False, action_taken="alerted", description="brute force")


def test_incident_store_list_and_ack(sec):
    conn, tenant = sec
    security.PgIncidentStore(lambda: conn).record(_incident(tenant))
    rows = security.list_incidents(conn, tenant)
    assert len(rows) == 1 and rows[0]["rule_id"] == "brute_force_login" and rows[0]["status"] == "open"
    assert security.set_incident_status(conn, rows[0]["id"], "acknowledged")
    assert security.list_incidents(conn, tenant, status="open") == []
    assert len(security.list_incidents(conn, tenant, status="acknowledged")) == 1


def test_rules_seed_override_disable_delete(sec):
    conn, tenant = sec
    store = security.RulesStore(lambda: conn)
    # Derived, not a literal: this asserts "seeding installs every default",
    # which is the actual property. A hardcoded count instead fails every time
    # a rule is ADDED — a false alarm that teaches people to bump the number
    # without reading why it moved.
    assert store.seed_defaults(tenant) == len(rules.default_rules())
    assert any(r.id == "brute_force_login" for r in store.rules_for(tenant))
    # tenant override lowers the threshold
    store.upsert_rule(tenant, {"id": "brute_force_login", "description": "d", "category": "auth",
                               "action": "login_failure", "outcome": "denied", "group_by": "actor",
                               "window_s": 300, "threshold": 3, "severity": "serious", "response": "alert"})
    bf = next(r for r in store.rules_for(tenant) if r.id == "brute_force_login")
    assert bf.threshold == 3
    # disabling drops it from the effective set
    store.upsert_rule(tenant, {"id": "brute_force_login", "description": "d", "category": "auth", "enabled": False})
    assert not any(r.id == "brute_force_login" for r in store.rules_for(tenant))
    assert store.delete_rule(tenant, "mass_delete")


class _FakePub:
    def __init__(self):
        self.calls = []

    def publish(self, **f):
        self.calls.append(f)
        return True


def _client():
    cfg = Config()
    cfg.jwt_secret = SECRET
    app = create_app(cfg)
    app.state.publisher = _FakePub()
    return TestClient(app)


def _tok(tenant):
    return sign({"sub": "admin", "roles": {tenant: ["administrators"]}, "exp": time.time() + 300})


def test_api_rules_seed_and_edit(sec):
    _conn, tenant = sec
    client = _client()
    hdr = {"Authorization": f"Bearer {_tok(tenant)}"}
    # GET seeds the global defaults and returns the effective set
    r = client.get(f"/v1/security/rules?tenant={tenant}", headers=hdr)
    assert r.status_code == 200
    assert any(x["id"] == "brute_force_login" for x in r.json()["effective"])
    # PUT a tenant override, then confirm it wins
    rule = {"id": "brute_force_login", "description": "d", "category": "auth", "action": "login_failure",
            "outcome": "denied", "group_by": "actor", "window_s": 300, "threshold": 2,
            "severity": "serious", "response": "alert"}
    assert client.put(f"/v1/security/rules?tenant={tenant}", json=rule, headers=hdr).status_code == 200
    eff = client.get(f"/v1/security/rules?tenant={tenant}", headers=hdr).json()["effective"]
    assert next(x for x in eff if x["id"] == "brute_force_login")["threshold"] == 2
    # bad rule -> 400; non-admin -> 403
    assert client.put(f"/v1/security/rules?tenant={tenant}", json={"id": "x", "description": "d",
                      "category": "auth", "severity": "nope"}, headers=hdr).status_code == 400
    bad = sign({"sub": "bob", "roles": {tenant: ["editors"]}, "exp": time.time() + 300})
    assert client.get(f"/v1/security/rules?tenant={tenant}",
                      headers={"Authorization": f"Bearer {bad}"}).status_code == 403


def test_api_incidents_empty(sec):
    _conn, tenant = sec
    r = _client().get(f"/v1/security/incidents?tenant={tenant}",
                      headers={"Authorization": f"Bearer {_tok(tenant)}"})
    assert r.status_code == 200 and r.json()["incidents"] == []


def test_api_validate_against_history(pg_conn, audit_schema):
    # seed some login_failure events in the tenant's audit_log, then validate a
    # threshold=3 brute-force rule -> should fire once (5 failures for one actor).
    from audit_service.envelope import parse_envelope
    from audit_service.writer import write_batch
    rows = [parse_envelope({"event_id": str(uuid.uuid4()), "ts": f"2026-07-10T12:00:0{i}Z",
                            "tenant": audit_schema, "category": "auth", "action": "login_failure",
                            "outcome": "denied", "actor": "mallory"}) for i in range(5)]
    write_batch(pg_conn, rows, {})
    pg_conn.commit()
    client = _client()
    rule = {"id": "bf", "description": "d", "category": "auth", "action": "login_failure",
            "outcome": "denied", "group_by": "actor", "window_s": 300, "threshold": 3,
            "severity": "warn", "response": "flag"}
    r = client.post(f"/v1/security/rules/validate?tenant={audit_schema}", json=rule,
                    headers={"Authorization": f"Bearer {_tok(audit_schema)}"})
    assert r.status_code == 200
    body = r.json()
    assert body["events_examined"] == 5 and body["would_fire"] == 1
