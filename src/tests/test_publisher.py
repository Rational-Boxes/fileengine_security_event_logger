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

import json
import uuid

import pytest

from audit_service.envelope import parse_envelope
from audit_service.publisher import AuditPublisher, build_envelope


# ------------------------------- unit: build_envelope ------------------------

def test_build_minimal_generates_id_and_ts():
    env = build_envelope(category="auth", action="login_failure", outcome="denied",
                         actor="mallory", tenant="acme")
    assert uuid.UUID(env["event_id"])              # a real UUID
    assert env["ts"].endswith("Z")                 # ISO-8601 UTC
    assert env["scope"] == "tenant" and env["tenant"] == "acme"
    # Round-trips through the consumer's parser (contract self-consistency).
    row = parse_envelope(env)
    assert row.category == 4 and row.outcome == 1 and row.actor == "mallory"


def test_optionals_included_when_present():
    env = build_envelope(category="permission", action="acl_grant", outcome="ok",
                         actor="alice", tenant="acme", actor_roles=["admin"],
                         target_uid="f1", target_type="acl",
                         detail={"principal": "bob"}, source_iface="rest",
                         source_addr="1.2.3.4", request_id="r1")
    assert env["actor_roles"] == ["admin"] and env["target_type"] == "acl"
    assert env["detail"] == {"principal": "bob"} and env["source_addr"] == "1.2.3.4"


def test_global_scope_needs_no_tenant():
    env = build_envelope(category="admin", action="tenant_create", outcome="ok",
                         actor="root", scope="global")
    assert env["scope"] == "global" and "tenant" not in env


def test_provided_event_id_and_ts_preserved():
    env = build_envelope(category="auth", action="login_success", outcome="ok",
                         actor="alice", tenant="acme",
                         event_id="11111111-1111-1111-1111-111111111111",
                         ts="2026-07-10T12:00:00Z")
    assert env["event_id"] == "11111111-1111-1111-1111-111111111111"
    assert env["ts"] == "2026-07-10T12:00:00Z"


@pytest.mark.parametrize("kw", [
    {"category": "bogus"}, {"outcome": "maybe"}, {"target_type": "planet"},
    {"scope": "sideways"}, {"actor": ""},
])
def test_invalid_fields_raise(kw):
    base = dict(category="auth", action="x", outcome="ok", actor="a", tenant="t")
    with pytest.raises(ValueError):
        build_envelope(**{**base, **kw})


def test_tenant_scope_without_tenant_raises():
    with pytest.raises(ValueError):
        build_envelope(category="auth", action="x", outcome="ok", actor="a")


# ------------------------------- live: publish -> Redis ----------------------

@pytest.mark.live
def test_publish_lands_on_stream_and_parses(redis_client):
    stream = f"test:audit:pub:{uuid.uuid4().hex[:8]}"
    pub = AuditPublisher(redis_client=redis_client, stream=stream)
    ok = pub.publish(category="auth", action="login_failure", outcome="denied",
                     actor="mallory", tenant="acme", source_addr="10.0.0.5",
                     detail={"reason": "bad_password"})
    assert ok is True
    try:
        entries = redis_client.xrange(stream)
        assert len(entries) == 1
        _id, fields = entries[0]
        env = json.loads(fields[b"payload"])
        row = parse_envelope(env)          # the published envelope is consumer-valid
        assert row.category == 4 and row.action == "login_failure"
        assert row.source_addr == "10.0.0.5"
    finally:
        redis_client.delete(stream)


@pytest.mark.live
def test_from_env_builds_publisher(monkeypatch, redis_client):
    monkeypatch.setenv("FILEENGINE_AUDIT_STREAM", f"test:audit:env:{uuid.uuid4().hex[:8]}")
    pub = AuditPublisher.from_env()
    pub._redis = redis_client  # reuse the reachable test client
    assert pub.publish(category="admin", action="audit_read", outcome="ok",
                       actor="admin", tenant="acme") is True
    redis_client.delete(pub.stream)
