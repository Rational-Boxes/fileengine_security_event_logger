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

from datetime import timezone

import pytest

from audit_service.envelope import InvalidEnvelope, parse_envelope

GOOD = {
    "event_id": "11111111-1111-1111-1111-111111111111",
    "ts": "2026-07-10T12:00:00Z",
    "tenant": "acme",
    "category": "access",
    "action": "read",
    "outcome": "ok",
    "actor": "alice",
}


def test_minimal_valid_envelope():
    row = parse_envelope(GOOD)
    assert row.event_id == "11111111-1111-1111-1111-111111111111"
    assert row.category == 0 and row.outcome == 0
    assert row.scope == "tenant" and row.tenant == "acme"
    assert row.ts.tzinfo is not None
    assert row.ts.astimezone(timezone.utc).isoformat() == "2026-07-10T12:00:00+00:00"


def test_roles_list_becomes_csv():
    row = parse_envelope({**GOOD, "actor_roles": ["admin", "editor"]})
    assert row.actor_roles == "admin,editor"


def test_detail_object_becomes_canonical_json():
    row = parse_envelope({**GOOD, "detail": {"b": 2, "a": 1}})
    assert row.detail == '{"a":1,"b":2}'  # sorted keys, compact


def test_detail_string_passthrough():
    row = parse_envelope({**GOOD, "detail": '{"x":1}'})
    assert row.detail == '{"x":1}'


def test_target_type_mapped():
    row = parse_envelope({**GOOD, "target_type": "file"})
    assert row.target_type == 0


def test_epoch_ts_supported():
    row = parse_envelope({**GOOD, "ts": 1783771200})
    assert row.ts.astimezone(timezone.utc).year == 2026


def test_global_scope_needs_no_tenant():
    env = {k: v for k, v in GOOD.items() if k != "tenant"}
    env["scope"] = "global"
    row = parse_envelope(env)
    assert row.scope == "global" and row.tenant is None


@pytest.mark.parametrize("mutate", [
    {"event_id": "not-a-uuid"},
    {"category": "bogus"},
    {"outcome": "maybe"},
    {"target_type": "planet"},
    {"ts": "not-a-date"},
    {"action": ""},          # missing required
    {"actor": ""},           # missing required
    {"scope": "sideways"},
])
def test_invalid_envelopes_rejected(mutate):
    with pytest.raises(InvalidEnvelope):
        parse_envelope({**GOOD, **mutate})


def test_tenant_scope_without_tenant_rejected():
    env = {k: v for k, v in GOOD.items() if k != "tenant"}  # scope defaults tenant
    with pytest.raises(InvalidEnvelope):
        parse_envelope(env)


def test_long_fields_truncated():
    row = parse_envelope({**GOOD, "actor": "a" * 500, "action": "b" * 100})
    assert len(row.actor) == 255 and len(row.action) == 32
