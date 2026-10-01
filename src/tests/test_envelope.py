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


# ── names never enter the log (PROPOSAL_accountability_record §5.4.7) ───────


def test_target_name_is_dropped_even_when_a_producer_sends_one():
    """The audit log records identifiers and structure, never payload.

    A filename is party data, and this log is immutable and long-lived — so a
    name stored here is one the platform has committed to keeping and cannot
    easily remove. The core already stopped sending one, but this pipe accepted,
    stored and returned it, so the property held only because one producer chose
    not to exercise it. That is a convention; this is the control.
    """
    row = parse_envelope({**GOOD,
                          "target_uid": "3cbdbc15-60a6-4d6f-b6c4-062f85279242",
                          "target_name": "Acme_Corp_Contract_J_Smith.pdf"})
    assert row.target_name is None, "a filename must never reach the log"
    # The identifier survives, which is the whole point: the file's history stays
    # readable and a viewer joins to the current name at read time — a join that
    # finds nothing once the file is erased.
    assert row.target_uid == "3cbdbc15-60a6-4d6f-b6c4-062f85279242"


def test_an_envelope_without_a_name_is_unaffected():
    row = parse_envelope({**GOOD, "target_uid": "u-1"})
    assert row.target_name is None and row.target_uid == "u-1"


def test_dropping_the_name_does_not_drop_the_event():
    """The event is a security record and must survive a bad metadata field.

    Rejecting the envelope would lose an audit event over a filename, which is
    the wrong trade — so the field is dropped and the attempt is logged.
    """
    row = parse_envelope({**GOOD, "action": "erase", "target_uid": "u-1",
                          "target_name": "sensitive.pdf"})
    assert row.action == "erase" and row.actor == GOOD["actor"]
    assert row.target_name is None
