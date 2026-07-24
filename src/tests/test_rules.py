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

import pytest

from audit_service.rules import Rule, default_rules


def test_default_pack_present():
    ids = {r.id for r in default_rules()}
    assert {"brute_force_login", "brute_force_source_ip", "credential_guess",
            "bulk_exfiltration", "mass_delete"} <= ids
    # Defaults never ship as auto-disable (§11 — opt-in only).
    assert all(r.response in ("flag", "alert") for r in default_rules())


@pytest.mark.parametrize("bad", [
    {"severity": "huge"}, {"response": "nuke"}, {"group_by": "planet"}])
def test_rule_validation_rejects_bad_enums(bad):
    with pytest.raises(ValueError):
        Rule(id="x", description="d", category="auth", **bad)


def test_matches_primary():
    r = Rule(id="x", description="d", category="auth", action="login_failure", outcome="denied")
    assert r.matches_primary({"category": "auth", "action": "login_failure", "outcome": "denied"})
    assert not r.matches_primary({"category": "auth", "action": "login_success", "outcome": "ok"})
    assert not r.matches_primary({"category": "access", "action": "login_failure", "outcome": "denied"})


def test_key_for():
    r = Rule(id="x", description="d", category="auth", group_by="source_addr")
    assert r.key_for({"source_addr": "1.2.3.4"}) == "1.2.3.4"
    assert r.key_for({}) is None


def test_sequence_and_seal():
    r = Rule(id="x", description="d", category="auth", action="login_failure",
             then_action="login_success")
    assert r.is_sequence
    assert r.matches_seal({"category": "auth", "action": "login_success"})
    assert not r.matches_seal({"category": "auth", "action": "login_failure"})


def test_from_dict_ignores_unknown_keys():
    r = Rule.from_dict({"id": "x", "description": "d", "category": "auth",
                        "threshold": 3, "bogus": 1})
    assert r.threshold == 3 and r.category == "auth"
