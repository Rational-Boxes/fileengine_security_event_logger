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


# --- share links (OUTSIDE_SHARE_LINKS §8.4) -------------------------------

def _rule(rule_id):
    return next(r for r in default_rules() if r.id == rule_id)


def test_the_lockout_rule_fires_on_the_first_event():
    """Threshold 1 on purpose.

    share_service emits share_link_locked only after it has ALREADY adjudicated
    a link as under attack — counted failures, weighted timing trips, locked the
    link. Waiting for a burst of these would mean two systems independently
    deciding what an attack looks like, and this one, without the per-link
    state, is the weaker judge.
    """
    r = _rule("share_link_brute_force")
    assert r.threshold == 1
    assert r.response == "alert" and r.severity == "serious"
    assert r.matches_primary({"category": "auth", "action": "share_link_locked",
                              "outcome": "denied"})


def test_the_lockout_rule_groups_per_link():
    """A share event's actor IS the link (`share:<link_uid>`), so grouping by
    actor is grouping by link without inventing a new dimension."""
    r = _rule("share_link_brute_force")
    assert r.group_by == "actor"
    assert r.key_for({"actor": "share:abc-123"}) == "share:abc-123"


def test_an_ordinary_share_denial_does_not_trip_the_lockout_rule():
    """A wrong code is routine — most of them are typos. Only the adjudicated
    lock is worth waking someone for."""
    r = _rule("share_link_brute_force")
    assert not r.matches_primary({"category": "access",
                                  "action": "share_link_denied",
                                  "outcome": "denied"})


def test_the_burst_rule_watches_the_source_not_the_link():
    """What the per-link lockout cannot see: denials spread thinly across MANY
    links from one source. Each link stays under its own threshold, so no
    lockout ever fires, and the source is the only dimension that sees it."""
    r = _rule("share_link_denial_burst")
    assert r.group_by == "source_addr"
    assert r.threshold > 1
    assert r.matches_primary({"category": "access", "action": "share_link_denied",
                              "outcome": "denied"})
    assert r.key_for({"source_addr": "203.0.113.7"}) == "203.0.113.7"


def test_share_rules_ship_within_the_no_auto_disable_policy():
    # Guard on the pack-wide invariant, restated for the new rules: an
    # unauthenticated door must not be able to disable an account.
    for rid in ("share_link_brute_force", "share_link_denial_burst"):
        assert _rule(rid).response in ("flag", "alert")
