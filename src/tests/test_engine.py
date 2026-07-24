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

from audit_service.engine import RulesEngine
from audit_service.rules import Rule, default_rules


class Fakes:
    """One object serving as store + notifier + enforcer."""
    def __init__(self):
        self.recorded, self.alerts, self.mandatory, self.disabled = [], [], [], []

    def record(self, inc):
        self.recorded.append(inc)

    def alert(self, inc):
        self.alerts.append(inc)

    def notify_admins_mandatory(self, inc):
        self.mandatory.append(inc)

    def disable(self, tenant, actor):
        self.disabled.append((tenant, actor))


def _engine(rules):
    f = Fakes()
    return RulesEngine(rules, store=f, notifier=f, enforcer=f), f


def _fail(actor, ts, ip="1.2.3.4", tenant="acme"):
    return {"category": "auth", "action": "login_failure", "outcome": "denied",
            "actor": actor, "source_addr": ip, "tenant": tenant, "ts": ts}


def _bf(**over):
    base = dict(id="bf", description="d", category="auth", action="login_failure",
                outcome="denied", group_by="actor", window_s=300, threshold=5,
                severity="serious", response="alert")
    base.update(over)
    return Rule(**base)


def test_brute_force_fires_and_emails():
    eng, f = _engine([_bf()])
    incs = []
    for i in range(5):
        incs += eng.feed(_fail("mallory", 1000 + i))
    assert len(incs) == 1 and incs[0].count == 5 and incs[0].action_taken == "alerted"
    assert len(f.alerts) == 1
    assert len(f.mandatory) == 1          # serious -> mandatory admin email


def test_below_threshold_no_incident():
    eng, f = _engine([_bf()])
    for i in range(4):
        eng.feed(_fail("m", 1000 + i))
    assert f.recorded == []


def test_group_isolation():
    eng, f = _engine([_bf()])
    for i in range(4):
        eng.feed(_fail("a", 1000 + i))
    for i in range(4):
        eng.feed(_fail("b", 1000 + i))
    assert f.recorded == []                # neither actor reached 5


def test_window_expiry():
    eng, f = _engine([_bf(window_s=300)])
    for i in range(5):
        eng.feed(_fail("m", 1000 + i * 100))   # spread over 400s > window
    assert f.recorded == []


def test_cooldown_is_one_incident_per_attack():
    eng, f = _engine([_bf(threshold=5, cooldown_s=1000)])
    for i in range(12):
        eng.feed(_fail("m", 1000 + i))
    assert len(f.recorded) == 1


def test_sequence_credential_guess():
    rule = _bf(id="cg", then_action="login_success", window_s=600, threshold=5)
    eng, f = _engine([rule])
    for i in range(5):
        eng.feed(_fail("m", 1000 + i))
    incs = eng.feed({"category": "auth", "action": "login_success", "outcome": "ok",
                     "actor": "m", "tenant": "acme", "ts": 1010})
    assert len(incs) == 1 and incs[0].rule_id == "cg"
    assert len(f.mandatory) == 1


def test_auto_disable_calls_enforcer():
    eng, f = _engine([_bf(response="auto_disable", dry_run=False, threshold=3)])
    for i in range(3):
        eng.feed(_fail("m", 1000 + i))
    assert f.disabled == [("acme", "m")]
    assert f.recorded[0].action_taken == "disabled"


def test_dry_run_would_disable_without_enforcing():
    eng, f = _engine([_bf(response="auto_disable", dry_run=True, threshold=3)])
    for i in range(3):
        eng.feed(_fail("m", 1000 + i))
    assert f.disabled == []
    assert f.recorded[0].action_taken == "would_disable"


def test_serious_flag_still_emails():
    eng, f = _engine([_bf(response="flag", severity="serious", threshold=2)])
    for i in range(2):
        eng.feed(_fail("m", 1000 + i))
    assert f.recorded[0].action_taken == "flagged"
    assert len(f.mandatory) == 1           # serious emails even in flag mode


def test_warn_flag_does_not_email():
    rule = Rule(id="md", description="d", category="mutate", action="soft_delete",
                group_by="actor", window_s=300, threshold=3, severity="warn", response="flag")
    eng, f = _engine([rule])
    for i in range(3):
        eng.feed({"category": "mutate", "action": "soft_delete", "actor": "m",
                  "tenant": "acme", "ts": 1000 + i})
    assert len(f.recorded) == 1 and f.mandatory == []


def test_default_pack_detects_brute_force():
    eng, f = _engine(default_rules())
    for i in range(5):
        eng.feed(_fail("m", 1000 + i))
    assert any(inc.rule_id == "brute_force_login" for inc in f.recorded)
