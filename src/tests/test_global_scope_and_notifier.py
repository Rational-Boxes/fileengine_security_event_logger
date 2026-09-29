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

"""The two prerequisites the deployment-admin tier could not exist without.

PROPOSAL_deployment_admin_signal.md §3.5, §3.6 and §5, and
PROPOSAL_system_administration_application.md §7.3 / §7.4.

The test that matters most is `test_the_attack_that_was_invisible_before`: it
drives the exact shape §3.5 describes — one source, ten tenants, four attempts
each — past a per-tenant rule that cannot see it and a global rule that can.
Everything else supports that or guards the constraints around it.
"""
from __future__ import annotations

import logging

import pytest

from audit_service.engine import RulesEngine
from audit_service.notifier import (
    EmailAdminNotifier,
    RecordingTransport,
    from_config,
)
from audit_service.rules import Rule
from audit_service.windows import DistinctWindows


def _ev(tenant, addr, ts, *, category="auth", action="login", outcome="denied", actor=None):
    return {"tenant": tenant, "source_addr": addr, "ts": ts, "category": category,
            "action": action, "outcome": outcome, "actor": actor}


PER_TENANT = Rule(id="auth_fail_tenant", description="auth failures from one source",
                  category="auth", action="login", outcome="denied",
                  group_by="source_addr", window_s=300, threshold=5)

GLOBAL = Rule(id="auth_fail_global", description="auth failures across the platform",
              category="auth", action="login", outcome="denied",
              group_by="source_addr", window_s=300, threshold=20,
              scope="global", audience="deployment", severity="serious")

FANOUT = Rule(id="auth_fanout", description="one source touching many tenants",
              category="auth", action="login", outcome="denied",
              group_by="source_addr", distinct="tenant",
              window_s=300, threshold=3,
              scope="global", audience="deployment", severity="serious")


# ── §3.5: aggregating is not detecting ─────────────────────────────────────


def test_the_attack_that_was_invisible_before():
    # THE CASE THE WHOLE FEATURE EXISTS FOR. One source, ten tenants, four
    # attempts each: forty attempts in five minutes. Every tenant sees four,
    # which is below its threshold of five, so no incident exists in any tenant
    # and a cross-tenant view has nothing to aggregate.
    engine = RulesEngine(rules=[PER_TENANT, GLOBAL])
    fired = []
    ts = 1000.0
    for i in range(10):
        for _ in range(4):
            ts += 1
            fired += engine.feed(_ev(f"tenant{i}", "203.0.113.7", ts))

    per_tenant = [f for f in fired if f.rule_id == PER_TENANT.id]
    globals_ = [f for f in fired if f.rule_id == GLOBAL.id]
    assert per_tenant == [], "no tenant can see this, which is the point"
    assert len(globals_) == 1, "the deployment tier must see it"
    assert globals_[0].count >= 20
    assert globals_[0].scope == "global"
    assert globals_[0].audience == "deployment"


def test_a_global_incident_names_no_tenant():
    # Its count spans tenants. Naming one would be a lie a consumer would route
    # on, and would disclose the others to whoever received it.
    engine = RulesEngine(rules=[GLOBAL])
    ts = 1000.0
    fired = []
    for i in range(25):
        ts += 1
        fired += engine.feed(_ev(f"tenant{i % 5}", "203.0.113.7", ts))
    assert fired and fired[0].tenant is None


def test_a_tenant_rule_still_counts_within_one_tenant():
    # The change must not widen existing rules. Five in ONE tenant still fires;
    # five spread over five tenants still does not.
    engine = RulesEngine(rules=[PER_TENANT])
    ts = 1000.0
    fired = []
    for _ in range(5):
        ts += 1
        fired += engine.feed(_ev("acme", "203.0.113.7", ts))
    assert len(fired) == 1 and fired[0].tenant == "acme" and fired[0].scope == "tenant"

    engine2 = RulesEngine(rules=[PER_TENANT])
    ts = 1000.0
    spread = []
    for i in range(5):
        ts += 1
        spread += engine2.feed(_ev(f"t{i}", "203.0.113.7", ts))
    assert spread == []


def test_two_sources_do_not_pool_in_a_global_rule():
    # Global drops the TENANT from the key, not the group key. Two different
    # sources must still be counted apart, or the rule fires on unrelated noise.
    engine = RulesEngine(rules=[GLOBAL])
    ts = 1000.0
    fired = []
    for i in range(19):
        ts += 1
        fired += engine.feed(_ev(f"t{i % 4}", "203.0.113.7", ts))
        fired += engine.feed(_ev(f"t{i % 4}", "198.51.100.9", ts))
    assert fired == [], "19 each, threshold 20 — neither source should fire"


# ── §3.6: fan-out ──────────────────────────────────────────────────────────


def test_fanout_fires_on_breadth_not_volume():
    # One attempt per tenant. A volume threshold of any size never sees this;
    # the fan-out is the anomaly and patience is no defence against it.
    engine = RulesEngine(rules=[FANOUT])
    ts = 1000.0
    fired = []
    for i in range(3):
        ts += 60          # slow, deliberate, still inside the window
        fired += engine.feed(_ev(f"tenant{i}", "203.0.113.7", ts))
    assert len(fired) == 1
    assert fired[0].count == 3


def test_fanout_names_the_tenants_it_saw():
    # "8 tenants" without naming them leaves the administrator to go and find
    # out which, which is the first thing they will want.
    engine = RulesEngine(rules=[FANOUT])
    ts = 1000.0
    fired = []
    for t in ("alpha", "bravo", "charlie"):
        ts += 1
        fired += engine.feed(_ev(t, "203.0.113.7", ts))
    assert sorted(fired[0].distinct_values) == ["alpha", "bravo", "charlie"]


def test_hammering_one_tenant_is_not_fanout():
    # The false positive that would make this rule useless: a single noisy
    # tenant must not look like a platform probe.
    engine = RulesEngine(rules=[FANOUT])
    ts = 1000.0
    fired = []
    for _ in range(50):
        ts += 1
        fired += engine.feed(_ev("acme", "203.0.113.7", ts))
    assert fired == []


def test_fanout_forgets_outside_the_window():
    w = DistinctWindows()
    for i, t in enumerate(("a", "b", "c")):
        w.add_and_count(("r", "addr"), t, 100.0 + i, 300)
    assert w.count(("r", "addr"), 150.0, 300) == 3
    assert w.count(("r", "addr"), 500.0, 300) == 0


# ── the constraints that keep the shapes honest ────────────────────────────


def test_a_global_rule_cannot_have_a_tenant_audience():
    # Its count includes other tenants' events; showing it to one tenant
    # discloses that they exist.
    with pytest.raises(ValueError, match="audience"):
        Rule(id="x", description="d", category="auth", scope="global", audience="tenant")


def test_a_distinct_rule_cannot_count_the_field_it_groups_by():
    # It would count to 1 forever — a rule that never fires, sitting in the pack
    # looking like cover.
    with pytest.raises(ValueError, match="group_by"):
        Rule(id="x", description="d", category="auth",
             group_by="source_addr", distinct="source_addr")


def test_a_sequence_rule_cannot_also_be_a_fanout_rule():
    with pytest.raises(ValueError):
        Rule(id="x", description="d", category="auth", distinct="tenant", then_action="seal")


def test_existing_rules_keep_their_behaviour_by_default():
    # The fields are additive: a rule written before this change is tenant-scoped
    # and tenant-audience, which is what it was.
    r = Rule(id="x", description="d", category="auth")
    assert (r.scope, r.audience, r.distinct, r.is_fanout) == ("tenant", "tenant", None, False)


# ── §5 / §7.4: the notifier that used to lie ───────────────────────────────


def _incident(engine_rules, tenant_count=3, *, same_tenant=False):
    """Drive one incident out of the engine.

    ``same_tenant`` feeds every event into ONE tenant, which is what a
    tenant-scoped rule needs to reach its threshold — spreading them is exactly
    the shape such a rule cannot see, and asking for an incident that way asks
    for one that will never arrive.
    """
    engine = RulesEngine(rules=engine_rules)
    ts = 1000.0
    fired = []
    for i in range(tenant_count):
        ts += 1
        fired += engine.feed(_ev("acme" if same_tenant else f"tenant{i}",
                                 "203.0.113.7", ts))
    assert fired, "the rules under test produced no incident"
    return fired[0]


def test_a_mandatory_incident_is_actually_sent():
    t = RecordingTransport()
    n = EmailAdminNotifier(transport=t, recipients=("ops@rationalboxes.com",))
    n.notify_admins_mandatory(_incident([FANOUT]))
    assert len(t.sent) == 1
    assert t.sent[0]["to"] == ["ops@rationalboxes.com"]
    assert "auth_fanout" in t.sent[0]["subject"]


def test_the_message_carries_no_content():
    # §5: the audit log holds identifiers and structure, never payload, and an
    # email is a copy that escapes every retention rule the platform has. This
    # is the constraint most likely to be relaxed by someone adding "just the
    # filename" to make an alert more useful.
    t = RecordingTransport()
    n = EmailAdminNotifier(transport=t, recipients=("ops@rationalboxes.com",))
    n.notify_admins_mandatory(_incident([FANOUT]))
    body = t.sent[0]["body"]
    assert "carries no file names" in body
    for leak in ("/", ".txt", ".pdf", "content", "payload"):
        assert leak not in body.split("This message deliberately")[0].replace(
            "source_addr", "").replace("audience", ""), f"{leak!r} leaked into the body"


def test_a_global_incident_says_platform_wide_rather_than_naming_a_tenant():
    t = RecordingTransport()
    n = EmailAdminNotifier(transport=t, recipients=("ops@rationalboxes.com",))
    n.notify_admins_mandatory(_incident([FANOUT]))
    assert "platform-wide" in t.sent[0]["subject"]
    assert "(spans tenants)" in t.sent[0]["body"]


def test_a_tenant_audience_incident_is_not_mailed_to_the_deployment_tier():
    t = RecordingTransport()
    n = EmailAdminNotifier(transport=t, recipients=("ops@rationalboxes.com",))
    n.notify_admins_mandatory(_incident([Rule(
        id="tenant_rule", description="d", category="auth", action="login",
        outcome="denied", group_by="source_addr", threshold=3, severity="serious")],
        same_tenant=True))
    assert t.sent == []


def test_a_warn_incident_does_not_page_anyone():
    # Mailing every warn is how an administrator learns to filter the whole
    # address into a folder they stop reading.
    warn = Rule(id="w", description="d", category="auth", action="login", outcome="denied",
                group_by="source_addr", distinct="tenant", threshold=3,
                scope="global", audience="deployment", severity="warn")
    t = RecordingTransport()
    n = EmailAdminNotifier(transport=t, recipients=("ops@rationalboxes.com",))
    n.notify_admins_mandatory(_incident([warn]))
    assert t.sent == []


def test_an_unconfigured_notifier_says_so_loudly(caplog):
    # THE STUB'S FAILURE MODE, and the reason this class exists. The old one
    # logged "MANDATORY admin email for serious incident" and sent nothing, so a
    # deployment could run for a year believing it was covered.
    n = EmailAdminNotifier(transport=None, recipients=())
    with caplog.at_level(logging.ERROR):
        n.notify_admins_mandatory(_incident([FANOUT]))
    assert any("NOT sent to anyone" in r.message for r in caplog.records)


def test_a_delivery_failure_is_not_swallowed(caplog):
    class Broken:
        def send(self, subject, body, to):
            raise OSError("connection refused")

    n = EmailAdminNotifier(transport=Broken(), recipients=("ops@rationalboxes.com",))
    with caplog.at_level(logging.ERROR):
        with pytest.raises(OSError):
            n.notify_admins_mandatory(_incident([FANOUT]))
    assert any("nobody was told" in r.message for r in caplog.records)
    assert n.sent == [], "a failed send must not be recorded as sent"


def test_from_config_returns_a_notifier_even_when_unconfigured():
    # Returning None would make callers check, and the one who forgets
    # reproduces the stub exactly.
    class Cfg:
        smtp_host = ""
        admin_emails = ()

    n = from_config(Cfg())
    assert isinstance(n, EmailAdminNotifier) and n.transport is None


def test_from_config_builds_a_transport_when_configured():
    class Cfg:
        smtp_host = "mail.example.com"
        smtp_port = 587
        smtp_from = "audit@example.com"
        smtp_user = ""
        smtp_password = ""
        smtp_tls = True
        admin_emails = ("ops@rationalboxes.com",)

    n = from_config(Cfg())
    assert n.transport is not None and n.recipients == ("ops@rationalboxes.com",)
