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

"""The acknowledgement queue against a real Postgres (§4).

What the offline state-machine tests cannot check: that the state is genuinely
the FOLD of an append-only table rather than a column, that an item with no
transitions reads as `raised` (the state that matters most and the one a plain
join would drop), and that the backlog counts what is actually waiting.
"""
from __future__ import annotations

import pytest

from audit_service import queue as q
from audit_service import security
from audit_service.engine import Incident

pytestmark = pytest.mark.live

ACTOR = "james@rationalboxes.com"


def _incident(conn, *, audience="deployment", severity="serious", tenant=None,
              rule_id="qtest_rule"):
    security.ensure_tables(conn)
    q.ensure_tables(conn)
    store = security.PgIncidentStore(lambda: conn)
    store.record(Incident(
        rule_id=rule_id, tenant=tenant, group_by="source_addr",
        group_key="203.0.113.5", severity=severity, response="flag", count=9,
        window_s=300, actor=None, last_ts="2026-09-29T12:00:00Z", dry_run=False,
        action_taken="flagged", description="queue test",
        scope="global" if tenant is None else "tenant", audience=audience,
        distinct_values=("a", "b", "c")))
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM public.security_incidents WHERE rule_id = %s "
                    "ORDER BY id DESC LIMIT 1", (rule_id,))
        return cur.fetchone()[0]


@pytest.fixture()
def clean(pg_conn):
    security.ensure_tables(pg_conn)
    q.ensure_tables(pg_conn)
    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM public.security_incidents WHERE rule_id LIKE 'qtest_%'")
    pg_conn.commit()
    yield pg_conn
    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM public.security_incidents WHERE rule_id LIKE 'qtest_%'")
    pg_conn.commit()


def test_an_incident_with_no_transitions_reads_as_raised(clean):
    # `raised` is the ABSENCE of a transition, not a row written when the rule
    # fires. That keeps the engine's write path unchanged and means an incident
    # predating this table reads as exactly what it is.
    iid = _incident(clean)
    assert q.current_state(clean, iid) == q.RAISED
    assert q.history(clean, iid) == []


def test_the_state_is_the_fold_of_the_transitions(clean):
    iid = _incident(clean)
    q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ACTOR))
    assert q.current_state(clean, iid) == q.ACKNOWLEDGED
    q.transition(clean, q.Transition(iid, q.CUSTOMER_CONFIRMED, ACTOR,
                                     asserted_by=ACTOR, counterparty="Ops at Acme"))
    assert q.current_state(clean, iid) == q.CUSTOMER_CONFIRMED
    assert [h["state"] for h in q.history(clean, iid)] == \
        [q.ACKNOWLEDGED, q.CUSTOMER_CONFIRMED]


def test_history_keeps_every_step_including_the_refusal(clean):
    # erasure_ack records complied=false rather than silence; a decline here is
    # an entry with an actor, a time and a reason.
    iid = _incident(clean)
    q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ACTOR))
    q.transition(clean, q.Transition(iid, q.DECLINED, ACTOR, reason="false positive: NAT egress"))
    hist = q.history(clean, iid)
    assert [h["state"] for h in hist] == [q.ACKNOWLEDGED, q.DECLINED]
    assert hist[-1]["reason"] == "false positive: NAT egress"
    assert hist[-1]["actor"] == ACTOR
    assert q.current_state(clean, iid) == q.DECLINED


def test_an_illegal_transition_is_refused_and_records_nothing(clean):
    iid = _incident(clean)
    with pytest.raises(q.QueueError):
        q.transition(clean, q.Transition(iid, q.APPROVED, ACTOR))
    assert q.history(clean, iid) == [], "a refused transition must leave no trace"
    assert q.current_state(clean, iid) == q.RAISED


def test_a_customer_confirmation_needs_a_named_counterparty(clean):
    # §4: it records an ASSERTION. An assertion with nobody named is a checkbox.
    iid = _incident(clean)
    q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ACTOR))
    with pytest.raises(q.QueueError, match="counterparty"):
        q.transition(clean, q.Transition(iid, q.CUSTOMER_CONFIRMED, ACTOR, asserted_by=ACTOR))


def test_a_decline_needs_a_reason(clean):
    iid = _incident(clean)
    q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ACTOR))
    with pytest.raises(q.QueueError, match="reason"):
        q.transition(clean, q.Transition(iid, q.DECLINED, ACTOR))


def test_completion_needs_evidence(clean):
    iid = _incident(clean)
    for t in (q.Transition(iid, q.ACKNOWLEDGED, ACTOR),
              q.Transition(iid, q.CUSTOMER_CONFIRMED, ACTOR, asserted_by=ACTOR,
                           counterparty="Ops at Acme"),
              q.Transition(iid, q.APPROVED, ACTOR, reason="confirmed in writing")):
        q.transition(clean, t)
    with pytest.raises(q.QueueError, match="evidence"):
        q.transition(clean, q.Transition(iid, q.COMPLETED, ACTOR))
    q.transition(clean, q.Transition(iid, q.COMPLETED, ACTOR,
                                     evidence="redaction-run-2026-09-29-01"))
    assert q.current_state(clean, iid) == q.COMPLETED
    assert q.history(clean, iid)[-1]["evidence"] == "redaction-run-2026-09-29-01"


def test_a_transition_needs_an_actor(clean):
    iid = _incident(clean)
    with pytest.raises(q.QueueError, match="actor"):
        q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ""))


def test_a_transition_on_an_unknown_incident_is_refused(clean):
    with pytest.raises(q.QueueError, match="no such incident"):
        q.transition(clean, q.Transition(999_999_999, q.ACKNOWLEDGED, ACTOR))


# ── the backlog, which is the point ────────────────────────────────────────


def test_an_untouched_incident_counts_as_unacknowledged(clean):
    # The LEFT JOIN LATERAL exists for this: a plain join would drop items with
    # no transitions, which is the state that matters most.
    _incident(clean)
    b = q.backlog(clean)
    assert b["unacknowledged"] >= 1
    assert b["counts"][q.RAISED] >= 1


def test_acknowledging_moves_it_out_of_unacknowledged(clean):
    iid = _incident(clean)
    before = q.backlog(clean)["unacknowledged"]
    q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ACTOR))
    after = q.backlog(clean)
    assert after["unacknowledged"] == before - 1
    assert after["counts"][q.ACKNOWLEDGED] >= 1


def test_an_approved_item_is_still_waiting(clean):
    # It has to be carried out elsewhere. Counting it as done would hide exactly
    # the items waiting on the cloud-B redaction step.
    iid = _incident(clean)
    for t in (q.Transition(iid, q.ACKNOWLEDGED, ACTOR),
              q.Transition(iid, q.CUSTOMER_CONFIRMED, ACTOR, asserted_by=ACTOR,
                           counterparty="Ops"),
              q.Transition(iid, q.APPROVED, ACTOR)):
        q.transition(clean, t)
    assert q.backlog(clean)["needs_a_human"] >= 1


def test_a_declined_item_stops_counting(clean):
    iid = _incident(clean)
    q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ACTOR))
    open_before = q.backlog(clean)["open"]
    q.transition(clean, q.Transition(iid, q.DECLINED, ACTOR, reason="NAT egress"))
    assert q.backlog(clean)["open"] == open_before - 1


def test_the_backlog_only_counts_deployment_audience_by_default(clean):
    # A tenant's own incidents are not this queue's business.
    _incident(clean, audience="tenant", tenant="acme", rule_id="qtest_tenant_only")
    b = q.backlog(clean, audience="deployment")
    assert b["counts"][q.RAISED] == 0


def test_older_than_hours_excludes_fresh_items(clean):
    _incident(clean)
    assert q.backlog(clean, older_than_hours=0)["unacknowledged"] >= 1
    # Nothing created in this test is an hour old, so the alertable count is 0 —
    # which is the number §4 asks to alert on.
    assert q.backlog(clean, older_than_hours=1)["unacknowledged"] == 0


# ── listing ────────────────────────────────────────────────────────────────


def test_items_carry_their_state_and_the_legal_next_moves(clean):
    iid = _incident(clean)
    rows = [r for r in q.items(clean) if r["id"] == iid]
    assert rows and rows[0]["state"] == q.RAISED
    assert rows[0]["next_states"] == [q.ACKNOWLEDGED]
    q.transition(clean, q.Transition(iid, q.ACKNOWLEDGED, ACTOR))
    rows = [r for r in q.items(clean) if r["id"] == iid]
    assert rows[0]["state"] == q.ACKNOWLEDGED
    assert set(rows[0]["next_states"]) == {q.CUSTOMER_CONFIRMED, q.DECLINED}
    assert rows[0]["last_actor"] == ACTOR


def test_items_can_be_filtered_by_state(clean):
    a = _incident(clean, rule_id="qtest_a")
    b = _incident(clean, rule_id="qtest_b")
    q.transition(clean, q.Transition(b, q.ACKNOWLEDGED, ACTOR))
    raised = [r["id"] for r in q.items(clean, state=q.RAISED)]
    acked = [r["id"] for r in q.items(clean, state=q.ACKNOWLEDGED)]
    assert a in raised and b not in raised
    assert b in acked and a not in acked


def test_an_unknown_state_filter_is_refused(clean):
    with pytest.raises(q.QueueError):
        q.items(clean, state="nearly_done")
