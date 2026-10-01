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

"""The acknowledgement procedure (§4), offline.

The state machine is the requirement here, not an implementation detail: "always
a human validated and confirmed procedure" is true only if the ORDER is enforced.
A permissive graph with an audit trail would satisfy every test that only checks
that transitions get recorded, and would turn the procedure back into a list.

The storage half is in test_queue_live.py, which needs Postgres.
"""
from __future__ import annotations

import pytest

from audit_service.queue import (
    ACKNOWLEDGED,
    APPROVED,
    COMPLETED,
    CUSTOMER_CONFIRMED,
    DECLINED,
    OPEN_STATES,
    RAISED,
    STATES,
    TERMINAL_STATES,
    TRANSITIONS,
    QueueError,
    legal,
    validate,
)


# ── the order is the procedure ─────────────────────────────────────────────


def test_the_happy_path_is_the_documented_one():
    # raised -> acknowledged -> customer_confirmed -> approved -> completed
    chain = [RAISED, ACKNOWLEDGED, CUSTOMER_CONFIRMED, APPROVED, COMPLETED]
    for a, b in zip(chain, chain[1:]):
        assert legal(a, b), f"{a} -> {b} must be allowed"


def test_an_item_cannot_be_approved_without_being_looked_at():
    # THE REQUIREMENT. Approving straight from raised is the shortcut that makes
    # "human validated" a claim rather than a property.
    assert not legal(RAISED, APPROVED)
    with pytest.raises(QueueError):
        validate(RAISED, APPROVED)


def test_a_redaction_cannot_be_approved_before_the_customer_is_confirmed():
    # §3.3: "the administrator confirms it with the end customer, and only then
    # is it approved". Acknowledged -> approved would collapse exactly the step
    # the redaction design exists to protect.
    assert not legal(ACKNOWLEDGED, APPROVED)


def test_an_acknowledged_item_can_be_declined_without_inventing_a_phone_call():
    # A false positive should be declinable at the point somebody looks at it.
    # Forcing it through customer_confirmed first would mean recording an
    # assertion that nobody made.
    assert legal(ACKNOWLEDGED, DECLINED)


def test_a_confirmed_item_can_still_be_declined():
    # The confirmation is not the decision. An administrator may speak to the
    # customer and then decline.
    assert legal(CUSTOMER_CONFIRMED, DECLINED)


def test_terminal_states_are_terminal():
    for state in TERMINAL_STATES:
        assert TRANSITIONS[state] == ()
        for other in STATES:
            if other != state:
                assert not legal(state, other), f"{state} must not move to {other}"


def test_completed_is_only_reachable_from_approved():
    sources = [s for s in STATES if legal(s, COMPLETED)]
    assert sources == [APPROVED]


def test_nothing_can_go_backwards():
    order = {RAISED: 0, ACKNOWLEDGED: 1, CUSTOMER_CONFIRMED: 2,
             APPROVED: 3, DECLINED: 3, COMPLETED: 4}
    for frm, tos in TRANSITIONS.items():
        for to in tos:
            assert order[to] > order[frm], f"{frm} -> {to} goes backwards"


def test_re_entering_the_same_state_is_refused():
    # It would append a second identical entry and make the history lie about
    # how many people looked.
    with pytest.raises(QueueError, match="already"):
        validate(ACKNOWLEDGED, ACKNOWLEDGED)


def test_an_unknown_state_is_refused():
    with pytest.raises(QueueError, match="unknown state"):
        validate(RAISED, "probably_fine")


def test_the_refusal_says_what_is_allowed():
    # An operator hitting this needs to know the next legal move, not just that
    # they were wrong.
    with pytest.raises(QueueError) as e:
        validate(RAISED, COMPLETED)
    assert ACKNOWLEDGED in str(e.value)


def test_every_state_is_reachable_from_raised():
    # A state nobody can reach is a state that lies about the procedure.
    seen, frontier = {RAISED}, [RAISED]
    while frontier:
        for nxt in TRANSITIONS[frontier.pop()]:
            if nxt not in seen:
                seen.add(nxt)
                frontier.append(nxt)
    assert seen == set(STATES)


def test_open_and_terminal_partition_the_states():
    assert set(OPEN_STATES) | set(TERMINAL_STATES) == set(STATES)
    assert not set(OPEN_STATES) & set(TERMINAL_STATES)


def test_approved_counts_as_open_because_the_work_is_not_done():
    # An approved redaction still has to be carried out elsewhere. Counting it as
    # finished would hide exactly the items waiting on the cloud-B step.
    assert APPROVED in OPEN_STATES
    assert COMPLETED in TERMINAL_STATES
