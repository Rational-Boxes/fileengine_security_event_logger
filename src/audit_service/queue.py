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

"""The queue of things waiting on a human, and the record of what they decided.

PROPOSAL_deployment_admin_signal.md §4 — "A notification is not a procedure" —
and PROPOSAL_system_administration_application.md §3.2. It lives HERE rather
than in the console because §5 says so plainly: an API on `audit_service` for
the queue and its transitions, "so the interface adopts it later rather than the
queue being built inside a UI that does not exist yet".

**Transitions are append-only, and the shape is copied from `erasure_ack`** —
which §4 names as "the shape to copy rather than invent". Its defining property
is that `complied = false` is RECORDED rather than inferred from silence, and
the same applies here: a `declined` is an entry with an actor, a time and a
reason, not an absence of an `approved`.

So the current state is the fold of the transitions, never a column somebody
sets. `set_incident_status` — which this replaces for deployment items — wrote a
status straight onto the incident row, which cannot answer "who acknowledged
this, and when" and cannot distinguish "declined" from "nobody looked".

**`customer_confirmed` records an ASSERTION, not a fact.** §4 is explicit and
§3.3 repeats it: the confirmation happens on a call or in writing, outside any
system. What can honestly be stored is that a named administrator stated it
happened, and when. Every name in this module is chosen so a reader cannot
mistake it for verification — the field is `asserted_by`, the state is
`customer_confirmed` rather than `customer_verified`, and the API refuses a
transition into it without a named counterparty.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger("audit_service.queue")

# ── states ─────────────────────────────────────────────────────────────────

RAISED = "raised"                          # the rule fired; nobody has looked
ACKNOWLEDGED = "acknowledged"              # a named administrator has seen it
CUSTOMER_CONFIRMED = "customer_confirmed"  # an administrator ASSERTS the customer confirmed
APPROVED = "approved"                      # the decision
DECLINED = "declined"                      # the other decision, recorded the same way
COMPLETED = "completed"                    # carried out, with a pointer to evidence

STATES = (RAISED, ACKNOWLEDGED, CUSTOMER_CONFIRMED, APPROVED, DECLINED, COMPLETED)

#: Legal moves. Enumerated rather than "anything to anything with an audit
#: trail", because the ORDER is the procedure: an item cannot be approved by
#: somebody who never acknowledged it, and a redaction cannot be approved before
#: a customer confirmation is on record. That is the whole requirement — "always
#: a human validated and confirmed procedure" — and a permissive graph would
#: turn it back into a list with a history.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    RAISED: (ACKNOWLEDGED,),
    # An administrator who has looked may decline outright. Not every item needs
    # a customer: a false positive is declined at this point and should not
    # require pretending a call happened.
    ACKNOWLEDGED: (CUSTOMER_CONFIRMED, DECLINED),
    CUSTOMER_CONFIRMED: (APPROVED, DECLINED),
    # Terminal. An approved item is carried out elsewhere (this application
    # executes nothing), and `completed` is where that comes back.
    APPROVED: (COMPLETED,),
    DECLINED: (),
    COMPLETED: (),
}

#: States that still need somebody. The backlog is measured over these.
OPEN_STATES = (RAISED, ACKNOWLEDGED, CUSTOMER_CONFIRMED, APPROVED)

#: States where the item is finished either way.
TERMINAL_STATES = (DECLINED, COMPLETED)


class QueueError(Exception):
    """A transition the procedure does not allow."""


def legal(from_state: str, to_state: str) -> bool:
    return to_state in TRANSITIONS.get(from_state, ())


def validate(from_state: str, to_state: str) -> None:
    if to_state not in STATES:
        raise QueueError(f"unknown state: {to_state!r}")
    if from_state == to_state:
        # Not an error worth an exception elsewhere, but here it would append a
        # second identical entry and make the history lie about how many people
        # looked.
        raise QueueError(f"already {to_state}")
    if not legal(from_state, to_state):
        allowed = ", ".join(TRANSITIONS.get(from_state, ())) or "nothing (terminal)"
        raise QueueError(f"cannot go {from_state} -> {to_state}; from {from_state} "
                         f"the only moves are: {allowed}")


# ── storage ────────────────────────────────────────────────────────────────

_ACK_DDL = """
CREATE TABLE IF NOT EXISTS public.incident_ack (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  BIGINT       NOT NULL REFERENCES public.security_incidents(id)
                              ON DELETE CASCADE,
    state        VARCHAR(24)  NOT NULL,
    -- WHO did it. Never blank: a transition with no actor is the thing this
    -- table exists to make impossible.
    actor        VARCHAR(255) NOT NULL,
    -- Recorded either way, exactly as erasure_ack records complied = false
    -- rather than leaving silence to be interpreted.
    reason       TEXT         NOT NULL DEFAULT '',
    -- For customer_confirmed ONLY: who the administrator says they spoke to.
    -- The platform did not verify this and the column name must not suggest it
    -- did; `asserted_by` is the administrator making the claim.
    asserted_by  VARCHAR(255) NOT NULL DEFAULT '',
    counterparty VARCHAR(255) NOT NULL DEFAULT '',
    -- For completed: a pointer to the evidence, e.g. a redaction run id.
    evidence     TEXT         NOT NULL DEFAULT '',
    at           TIMESTAMPTZ  NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS idx_incident_ack_incident ON public.incident_ack(incident_id, id);
"""

#: Same advisory lock as security.ensure_tables, for the same reason: idempotent
#: DDL is not concurrency-safe DDL, and more than one process calls this.
_DDL_LOCK = 0x5ECA_11D2


def ensure_tables(conn) -> None:
    with conn.cursor() as cur:
        cur.execute("SELECT pg_advisory_xact_lock(%s)", (_DDL_LOCK,))
        cur.execute(_ACK_DDL)
    conn.commit()


@dataclass(frozen=True)
class Transition:
    incident_id: int
    state: str
    actor: str
    reason: str = ""
    asserted_by: str = ""
    counterparty: str = ""
    evidence: str = ""


def current_state(conn, incident_id: int) -> str:
    """The item's state now: the LAST transition, or `raised` if there is none.

    `raised` is the absence of a transition rather than a row written when the
    rule fires. That keeps the engine's write path unchanged — it records an
    incident, not a queue item — and means an incident that predates this table
    reads as `raised`, which is exactly what it is.
    """
    with conn.cursor() as cur:
        cur.execute("SELECT state FROM public.incident_ack WHERE incident_id = %s "
                    "ORDER BY id DESC LIMIT 1", (incident_id,))
        row = cur.fetchone()
    return row[0] if row else RAISED


def history(conn, incident_id: int) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("SELECT state, actor, reason, asserted_by, counterparty, evidence, at "
                    "FROM public.incident_ack WHERE incident_id = %s ORDER BY id",
                    (incident_id,))
        rows = cur.fetchall()
    keys = ["state", "actor", "reason", "asserted_by", "counterparty", "evidence", "at"]
    out = []
    for r in rows:
        d = dict(zip(keys, r))
        d["at"] = d["at"].isoformat()
        out.append(d)
    return out


def transition(conn, t: Transition) -> dict:
    """Append one transition, refusing anything the procedure disallows.

    The checks are here rather than in the API so they hold for any caller,
    including a future CLI or the interface when it is built.
    """
    if not t.actor:
        raise QueueError("a transition needs an actor")

    with conn.cursor() as cur:
        cur.execute("SELECT audience FROM public.security_incidents WHERE id = %s",
                    (t.incident_id,))
        row = cur.fetchone()
    if row is None:
        raise QueueError(f"no such incident: {t.incident_id}")

    from_state = current_state(conn, t.incident_id)
    validate(from_state, t.state)

    if t.state == CUSTOMER_CONFIRMED:
        # §4: "customer_confirmed records an assertion, not a fact." An
        # assertion with nobody named is not an assertion, it is a checkbox —
        # so both the asserting administrator and the counterparty are required.
        if not t.counterparty:
            raise QueueError("customer_confirmed needs the counterparty the "
                             "administrator says they spoke to")
        if not t.asserted_by:
            raise QueueError("customer_confirmed needs the administrator asserting it")
    if t.state == DECLINED and not t.reason:
        # A refusal without a reason is indistinguishable from a mistake a year
        # later. erasure_ack records complied=false WITH detail for the same
        # reason.
        raise QueueError("a decline needs a reason")
    if t.state == COMPLETED and not t.evidence:
        raise QueueError("completed needs a pointer to the evidence")

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO public.incident_ack "
            "(incident_id, state, actor, reason, asserted_by, counterparty, evidence) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id, at",
            (t.incident_id, t.state, t.actor, t.reason, t.asserted_by,
             t.counterparty, t.evidence))
        new_id, at = cur.fetchone()
    conn.commit()
    log.info("incident %s: %s -> %s by %s", t.incident_id, from_state, t.state, t.actor)
    return {"id": new_id, "incident_id": t.incident_id, "from_state": from_state,
            "state": t.state, "actor": t.actor, "at": at.isoformat()}


# ── the backlog, which is the point ────────────────────────────────────────


def backlog(conn, *, older_than_hours: float = 0.0,
            audience: str = "deployment") -> dict:
    """What is still waiting, and for how long.

    §4: "A queue whose backlog is invisible is a log. The count of `raised` items
    older than N hours is the number worth alerting on, and it is the one number
    that cannot be satisfied by sending more email."

    So this is deliberately not a list — it is the counts, per state, plus the
    oldest item's age. A caller that wants the items asks for them; a caller
    that wants to know whether anyone is keeping up asks for this.
    """
    cutoff_sql = ""
    params: list = [audience]
    if older_than_hours > 0:
        cutoff_sql = " AND i.ts < now() - make_interval(secs => %s)"
        params.append(float(older_than_hours) * 3600.0)

    # LEFT JOIN on the latest transition, so an incident with no transitions
    # counts as `raised` rather than being missed — which is the state that
    # matters most and the one a plain join would drop.
    sql = f"""
        SELECT COALESCE(a.state, '{RAISED}') AS state,
               COUNT(*) AS n,
               MAX(EXTRACT(EPOCH FROM (now() - i.ts))) AS oldest_s
        FROM public.security_incidents i
        LEFT JOIN LATERAL (
            SELECT state FROM public.incident_ack
            WHERE incident_id = i.id ORDER BY id DESC LIMIT 1
        ) a ON true
        WHERE i.audience = %s{cutoff_sql}
        GROUP BY COALESCE(a.state, '{RAISED}')
    """
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()

    counts = {s: 0 for s in STATES}
    oldest = {s: 0.0 for s in STATES}
    for state, n, oldest_s in rows:
        if state in counts:
            counts[state] = int(n)
            oldest[state] = float(oldest_s or 0.0)

    open_n = sum(counts[s] for s in OPEN_STATES)
    return {
        "audience": audience,
        "older_than_hours": older_than_hours,
        "counts": counts,
        "oldest_seconds": oldest,
        "open": open_n,
        # The single number §4 asks for, named so an alert rule can bind to it
        # without knowing the rest of the shape.
        "unacknowledged": counts[RAISED],
        "needs_a_human": open_n,
    }


def items(conn, *, state: Optional[str] = None, audience: str = "deployment",
          limit: int = 100) -> list[dict]:
    """Queue items with their current state, newest first."""
    if state is not None and state not in STATES:
        raise QueueError(f"unknown state: {state!r}")
    params: list = [audience]
    having = ""
    if state is not None:
        having = " AND COALESCE(a.state, %s) = %s"
        params += [RAISED, state]
    sql = f"""
        SELECT i.id, i.ts, i.tenant, i.rule_id, i.severity, i.group_by, i.group_key,
               i.match_count, i.scope, i.description,
               COALESCE(a.state, '{RAISED}') AS state, a.actor, a.at
        FROM public.security_incidents i
        LEFT JOIN LATERAL (
            SELECT state, actor, at FROM public.incident_ack
            WHERE incident_id = i.id ORDER BY id DESC LIMIT 1
        ) a ON true
        WHERE i.audience = %s{having}
        ORDER BY i.ts DESC LIMIT %s
    """
    params.append(limit)
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    keys = ["id", "ts", "tenant", "rule_id", "severity", "group_by", "group_key",
            "match_count", "scope", "description", "state", "last_actor", "last_at"]
    out = []
    for r in rows:
        d = dict(zip(keys, r))
        d["ts"] = d["ts"].isoformat()
        d["last_at"] = d["last_at"].isoformat() if d["last_at"] else None
        d["next_states"] = list(TRANSITIONS.get(d["state"], ()))
        out.append(d)
    return out
