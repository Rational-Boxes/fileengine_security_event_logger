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

"""Is the accountability drain actually running, and is any chain halted?

**An unmonitored backstop is not a backstop.** A drain that silently stops
running produces exactly the failure it exists to prevent — core security
records going unrecorded — and it looks perfectly healthy while doing it. So
does an integrity halt nobody is paged about. Both have to be answerable from
outside the process.

The state is read from ``accountability_cursor`` rather than from counters held
in the drain process, and that is the load-bearing choice here. The poller, the
consumer and the query API are three separate processes; a counter in one of them
is invisible to the ``/metrics`` endpoint in another, and would reset to a
healthy-looking zero on every restart. The cursor table is shared, durable, and
already the thing the drain updates on every successful pass — so "when did this
last work?" is a column, not an inference.

Two failure modes this is built to make loud rather than quiet:

* **A stopped drain.** ``last_polled_at`` stops moving. Nothing errors, no
  exception is thrown, and the audit log simply stops gaining core records.
  Alert on ``fileengine_accountability_drain_age_seconds`` exceeding a few poll
  intervals.

  Measured on ``last_polled_at``, NOT ``updated_at``: the latter moves only when
  records are appended, so a tenant that is merely quiet is indistinguishable
  from one whose drain has died. Most tenants are quiet most of the time, so
  conflating the two makes the alarm permanently red — and an alarm that is
  always on is one nobody reads.
* **A halted chain.** ``halted_reason`` is set and the cursor is frozen on
  purpose, awaiting operator acknowledgement.
  ``fileengine_accountability_halted_chains`` going above zero is a security
  page, not a capacity one.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("audit_service.drain_health")

# A chain that has not been POLLED in this long is treated as stale by /readyz.
# Comfortably above any sane poll interval so a slow pass or a restart does not
# flap, but far below "nobody would notice" — the heartbeat moves on every clean
# pass, so this genuinely means the drain stopped rather than that nothing
# happened to record.
DEFAULT_STALE_AFTER_S = 300


def snapshot(conn) -> dict:
    """Current drain state for every chain.

    Returns ``{"chains": [...], "halted": [...], "oldest_pass_age_s": float|None}``.
    Never raises: a monitoring probe that throws is a monitoring outage, and this
    is called from readiness and metrics paths where that would be worse than a
    missing number.
    """
    out = {"chains": [], "halted": [], "oldest_pass_age_s": None, "error": None}
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tenant, last_seq, recorded_until, "
                "       EXTRACT(EPOCH FROM (now() - last_polled_at))::double precision, "
                "       halted_reason, halted_seq, "
                "       EXTRACT(EPOCH FROM (now() - halted_at))::double precision, "
                "       EXTRACT(EPOCH FROM (now() - updated_at))::double precision "
                "FROM accountability_cursor ORDER BY tenant")
            rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001 — a probe must not raise
        # Includes "table does not exist", which is the honest answer before the
        # drain has ever run: no chains, no claim about health.
        out["error"] = str(e)
        return out

    oldest = None
    for (tenant, last_seq, recorded_until, polled_age_s, reason, halted_seq,
         halted_age_s, progress_age_s) in rows:
        age = float(polled_age_s) if polled_age_s is not None else None
        out["chains"].append({
            "tenant": tenant,
            "last_seq": int(last_seq or 0),
            "recorded_until_micros": int(recorded_until or 0),
            # Seconds since this chain was last polled — the liveness signal.
            "age_s": age,
            # Seconds since a record was last appended — progress, not liveness.
            # Large and growing here is normal for a quiet tenant.
            "idle_s": float(progress_age_s) if progress_age_s is not None else None,
            "halted": reason is not None,
        })
        if reason is not None:
            out["halted"].append({
                "tenant": tenant,
                "seq": int(halted_seq) if halted_seq is not None else None,
                "reason": reason,
                "age_s": float(halted_age_s) if halted_age_s is not None else None,
            })
        # A halted chain's cursor is frozen deliberately, so its age is not
        # evidence of a stopped drain — excluding it keeps the two alarms
        # independent instead of making one mask the other.
        if reason is None and age is not None and (oldest is None or age > oldest):
            oldest = age
    out["oldest_pass_age_s"] = oldest
    return out


def is_healthy(state: dict, stale_after_s: float = DEFAULT_STALE_AFTER_S) -> tuple:
    """``(ok, reason)`` for a readiness probe.

    A halted chain makes the service NOT ready. That is deliberate and worth
    stating, because it is the arguable call: the query API still serves fine
    with a halted chain, so one could call it ready. But the service's job is to
    hold a complete, verified security log, and while a chain is halted it is
    knowingly not doing that. Draining traffic away from an instance that cannot
    honour its own guarantee is the safer default, and the condition needs a
    human either way.
    """
    if state.get("error"):
        return True, f"drain state unavailable ({state['error']})"
    if state["halted"]:
        names = ", ".join(h["tenant"] for h in state["halted"])
        return False, f"integrity halt on: {names}"
    age = state.get("oldest_pass_age_s")
    if age is not None and age > stale_after_s:
        return False, f"drain is stale ({int(age)}s since a cursor last advanced)"
    return True, "ok"


def collect(conn_factory, stale_after_s: float = DEFAULT_STALE_AFTER_S):
    """Build a ``metrics.install`` collector over the drain state."""

    def _collect(m) -> None:
        conn = None
        try:
            conn = conn_factory()
            state = snapshot(conn)
        except Exception as e:  # noqa: BLE001
            log.warning("drain metrics unavailable: %s", e)
            state = {"chains": [], "halted": [], "oldest_pass_age_s": None, "error": str(e)}
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        m.gauge("fileengine_accountability_halted_chains",
                "Accountability chains stopped on an integrity break, awaiting "
                "operator acknowledgement. Above zero is a security page.",
                len(state["halted"]))
        m.gauge("fileengine_accountability_chains",
                "Accountability chains this consumer tracks a cursor for.",
                len(state["chains"]))

        age = state.get("oldest_pass_age_s")
        # -1 means "no chain to report on", which is different from "zero
        # seconds since the last pass" and must not be alertable as healthy.
        m.gauge("fileengine_accountability_drain_age_seconds",
                "Seconds since the least recently advanced chain's cursor moved. "
                "Rising without bound means the drain has stopped; -1 means there "
                "are no chains yet.",
                age if age is not None else -1)

        for chain in state["chains"]:
            labels = {"tenant": chain["tenant"]}
            m.gauge("fileengine_accountability_cursor_seq",
                    "Highest accountability seq this consumer has durably recorded.",
                    chain["last_seq"], labels)
            m.gauge("fileengine_accountability_chain_halted",
                    "1 when this chain is halted on an integrity break.",
                    1 if chain["halted"] else 0, labels)

    return _collect
