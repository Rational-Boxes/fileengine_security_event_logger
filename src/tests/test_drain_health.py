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

"""Is a stopped drain and a halted chain actually visible from outside?

The failure this guards against is the quiet one: the drain stops, nothing
raises, no error is logged, and the audit log simply stops gaining core records
while every probe stays green. These tests assert that both conditions turn into
a number and a 503 rather than a silence.
"""
from __future__ import annotations

import os

import pytest

from audit_service import drain_health
from audit_service.cursors import CursorStore
from audit_service.metrics import Metrics

pytestmark = pytest.mark.live

TENANT = f"drainz_it_{os.getpid()}"


@pytest.fixture()
def store(pg_conn):
    s = CursorStore()
    s.ensure_schema(pg_conn)
    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM accountability_cursor WHERE tenant LIKE %s",
                    ("drainz_it_%",))
    pg_conn.commit()
    yield s
    with pg_conn.cursor() as cur:
        cur.execute("DELETE FROM accountability_cursor WHERE tenant LIKE %s",
                    ("drainz_it_%",))
    pg_conn.commit()


def _seed(pg_conn, store, tenant, *, seq=5, age_sql="now()", idle_sql=None):
    """Seed a chain. ``age_sql`` ages last_polled_at (liveness); ``idle_sql``
    ages updated_at (progress). They are deliberately independent — a quiet
    tenant is old on the second and current on the first."""
    state = store.get(pg_conn, tenant)
    state.advance(seq, 1756296000000000, b"\x01" * 32)
    store.stage(pg_conn, tenant, state)
    store.touch_polled(pg_conn, tenant)
    with pg_conn.cursor() as cur:
        cur.execute(f"UPDATE accountability_cursor SET last_polled_at = {age_sql}, "
                    f"updated_at = {idle_sql or age_sql} WHERE tenant = %s", (tenant,))
    pg_conn.commit()


def test_a_freshly_advanced_chain_is_healthy(pg_conn, store):
    _seed(pg_conn, store, TENANT)
    state = drain_health.snapshot(pg_conn)
    ok, reason = drain_health.is_healthy(state)
    assert ok and reason == "ok"
    assert any(c["tenant"] == TENANT and c["last_seq"] == 5 for c in state["chains"])


def test_a_stopped_drain_is_not_ready(pg_conn, store):
    """The whole point: a drain that stopped throws nothing and looks idle."""
    _seed(pg_conn, store, TENANT, age_sql="now() - interval '2 hours'")
    state = drain_health.snapshot(pg_conn)
    assert state["oldest_pass_age_s"] > 3600
    ok, reason = drain_health.is_healthy(state)
    assert not ok and "stale" in reason


def test_a_merely_quiet_tenant_is_still_healthy(pg_conn, store):
    """The bug this separation fixes.

    A tenant nobody is changing permissions on has an ancient updated_at — no
    records to append — while its drain is polling perfectly happily. Measuring
    staleness on progress rather than on the heartbeat made every idle tenant
    read as a dead drain, which in a real deployment is most of them, and an
    alarm that is always on is one nobody reads.
    """
    _seed(pg_conn, store, TENANT,
          age_sql="now()",                              # polled just now
          idle_sql="now() - interval '30 days'")        # nothing recorded in a month
    state = drain_health.snapshot(pg_conn)
    ours = next(c for c in state["chains"] if c["tenant"] == TENANT)
    assert ours["idle_s"] > 86400, "it really has been idle for a long time"
    assert ours["age_s"] < 60, "but it was polled seconds ago"
    ok, reason = drain_health.is_healthy(state)
    assert ok and reason == "ok", "idle is not the same as stopped"


def test_a_halted_chain_is_not_ready_and_names_itself(pg_conn, store):
    _seed(pg_conn, store, TENANT)
    store.halt(pg_conn, TENANT, 7, "prev_hash does not match the previous row's hash")
    pg_conn.commit()

    state = drain_health.snapshot(pg_conn)
    assert [h["tenant"] for h in state["halted"]] == [TENANT]
    assert state["halted"][0]["seq"] == 7
    ok, reason = drain_health.is_healthy(state)
    assert not ok
    # The operator has to be able to act on this, which means the reason has to
    # carry the chain, not just "not ready".
    assert TENANT in reason


def test_a_halted_chain_does_not_also_read_as_stale(pg_conn, store):
    """A halted cursor is frozen deliberately. Counting its age as staleness
    would make one alarm mask the other and hide which is actually wrong.

    Aged absurdly far back on purpose: this runs against a shared dev database
    that may hold other chains, so the assertion has to be "ours is not the
    maximum" rather than "there is no maximum" — which would only hold on an
    otherwise-empty table and would fail the moment a real stack was running.
    """
    ancient = "now() - interval '3650 days'"
    _seed(pg_conn, store, TENANT, age_sql=ancient)
    store.halt(pg_conn, TENANT, 7, "hash does not recompute")
    pg_conn.commit()

    state = drain_health.snapshot(pg_conn)
    ours = next(c for c in state["chains"] if c["tenant"] == TENANT)
    assert ours["halted"] and ours["age_s"] > 3600, "our chain really is old and halted"
    oldest = state["oldest_pass_age_s"]
    assert oldest is None or oldest < ours["age_s"], \
        "the halted chain is excluded from the staleness calculation"

    ok, reason = drain_health.is_healthy(state)
    assert not ok and "integrity halt" in reason


def test_acknowledging_restores_readiness(pg_conn, store):
    _seed(pg_conn, store, TENANT)
    store.halt(pg_conn, TENANT, 7, "prev_hash does not match")
    pg_conn.commit()
    assert not drain_health.is_healthy(drain_health.snapshot(pg_conn))[0]

    assert store.acknowledge(pg_conn, TENANT) is True
    pg_conn.commit()
    assert drain_health.is_healthy(drain_health.snapshot(pg_conn))[0]


def test_metrics_expose_the_halt_and_the_age(config, pg_conn, store):
    _seed(pg_conn, store, TENANT)
    store.halt(pg_conn, TENANT, 7, "prev_hash does not match")
    pg_conn.commit()

    from audit_service import db

    m = Metrics("audit_service")
    # The collector opens its own connection, matching how /metrics is served
    # from a different process than the drain.
    drain_health.collect(lambda: db.connect(config))(m)
    text = "\n".join(m._lines)

    assert "fileengine_accountability_halted_chains" in text
    assert "fileengine_accountability_drain_age_seconds" in text
    assert f'tenant="{TENANT}"' in text
    # The halted gauge for this chain must read 1, or the page never fires.
    assert any(line.startswith("fileengine_accountability_chain_halted")
               and f'tenant="{TENANT}"' in line and line.rstrip().endswith(" 1")
               for line in text.splitlines())


def test_a_probe_failure_is_unknown_not_unhealthy(pg_conn, store):
    """Failing readiness because the probe itself could not run would take the
    service down for a monitoring fault."""
    state = {"chains": [], "halted": [], "oldest_pass_age_s": None,
             "error": "relation does not exist"}
    ok, reason = drain_health.is_healthy(state)
    assert ok and "unavailable" in reason


def test_snapshot_never_raises_on_a_broken_connection(pg_conn, store):
    class Broken:
        def cursor(self):
            raise RuntimeError("connection is closed")

    state = drain_health.snapshot(Broken())
    assert state["error"] and state["chains"] == []
