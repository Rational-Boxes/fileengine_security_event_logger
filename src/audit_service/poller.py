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

"""The scheduled accountability drain (§4.3). Launch: ``audit-accountability``.

Two ways in, and only one of them is a guarantee:

* **The scheduled poll** — every ``AUDIT_PULL_INTERVAL_S``, drain every chain to
  current. This is the guarantee path. It does not care whether Redis is up,
  whether a hint was published, or whether this process was running when the
  record was written.
* **The queue hint** — a best-effort ``accountability.committed`` on the
  fail-open file-activity stream, carrying nothing but a tenant and a committed
  seq. On receipt we do **not** process the payload; we read the core table
  immediately, out of schedule. That buys latency for the rules engine without
  making anything depend on the hint arriving.

The hint also carries a freshness assertion. It says "at least seq N exists"; if
the read does not show N, we are reading state that has not caught up — a replica
behind the primary, say — and we retry rather than advance the cursor. Without
the assertion that condition is invisible, because it looks exactly like "no new
records".

This runs as its own process, a separate consumer group from the writer, so its
poll cadence is independent of stream traffic and a stalled writer does not stall
the guarantee path.
"""
from __future__ import annotations

import json
import logging
import time

from . import db
from .accountability import GLOBAL_CHAIN_KEY, IntegrityBreak, StaleRead
from .core_client import CoreAccountabilityClient
from .cursors import CursorStore
from .puller import AccountabilityPuller

log = logging.getLogger("audit_service.poller")


class HintSource:
    """Reads ``accountability.committed`` hints off the file-activity stream.

    A separate consumer group from anything else on that stream, so we see every
    hint independently — and so nothing we do can affect another consumer's
    delivery.
    """

    def __init__(self, config, consumer_name: str | None = None):
        self.config = config
        self.stream = config.events_stream
        self.group = config.hint_group
        self.consumer = consumer_name or (config.consumer_name + "-acct")
        self._redis = None

    def _client(self):
        if self._redis is None:
            import redis
            self._redis = redis.Redis(
                host=self.config.redis_host, port=self.config.redis_port,
                password=self.config.redis_password or None, db=self.config.redis_db)
        return self._redis

    def ensure_group(self) -> None:
        import redis
        try:
            # Start at "$": hints are only useful for records committed from now
            # on. Replaying old ones would just trigger drains for work the
            # scheduled poll has long since collected.
            self._client().xgroup_create(self.stream, self.group, id="$", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    def read(self, count: int = 256, block_ms: int = 1000) -> dict:
        """Return ``{tenant: highest_asserted_seq}`` from the pending hints.

        Collapsed per tenant on purpose: fifty hints for one tenant still mean a
        single drain to current, and the highest seq is the strongest assertion
        among them.
        """
        resp = self._client().xreadgroup(self.group, self.consumer, {self.stream: ">"},
                                         count=count, block=block_ms)
        asserted: dict = {}
        msg_ids = []
        for _stream, messages in resp or []:
            for msg_id, fields in messages:
                msg_ids.append(msg_id)
                raw = fields.get(b"payload") or fields.get("payload")
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                try:
                    event = json.loads(raw) if raw else {}
                except ValueError:
                    continue
                if event.get("type") != "accountability.committed":
                    continue          # every other file-activity event is not ours
                tenant = event.get("tenant") or "default"
                seq = int(event.get("accountability_seq") or 0)
                if seq > asserted.get(tenant, 0):
                    asserted[tenant] = seq
        if msg_ids:
            # Ack everything we read, ours or not. A hint carries no data we
            # could lose: if we drop one, the scheduled poll still collects the
            # record. Leaving them pending would grow the group's PEL forever.
            self._client().xack(self.stream, self.group, *msg_ids)
        return asserted


class AccountabilityPoller:
    def __init__(self, config, connect_fn=None, puller=None):
        self.config = config
        self._connect = connect_fn or (lambda: db.connect(config))
        self._conn = None
        self._heads: dict = {}
        self._schema_ready = False
        self.cursors = CursorStore()
        self.puller = puller if puller is not None else AccountabilityPuller(
            config, CoreAccountabilityClient(config), self.cursors)
        self.last_successful_pass = 0.0   # for the staleness alarm below

    def _conn_get(self):
        if self._conn is None or getattr(self._conn, "closed", False):
            self._conn = self._connect()
            self._schema_ready = False
            self._heads = {}
        if not self._schema_ready:
            self.cursors.ensure_schema(self._conn)
            self._conn.commit()
            self._schema_ready = True
        return self._conn

    def _reset_conn(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None
        # A rolled-back batch may have advanced the in-memory chain heads for
        # rows that never committed; drop the cache so it reseeds from committed
        # state.
        self._heads = {}

    def pass_once(self, asserted: dict | None = None) -> int:
        """One drain pass over every chain. Commits, then advances the cursors.

        The cursor is staged inside the same transaction as the rows, so the
        commit here is what makes both durable together. Ordering the commit
        after the write and before anything else is what makes redelivery on
        crash at-least-once rather than at-most-once.
        """
        conn = self._conn_get()
        drained = 0
        try:
            if asserted:
                # Hint-driven: drain exactly the named tenants, asserting the
                # seq each hint promised.
                for tenant, seq in asserted.items():
                    key = None if tenant == GLOBAL_CHAIN_KEY else tenant
                    try:
                        drained += self.puller.drain(conn, key, self._heads,
                                                     asserted_seq=seq)
                    except StaleRead:
                        # Not an error worth failing the pass over: come back on
                        # the next tick without advancing.
                        conn.rollback()
                    except IntegrityBreak:
                        conn.rollback()
            else:
                drained += self.puller.drain_all(conn, self._heads)
            conn.commit()
            self.last_successful_pass = time.time()
        except Exception:
            log.exception("accountability drain pass failed; retrying next tick")
            self._reset_conn()
            return 0
        if drained:
            log.info("drained %d accountability record(s)", drained)
        return drained

    def run_forever(self, hints: HintSource | None = None, backoff_s: float = 2.0) -> None:
        if hints is not None:
            try:
                hints.ensure_group()
            except Exception:
                log.exception("could not join the hint stream — falling back to the "
                              "scheduled poll alone, which costs latency only")
                hints = None
        log.info("accountability poller — core=%s:%s interval=%ss hints=%s",
                 self.config.core_grpc_host, self.config.core_grpc_port,
                 self.config.pull_interval_s, "on" if hints else "off")

        next_scheduled = 0.0
        while True:
            try:
                asserted = {}
                if hints is not None:
                    # Blocks briefly, so a hint shortens the wait without making
                    # the loop spin.
                    asserted = hints.read(block_ms=min(
                        1000, self.config.pull_interval_s * 1000))
                now = time.time()
                if asserted:
                    self.pass_once(asserted)
                if now >= next_scheduled:
                    self.pass_once()
                    next_scheduled = time.time() + self.config.pull_interval_s
                elif hints is None:
                    time.sleep(min(1.0, max(0.0, next_scheduled - now)))
            except Exception:
                log.exception("accountability poller cycle failed; backing off %.1fs",
                              backoff_s)
                self._reset_conn()
                time.sleep(backoff_s)


def acknowledge_main() -> None:
    """``audit-accountability-ack <tenant>`` — clear an integrity halt.

    The deliberate human step §4.3.2 asks for. Draining resumes from the cursor,
    which never moved while the chain was halted, so nothing is skipped by
    acknowledging — the records after the break are re-read and re-verified.

    With no argument it lists what is halted, because the first thing an
    operator needs is to see the break and its seq, not to clear it.
    """
    import sys

    from .config import Config, load_dotenv
    from .cursors import CursorStore

    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    config = Config()
    store = CursorStore()
    conn = db.connect(config)
    try:
        store.ensure_schema(conn)
        conn.commit()
        halted = store.halted(conn)
        if len(sys.argv) < 2:
            if not halted:
                print("No accountability chain is halted.")
                return
            print("Halted chains — inspect the named seq before acknowledging:\n")
            for tenant, at, seq, reason in halted:
                print(f"  {tenant}\n    halted at : {at}\n    seq       : {seq}\n"
                      f"    reason    : {reason}\n")
            print("Acknowledge with: audit-accountability-ack <tenant>")
            return

        tenant = sys.argv[1]
        if store.acknowledge(conn, tenant):
            conn.commit()
            print(f"Acknowledged the integrity halt on {tenant!r}. Draining resumes "
                  f"from the cursor; the records after the break will be re-read and "
                  f"re-verified.")
        else:
            print(f"{tenant!r} is not halted — nothing to acknowledge.")
    finally:
        conn.close()


def main() -> None:
    from .config import Config, load_dotenv

    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    config = Config()
    poller = AccountabilityPoller(config)
    poller.run_forever(HintSource(config))


if __name__ == "__main__":
    main()
