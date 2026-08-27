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

"""The audit consumer: drain the aggregating sink → write → commit → ack.

A background worker (separate process, like CSAI's ingest and the discussion
consumer) that reads the ``fileengine:audit`` Redis Stream through a consumer
group and, for each batch:

  1. parses envelopes into rows (poison messages are logged + dropped/acked —
     they can never be written, and must not block the stream forever);
  2. writes the valid rows in one transaction and commits;
  3. acks the valid messages *only after* the commit succeeds.

At-least-once delivery + the ``(event_id, ts)`` idempotency key mean a crash
between commit and ack simply re-delivers and the re-insert no-ops. A DB failure
leaves the valid messages un-acked so they are retried on the next delivery.

``process`` is a single pure-ish cycle (unit/live-tested); ``run_forever`` is the
loop with reconnect/backoff. Launch: ``audit-consumer``.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Callable, List, Tuple

from . import db
from .accountability import GLOBAL_CHAIN_KEY, IntegrityBreak, StaleRead
from .core_client import CoreAccountabilityClient
from .cursors import CursorStore
from .envelope import InvalidEnvelope, parse_envelope
from .puller import AccountabilityPuller
from .writer import write_batch

log = logging.getLogger("audit_service.consumer")

Entry = Tuple[str, dict]


class RedisAuditSource:
    """XREADGROUP over the aggregating audit stream for the writer's group."""

    def __init__(self, config, consumer_name: str | None = None):
        self.config = config
        self.stream = config.audit_stream
        self.group = config.audit_group
        self.consumer = consumer_name or config.consumer_name
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
            self._client().xgroup_create(self.stream, self.group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    @staticmethod
    def _parse(fields) -> dict:
        raw = fields.get(b"payload") or fields.get("payload")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            return {}

    def read(self, count: int = 256, block_ms: int = 5000) -> List[Entry]:
        resp = self._client().xreadgroup(self.group, self.consumer, {self.stream: ">"},
                                         count=count, block=block_ms)
        out: List[Entry] = []
        for _stream, messages in resp or []:
            for msg_id, fields in messages:
                mid = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else msg_id
                out.append((mid, self._parse(fields)))
        return out

    def ack(self, msg_ids: List[str]) -> None:
        if msg_ids:
            self._client().xack(self.stream, self.group, *msg_ids)


class AuditConsumer:
    def __init__(self, config, connect_fn: Callable | None = None, puller=None):
        self.config = config
        self._connect = connect_fn or (lambda: db.connect(config))
        self._conn = None
        self._heads: dict = {}  # per-chain head row_hash cache (§7); reseeds from DB
        self.written = 0   # rows handed to write_batch (pre-dedup)
        self.dropped = 0   # poison messages that could not be parsed
        self._schema_ready = False
        # The core's accountability pull. Injectable so tests can drive it
        # without a live core; None disables precedence entirely, which is only
        # ever right in a unit test.
        self._cursors = CursorStore()
        self._puller = puller if puller is not None else AccountabilityPuller(
            config, CoreAccountabilityClient(config), self._cursors)

    def _conn_get(self):
        if self._conn is None or getattr(self._conn, "closed", False):
            self._conn = self._connect()
            self._schema_ready = False
        if not self._schema_ready:
            # The cursor table is ours, created on demand like the daily audit
            # partitions. Committed immediately so a later rollback of a batch
            # cannot take the table with it.
            self._cursors.ensure_schema(self._conn)
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
        # A rolled-back batch may have advanced heads for rows that never
        # committed; drop the cache so it reseeds from the committed DB state.
        self._heads = {}

    def _drain_core_first(self, conn, rows) -> None:
        """Precedence (§4.3.3): the core table is the FIRST authority.

        On any incoming queue event, from any subsystem, the core's
        accountability records are consulted and drained BEFORE that event is
        recorded — never the reverse, and never partially.

        The reason is this log's own chain. It is tamper-evident across all
        sources, and a chain records the order in which it was written.
        Appending a subsystem event while authoritative core records that
        happened EARLIER are still unread would place them out of temporal order
        permanently, and a tamper-evident structure cannot be re-sorted after the
        fact — that is precisely what it exists to prevent. So the core becomes
        the anchor everything else is sequenced against.

        Scoped per tenant (§4.3.5): an event for tenant X drains X's chain, not
        everyone's. A backlog in one tenant never delays recording for another,
        and the work per event is bounded by that tenant's own backlog.
        """
        if self._puller is None:
            return
        tenants = {r.tenant for r in rows if r.scope == "tenant" and r.tenant}
        # The global chain first: it carries tenant deletions, and acting on one
        # before draining a tenant we are about to forget avoids re-creating that
        # tenant's cursor moments after dropping it.
        for tenant in [None] + sorted(tenants):
            try:
                self._puller.drain(conn, tenant, self._heads)
            except (IntegrityBreak, StaleRead):
                # Deliberately re-raised: recording a subsystem event while the
                # core's own records for that tenant are unread or unverifiable
                # would break the ordering guarantee this whole rule buys. A core
                # outage already stops the platform, so blocking here costs
                # nothing that was not already lost.
                raise
            except Exception:
                log.exception("accountability drain failed for tenant %r before "
                              "recording queue events", tenant)
                raise

    def process(self, source: RedisAuditSource) -> int:
        """Run one read→drain→write→ack cycle. Returns the number of messages acked."""
        entries = source.read(self.config.read_count, self.config.read_block_ms)
        if not entries:
            return 0

        rows, valid_ids, poison_ids = [], [], []
        for msg_id, env in entries:
            try:
                rows.append(parse_envelope(env))
                valid_ids.append(msg_id)
            except InvalidEnvelope as e:
                log.error("dropping poison audit message %s: %s", msg_id, e)
                poison_ids.append(msg_id)

        # Poison can never be written; drop it (ack) with a loud log + counter.
        if poison_ids:
            source.ack(poison_ids)
            self.dropped += len(poison_ids)

        if rows:
            try:
                conn = self._conn_get()
                # Drain and append every pending authoritative core record FIRST,
                # in the same transaction, so the interleave is atomic.
                self._drain_core_first(conn, rows)
                write_batch(conn, rows, self._heads)
                conn.commit()
            except Exception:
                log.exception("audit write failed; not acking %d msg(s) — will retry",
                              len(valid_ids))
                self._reset_conn()  # rollback happens on close; force a fresh conn
                return len(poison_ids)
            source.ack(valid_ids)
            self.written += len(rows)

        return len(valid_ids) + len(poison_ids)

    def run_forever(self, source: RedisAuditSource, backoff_s: float = 2.0) -> None:
        source.ensure_group()
        log.info("audit consumer — stream=%s group=%s consumer=%s",
                 self.config.audit_stream, self.config.audit_group, self.config.consumer_name)
        while True:
            try:
                self.process(source)
            except Exception:
                log.exception("audit consumer cycle failed; backing off %.1fs", backoff_s)
                self._reset_conn()
                time.sleep(backoff_s)


def main() -> None:
    from .config import Config, load_dotenv

    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    config = Config()
    AuditConsumer(config).run_forever(RedisAuditSource(config))


if __name__ == "__main__":
    main()
