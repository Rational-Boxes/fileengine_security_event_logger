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

"""End-to-end consumer tests against real Redis + Postgres (skipped if either is
unreachable). Each test uses a unique throwaway stream/group so it never touches
the production audit stream."""
from __future__ import annotations

import json
import os
import uuid

import pytest

from audit_service.consumer import AuditConsumer, RedisAuditSource
from audit_service.naming import schema_for_tenant

pytestmark = pytest.mark.live


@pytest.fixture()
def test_stream(config, redis_client):
    """Point the config at a private stream/group and clean it up after."""
    name = f"test:audit:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    config.audit_stream = name
    config.audit_group = "audit-writer-test"
    config.read_block_ms = 200
    yield config
    try:
        redis_client.delete(name)
    except Exception:
        pass


def _publish(redis_client, stream, env):
    redis_client.xadd(stream, {"payload": json.dumps(env)})


def _env(tenant, **extra):
    return {"event_id": str(uuid.uuid4()), "ts": "2026-07-10T09:00:00Z", "tenant": tenant,
            "category": "auth", "action": "login_failure", "outcome": "denied",
            "actor": "mallory", **extra}


def test_end_to_end_drain_writes_and_acks(test_stream, redis_client, pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    stream = test_stream.audit_stream
    _publish(redis_client, stream, _env(audit_schema, source_addr="10.0.0.9"))
    _publish(redis_client, stream, _env(audit_schema, source_addr="10.0.0.9"))

    consumer = AuditConsumer(test_stream, connect_fn=lambda: pg_conn)
    source = RedisAuditSource(test_stream)
    source.ensure_group()
    acked = consumer.process(source)

    assert acked == 2
    assert consumer.written == 2
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT count(*) FROM "{schema}".audit_log WHERE action = %s',
                    ("login_failure",))
        assert cur.fetchone()[0] == 2

    # Everything acked → nothing pending for the group.
    pending = redis_client.xpending(stream, test_stream.audit_group)
    assert pending["pending"] == 0


def test_poison_message_is_dropped_not_blocking(test_stream, redis_client, pg_conn, audit_schema):
    schema = schema_for_tenant(audit_schema)
    stream = test_stream.audit_stream
    _publish(redis_client, stream, {"garbage": True})          # poison
    _publish(redis_client, stream, _env(audit_schema))          # good

    consumer = AuditConsumer(test_stream, connect_fn=lambda: pg_conn)
    source = RedisAuditSource(test_stream)
    source.ensure_group()
    acked = consumer.process(source)

    assert acked == 2
    assert consumer.dropped == 1 and consumer.written == 1
    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT count(*) FROM "{schema}".audit_log')
        assert cur.fetchone()[0] == 1
    assert redis_client.xpending(stream, test_stream.audit_group)["pending"] == 0


def test_redelivery_via_reprocess_is_idempotent(test_stream, redis_client, pg_conn, audit_schema):
    """Simulate crash-before-ack: read without acking, then reprocess the pending
    entry — the row must not double-insert."""
    schema = schema_for_tenant(audit_schema)
    stream = test_stream.audit_stream
    env = _env(audit_schema)
    _publish(redis_client, stream, env)

    source = RedisAuditSource(test_stream)
    source.ensure_group()

    # First delivery: write + commit, but do NOT ack (simulate crash).
    from audit_service.writer import write_batch
    from audit_service.envelope import parse_envelope
    entries = source.read(count=10, block_ms=200)
    write_batch(pg_conn, [parse_envelope(e) for _id, e in entries], {})
    pg_conn.commit()

    # Redelivery: the same entry is still pending; reprocessing must no-op.
    reclaimed = source._client().xreadgroup(
        source.group, source.consumer, {stream: "0"}, count=10)
    consumer = AuditConsumer(test_stream, connect_fn=lambda: pg_conn)
    # feed the pending entry back through the writer path
    from audit_service.envelope import parse_envelope as pe
    pending_rows = []
    for _s, msgs in reclaimed:
        for _mid, fields in msgs:
            pending_rows.append(pe(json.loads(fields[b"payload"])))
    write_batch(pg_conn, pending_rows, {})
    pg_conn.commit()

    with pg_conn.cursor() as cur:
        cur.execute(f'SELECT count(*) FROM "{schema}".audit_log')
        assert cur.fetchone()[0] == 1
