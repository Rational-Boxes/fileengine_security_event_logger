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

"""Emit-side helper: publish audit envelopes to the aggregating sink.

The Python doors (ldap_manager, discussion, mcp) use this to emit audit entries
to the same ``fileengine:audit`` stream the C++ core's RedisAuditSink publishes
to, per ``AUDIT_CONTRACT.md``. This is the Python counterpart of the core's
durable emitter.

XADD-success is the durability point (§6: a "queue-accepted" entry is durably
captured — Redis persists the stream), so ``publish()`` returns whether the entry
was accepted and never raises. A fail-closed caller (auth / user / permission /
admin) gates its guarded operation on that bool; a best-effort caller ignores it.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from . import codes

log = logging.getLogger("audit_service.publisher")

# Categories that are fail-closed by default (§6): the caller must not let the
# guarded operation proceed if publish() returns False.
FAIL_CLOSED = {"permission", "user", "auth", "admin"}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_envelope(*, category, action, outcome, actor, scope="tenant", tenant=None,
                   actor_roles=None, target_uid=None, target_name=None, target_type=None,
                   detail=None, source_iface=None, source_addr=None, request_id=None,
                   event_id=None, ts=None) -> dict:
    """Assemble + validate an audit envelope. Generates event_id/ts when omitted.
    Raises ValueError on an invalid enum or a missing scope/tenant pairing."""
    if category not in codes.CATEGORY:
        raise ValueError(f"unknown category: {category!r}")
    if outcome not in codes.OUTCOME:
        raise ValueError(f"unknown outcome: {outcome!r}")
    if target_type is not None and target_type not in codes.TARGET_TYPE:
        raise ValueError(f"unknown target_type: {target_type!r}")
    if scope not in ("tenant", "global"):
        raise ValueError(f"bad scope: {scope!r}")
    if scope == "tenant" and not tenant:
        raise ValueError("scope=tenant requires a tenant")
    if not actor:
        raise ValueError("actor is required")

    env = {
        "event_id": event_id or str(uuid.uuid4()),
        "ts": ts or _iso_now(),
        "scope": scope,
        "category": category,
        "action": action,
        "outcome": outcome,
        "actor": actor,
    }
    if tenant:
        env["tenant"] = tenant
    if actor_roles:
        env["actor_roles"] = list(actor_roles)
    if target_uid:
        env["target_uid"] = target_uid
    if target_name:
        env["target_name"] = target_name
    if target_type:
        env["target_type"] = target_type
    if detail is not None:
        env["detail"] = detail
    if source_iface:
        env["source_iface"] = source_iface
    if source_addr:
        env["source_addr"] = source_addr
    if request_id:
        env["request_id"] = request_id
    return env


class AuditPublisher:
    """Publishes audit envelopes to the aggregating Redis stream."""

    def __init__(self, *, host="localhost", port=6379, password="", db=0,
                 stream="fileengine:audit", redis_client=None):
        self.stream = stream
        self._redis = redis_client
        self._conn = dict(host=host, port=port, password=password or None, db=db)

    @classmethod
    def from_env(cls, env=None):
        """Build from the shared FILEENGINE_* environment (as the core uses)."""
        import os
        e = os.environ if env is None else env

        def _int(key, default):
            try:
                return int(e.get(key, default))
            except (TypeError, ValueError):
                return default

        return cls(host=e.get("FILEENGINE_REDIS_HOST", "localhost"),
                   port=_int("FILEENGINE_REDIS_PORT", 6379),
                   password=e.get("FILEENGINE_REDIS_PASSWORD", ""),
                   db=_int("FILEENGINE_REDIS_DB", 0),
                   stream=e.get("FILEENGINE_AUDIT_STREAM", "fileengine:audit"))

    def _client(self):
        if self._redis is None:
            import redis
            self._redis = redis.Redis(**self._conn)
        return self._redis

    def publish(self, **fields) -> bool:
        """Build + XADD an envelope. Returns True iff durably accepted by the
        stream. Never raises — a False return is the fail-closed signal."""
        try:
            env = build_envelope(**fields)
        except ValueError:
            log.exception("invalid audit fields; entry NOT published")
            return False
        try:
            self._client().xadd(self.stream, {"payload": json.dumps(env)})
            return True
        except Exception:
            log.exception("audit publish (XADD) failed; entry NOT durable")
            self._redis = None  # force reconnect on the next call
            return False
