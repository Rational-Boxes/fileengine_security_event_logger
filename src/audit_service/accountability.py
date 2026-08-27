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

"""The core's guaranteed accountability record, as this service consumes it.

See ``file_engine_core/design_documents/PROPOSAL_accountability_record.md``.

The core writes an append-only, hash-chained record **in the same transaction as
the operation it describes** for the operations that matter most to
accountability — who was granted access, who revoked it, who destroyed what. We
read it forward by cursor instead of relying on the Redis stream, which is the
whole point: the table is a transactional outbox, so no broker outage, outbox
overflow or lost node can lose a record, and this service can be rebuilt from
zero by resetting its cursor.

Two things live here:

* **The canonical form and chain hash**, mirroring
  ``file_engine_core/core/src/accountability.cpp`` byte for byte. If the two ever
  disagree, every verification fails — so both sides pin the same literal in
  their unit tests (``tests/test_accountability.py`` here,
  ``tests/accountability_tests.cpp`` there).
* **The per-batch verification** the consumer runs on every read (§4.3.2). A
  break in any of those checks is a security event in its own right, NOT a retry:
  a consumer that skips a gap to keep draining converts an integrity failure into
  silent data loss, which is the exact failure the record exists to prevent.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

# The reserved tenant key for the cross-tenant lifecycle chain. No real tenant
# can collide with it: the core strips '*' when deriving a schema name.
GLOBAL_CHAIN_KEY = "*global*"

# A stable namespace for deriving each record's audit event_id. (tenant, seq) is
# the idempotency key the proposal names, and uuid5 turns it into one
# deterministically — so a re-drain after a crash re-derives the same id and the
# audit table's UNIQUE (event_id, ts) absorbs it as a no-op.
_EVENT_NAMESPACE = uuid.UUID("6f4d1f8a-6c2f-5a7d-9b3e-2c1a4f7e8d05")


def canonical_json(obj) -> str:
    """The canonical JSON the core produces for ``detail``."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_record(*, seq: int, ts_micros: int, actor: str, actor_roles,
                     source_iface: str | None, source_addr: str | None,
                     category: str, action: str, target_uid: str | None,
                     target_type: str | None, principal: str | None,
                     detail: str | None, tenant: str | None) -> bytes:
    """The exact bytes the core hashed for this row.

    A compact JSON array with a fixed field order and no keys, so neither side
    can disagree about key ordering. Absent optional fields are JSON ``null``
    rather than ``""`` — "no principal" and "the principal named empty-string"
    must not collide, or two different records could hash identically.

    ``seq`` IS included, unlike the audit chain's own canonical form: it is
    claimed under the same lock that orders the chain, so it is part of what the
    row attests and renumbering must break verification.

    ``tenant`` is None for tenant-scoped rows (constant per chain, and the schema
    name is not reversible to the tenant id) and the tenant column for global rows.
    """
    roles = ",".join(actor_roles) if actor_roles else None
    fields = [seq, ts_micros, actor, roles, source_iface or None, source_addr or None,
              category, action, target_uid or None, target_type or None,
              principal or None, detail or None, tenant or None]
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def chain_hash(prev_hash: bytes | None, canonical: bytes) -> bytes:
    """``hash = SHA-256(prev_hash ‖ canonical)``; an empty prev contributes nothing."""
    h = hashlib.sha256()
    h.update(prev_hash or b"")
    h.update(canonical)
    return h.digest()


@dataclass
class CoreRecord:
    """One accountability record as returned by ``ListAccountabilityRecords``."""

    seq: int
    ts_micros: int
    ts: datetime
    actor: str
    actor_roles: list = field(default_factory=list)
    source_iface: str = ""
    source_addr: str = ""
    category: str = ""
    action: str = ""
    target_uid: str = ""
    target_type: str = ""
    principal: str = ""
    detail: str = "{}"
    prev_hash: bytes | None = None
    hash: bytes = b""
    global_tenant: str = ""

    @property
    def event_id(self) -> str:
        """Deterministic idempotency key, from the (tenant, seq) pair."""
        scope = self.global_tenant or ""
        return str(uuid.uuid5(_EVENT_NAMESPACE, f"{scope}:{self.seq}"))

    def recompute_hash(self, prev_hash: bytes | None) -> bytes:
        return chain_hash(prev_hash, canonical_record(
            seq=self.seq, ts_micros=self.ts_micros, actor=self.actor,
            actor_roles=self.actor_roles, source_iface=self.source_iface,
            source_addr=self.source_addr, category=self.category, action=self.action,
            target_uid=self.target_uid, target_type=self.target_type,
            principal=self.principal, detail=self.detail,
            tenant=self.global_tenant or None))


class IntegrityBreak(Exception):
    """A verification check failed on a batch of core records.

    This is deliberately an exception and not a return code. Every one of the
    §4.3.2 checks is a security event in its own right: a gap cannot occur
    naturally (the core claims seq under a lock that a rollback releases without
    advancing), a broken link means tampering or a write that bypassed that lock,
    and a ts that runs backwards means the monotonic guard failed or rows were
    reordered in transit. The correct response is to stop advancing that tenant's
    cursor and alarm — never to log it and step over it.
    """

    def __init__(self, tenant: str, seq: int | None, reason: str):
        self.tenant = tenant
        self.seq = seq
        self.reason = reason
        super().__init__(f"accountability integrity break for tenant {tenant!r} "
                         f"at seq {seq}: {reason}")


class StaleRead(Exception):
    """The read did not show a seq a queue hint asserted exists.

    Not an integrity break — the consumer is reading state that has not caught
    up, a replica behind the primary being the obvious case. Retry; do NOT
    advance the cursor. Without the hint's assertion this condition is invisible,
    because it looks exactly like "no new records".
    """


def verify_batch(tenant: str, records: list, *, last_seq: int | None,
                 last_hash: bytes | None, last_ts_micros: int | None,
                 asserted_seq: int | None = None) -> None:
    """Run every §4.3.2 check over one batch, in ``seq`` order.

    Verification happens HERE, on the consumer side, and not only at rest in the
    core, because that checks the record *and* its delivery in one operation: a
    transport that reorders, duplicates or drops is caught by the same mechanism
    that catches a tampered row.

    Raises ``IntegrityBreak`` on a gap, a non-increasing ts, a broken link or a
    row whose hash does not recompute; raises ``StaleRead`` when a hint asserted a
    seq this read cannot see.
    """
    prev_seq, prev_hash, prev_ts = last_seq, last_hash, last_ts_micros

    for rec in records:
        if prev_seq is not None and rec.seq != prev_seq + 1:
            raise IntegrityBreak(
                tenant, rec.seq,
                f"seq is not contiguous (expected {prev_seq + 1}); under the core's "
                "chain lock a gap cannot occur naturally, so this is a missing record")
        if prev_ts is not None and rec.ts_micros <= prev_ts:
            raise IntegrityBreak(
                tenant, rec.seq,
                f"ts did not increase (got {rec.ts_micros}, previous {prev_ts}); the "
                "monotonic guard failed or rows were reordered in transit, and the "
                "cursor's exactness no longer holds")
        if (rec.prev_hash or None) != (prev_hash or None):
            raise IntegrityBreak(tenant, rec.seq,
                                 "prev_hash does not match the previous row's hash — "
                                 "the chain is broken or forked")
        if rec.recompute_hash(prev_hash) != rec.hash:
            raise IntegrityBreak(tenant, rec.seq,
                                 "the row's hash does not recompute from the row — "
                                 "it was altered after commit")
        prev_seq, prev_hash, prev_ts = rec.seq, rec.hash, rec.ts_micros

    if asserted_seq and (prev_seq is None or prev_seq < asserted_seq):
        raise StaleRead(
            f"a hint asserted seq {asserted_seq} exists for tenant {tenant!r} but the "
            f"read reached only {prev_seq}; retrying rather than advancing the cursor")


def micros_to_datetime(ts_micros: int) -> datetime:
    return datetime.fromtimestamp(ts_micros / 1_000_000, tz=timezone.utc)


def datetime_to_micros(ts: datetime) -> int:
    return int(round(ts.timestamp() * 1_000_000))
