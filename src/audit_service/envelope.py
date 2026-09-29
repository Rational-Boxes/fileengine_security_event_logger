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

"""Parse + validate an audit envelope (the JSON published to the sink) into a
normalized ``AuditRow`` ready for insert.

The envelope contract is documented in ``AUDIT_CONTRACT.md``. A structurally
invalid envelope is a poison message: it can never be written, so the consumer
logs + drops it (and counts it) rather than blocking the stream forever. Every
recoverable ambiguity is normalized here (roles list → CSV, detail object →
canonical JSON, string codes → SMALLINT) so the writer only ever sees clean,
typed values.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from . import codes

log = logging.getLogger("audit_service.envelope")
from .hashing import canonical_json


class InvalidEnvelope(ValueError):
    """Envelope cannot be turned into a row (missing/at-odds fields)."""


@dataclass
class AuditRow:
    event_id: str            # canonical UUID string
    ts: datetime             # timezone-aware (UTC); emit-time, from the envelope
    category: int
    action: str
    outcome: int
    actor: str
    actor_roles: str | None
    target_uid: str | None
    target_name: str | None
    target_type: int | None
    detail: str | None       # canonical JSON text, or None
    source_iface: str | None
    source_addr: str | None
    request_id: str | None
    scope: str               # "tenant" | "global"
    tenant: str | None       # schema selector for scope=tenant; also a column on the global table


def _s(v, maxlen: int) -> str | None:
    if v is None or v == "":
        return None
    return str(v)[:maxlen]


def _refuse_name(value):
    """Always None, loudly when a producer tried.

    A warning rather than a rejected envelope: dropping the field keeps the
    event — which is a security record and must not be lost over a metadata
    field — while making the attempt visible so the producer gets fixed.
    """
    if value:
        log.warning("REFUSED target_name on an audit envelope: the log records "
                    "identifiers, never names. Emit target_uid and resolve the "
                    "name at read time.")
    return None


def _parse_ts(v) -> datetime:
    if isinstance(v, bool):  # bool is an int subclass; reject explicitly
        raise InvalidEnvelope(f"bad ts: {v!r}")
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v, tz=timezone.utc)
    if isinstance(v, str) and v:
        try:
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as e:
            raise InvalidEnvelope(f"bad ts: {v!r}") from e
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    raise InvalidEnvelope(f"bad ts: {v!r}")


def parse_envelope(env: dict) -> AuditRow:
    if not isinstance(env, dict):
        raise InvalidEnvelope("envelope is not a JSON object")

    def req(k: str):
        v = env.get(k)
        if v is None or v == "":
            raise InvalidEnvelope(f"missing required field: {k}")
        return v

    scope = env.get("scope", "tenant")
    if scope not in ("tenant", "global"):
        raise InvalidEnvelope(f"bad scope: {scope!r}")

    tenant = env.get("tenant")
    if scope == "tenant" and not tenant:
        raise InvalidEnvelope("scope=tenant requires a tenant")

    try:
        event_id = str(uuid.UUID(str(req("event_id"))))
    except ValueError as e:
        raise InvalidEnvelope(f"event_id is not a UUID: {env.get('event_id')!r}") from e

    category = codes.CATEGORY.get(req("category"))
    if category is None:
        raise InvalidEnvelope(f"unknown category: {env.get('category')!r}")

    outcome = codes.OUTCOME.get(req("outcome"))
    if outcome is None:
        raise InvalidEnvelope(f"unknown outcome: {env.get('outcome')!r}")

    target_type = None
    tt = env.get("target_type")
    if tt not in (None, ""):
        target_type = codes.TARGET_TYPE.get(tt)
        if target_type is None:
            raise InvalidEnvelope(f"unknown target_type: {tt!r}")

    roles = env.get("actor_roles")
    if isinstance(roles, (list, tuple)):
        roles = ",".join(str(r) for r in roles) or None
    elif roles is not None:
        roles = str(roles)

    # Always canonicalize detail so the hash computed at insert reproduces exactly
    # when verify reads the value back from JSONB (§7). A string that is itself
    # valid JSON is parsed first; otherwise it is stored as a JSON string value.
    detail = env.get("detail")
    if detail is not None:
        if isinstance(detail, str):
            try:
                detail = canonical_json(json.loads(detail))
            except ValueError:
                detail = canonical_json(detail)
        else:
            detail = canonical_json(detail)

    return AuditRow(
        event_id=event_id,
        ts=_parse_ts(req("ts")),
        category=category,
        action=str(req("action"))[:32],
        outcome=outcome,
        actor=str(req("actor"))[:255],
        actor_roles=roles,
        target_uid=_s(env.get("target_uid"), 64),
        # DROPPED AT INGEST, ALWAYS. The audit log records identifiers and
        # structure, never payload: a filename is party data
        # ("Acme_Corp_Contract_J_Smith.pdf"), and this log is immutable and
        # long-lived, so a name stored here is a name the platform has committed
        # to keeping and cannot easily remove.
        #
        # The core already stopped SENDING one — its AuditEntry has no
        # target_name and the comment there calls the old behaviour "a leak, not
        # a feature". But this pipe still accepted, stored and returned it, so
        # the property held only because one producer chose not to exercise it.
        # That is a convention, not a control, and the next service to publish
        # an envelope would not have known. Enforced here instead, at the one
        # point every producer passes through.
        #
        # Nothing populates it today (checked across the core, both bridges and
        # every Python service), so this drops nothing that is currently sent.
        # The column stays: existing rows keep their values and their hashes,
        # and rewriting history to enforce a rule retroactively would break the
        # chain that makes the log worth having.
        target_name=_refuse_name(env.get("target_name")),
        target_type=target_type,
        detail=detail,
        source_iface=_s(env.get("source_iface"), 16),
        source_addr=_s(env.get("source_addr"), 64),
        request_id=_s(env.get("request_id"), 64),
        scope=scope,
        tenant=(str(tenant) if tenant else None),
    )
