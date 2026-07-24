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

"""Per-tenant tamper-evidence hash chain (usage_logging_and_auditing §7).

``row_hash = SHA-256( prev_hash ‖ canonical(row) )``. Any edit or removal of a row
breaks the chain, detectable by ``verify.verify_chain`` (surfaced as the §9
VerifyAuditChain op). ``seq`` is NOT part of the hash (it is DB-assigned); ordering
is instead enforced by the ``prev_hash`` linkage, so reordering rows also breaks
the chain.

The canonical form must be reproducible *identically* from an ``AuditRow`` (at
insert) and from a stored DB row (at verify). It therefore uses the row's content
columns only (never seq / prev_hash / row_hash), a fixed field order, epoch-micro
timestamps, and a canonical JSON for ``detail``. The schema-implicit tenant is
excluded for tenant-scoped rows (constant per chain, and the schema name is not
reversible to the tenant id); the ``tenant`` *column* is included for global rows.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime


def canonical_json(obj) -> str:
    """The single canonical JSON serialization used for detail everywhere."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _ts_micros(ts: datetime) -> int:
    return int(round(ts.timestamp() * 1_000_000))


def canonical_row(*, event_id: str, ts: datetime, category: int, action: str,
                  outcome: int, actor: str, actor_roles, target_uid, target_name,
                  target_type, detail, source_iface, source_addr, request_id,
                  tenant) -> bytes:
    """Deterministic bytes for a row's content. ``detail`` is the canonical JSON
    *string* (or None); ``tenant`` is None for tenant-scoped rows and the tenant
    column value for global rows."""
    fields = [event_id, _ts_micros(ts), category, action, outcome, actor,
              actor_roles, target_uid, target_name, target_type, detail,
              source_iface, source_addr, request_id, tenant]
    return json.dumps(fields, separators=(",", ":")).encode("utf-8")


def compute_row_hash(prev_hash: bytes | None, canonical: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(prev_hash or b"")
    h.update(canonical)
    return h.digest()
