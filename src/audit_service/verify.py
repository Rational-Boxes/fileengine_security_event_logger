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

"""Verify a per-tenant audit hash chain (§7; surfaced as VerifyAuditChain, §9).

Walks the chain ordered by ``seq`` and checks, for every row: (1) linkage —
``prev_hash`` equals the previous row's ``row_hash``; (2) integrity — ``row_hash``
equals ``SHA-256(prev_hash ‖ canonical(row))`` recomputed from the row's content.
The first row that fails either check is the tamper point (an edited, removed, or
reordered row breaks the chain from there on).
"""
from __future__ import annotations

from dataclasses import dataclass

from .hashing import canonical_json, canonical_row, compute_row_hash
from .naming import schema_for_tenant

_COLS = ("seq, event_id, ts, category, action, outcome, actor, actor_roles, "
         "target_uid, target_name, target_type, detail, source_iface, "
         "source_addr, request_id, prev_hash, row_hash")


@dataclass
class ChainResult:
    ok: bool
    checked: int
    first_broken_seq: int | None = None
    reason: str | None = None


def verify_chain(conn, tenant: str | None) -> ChainResult:
    """Verify ``tenant``'s ``audit_log`` chain, or ``public.audit_log_global`` when
    ``tenant`` is None. Reads within the caller's transaction."""
    if tenant is None:
        parent, include_tenant = "audit_log_global", True
        query = f"SELECT {_COLS}, tenant FROM {parent} ORDER BY seq"
    else:
        parent, include_tenant = f'"{schema_for_tenant(tenant)}".audit_log', False
        query = f"SELECT {_COLS} FROM {parent} ORDER BY seq"

    checked = 0
    prev_row_hash: bytes | None = None
    with conn.cursor() as cur:  # note: a server-side cursor would stream very large logs
        cur.execute(query)
        for rec in cur:
            (seq, event_id, ts, category, action, outcome, actor, actor_roles,
             target_uid, target_name, target_type, detail, source_iface,
             source_addr, request_id, prev_hash, row_hash) = rec[:17]
            row_tenant = rec[17] if include_tenant else None
            prev_hash = bytes(prev_hash) if prev_hash is not None else None
            row_hash = bytes(row_hash) if row_hash is not None else None

            if prev_hash != prev_row_hash:
                return ChainResult(False, checked, seq,
                                   "prev_hash does not match the previous row's row_hash")

            canon = canonical_row(
                event_id=str(event_id), ts=ts, category=category, action=action,
                outcome=outcome, actor=actor, actor_roles=actor_roles,
                target_uid=target_uid, target_name=target_name, target_type=target_type,
                detail=(canonical_json(detail) if detail is not None else None),
                source_iface=source_iface, source_addr=source_addr, request_id=request_id,
                tenant=(row_tenant if include_tenant else None))
            if row_hash != compute_row_hash(prev_hash, canon):
                return ChainResult(False, checked, seq,
                                   "row_hash does not match the recomputed hash")
            prev_row_hash = row_hash
            checked += 1

    return ChainResult(True, checked)


def main() -> None:  # pragma: no cover
    """CLI: `audit-verify <tenant|--global>` → exits non-zero on a broken chain."""
    import sys

    from .config import Config, load_dotenv
    from . import db

    load_dotenv()
    arg = sys.argv[1] if len(sys.argv) > 1 else "--global"
    tenant = None if arg == "--global" else arg
    conn = db.connect(Config())
    try:
        res = verify_chain(conn, tenant)
    finally:
        conn.close()
    target = "global" if tenant is None else tenant
    if res.ok:
        print(f"OK: {target} chain verified ({res.checked} rows)")
        sys.exit(0)
    print(f"TAMPERED: {target} chain broke at seq={res.first_broken_seq} "
          f"after {res.checked} rows — {res.reason}")
    sys.exit(1)


if __name__ == "__main__":
    main()
