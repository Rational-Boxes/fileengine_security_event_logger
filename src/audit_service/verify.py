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

from . import catalog
from .chain import ChainWalker, record_to_dict, select_cols
from .naming import schema_for_tenant


@dataclass
class ChainResult:
    ok: bool
    checked: int
    first_broken_seq: int | None = None
    reason: str | None = None
    # The archived link this walk started from (SPEC_retention_and_archival §8);
    # None when the chain's first row is still in Postgres.
    anchored_at_seq: int | None = None


def verify_chain(conn, tenant: str | None) -> ChainResult:
    """Verify ``tenant``'s ``audit_log`` chain, or ``public.audit_log_global`` when
    ``tenant`` is None. Reads within the caller's transaction.

    Once retention has archived the oldest rows, the first row left links to the
    last ARCHIVED row, not to NULL — so the walk starts from the catalog's anchor.
    Starting from NULL would report every retained chain as tampered."""
    if tenant is None:
        parent, include_tenant = "audit_log_global", True
    else:
        parent, include_tenant = f'"{schema_for_tenant(tenant)}".audit_log', False
    anchor = catalog.anchor(conn, parent)
    walker = ChainWalker(anchor.last_row_hash if anchor else None,
                         anchor.last_seq if anchor else None)

    # Named (server-side) cursor: a chain is ~1M rows in production, and a
    # client-side cursor would hold all of them in memory at once.
    with conn.cursor(name="audit_verify_chain") as cur:
        cur.execute(f"SELECT {select_cols(include_tenant)} FROM {parent} ORDER BY seq")
        while True:
            recs = cur.fetchmany(2000)
            if not recs:
                break
            for rec in recs:
                if not walker.step_dict(record_to_dict(rec, include_tenant), include_tenant):
                    return ChainResult(False, walker.checked, walker.broken_seq,
                                       walker.reason,
                                       anchor.last_seq if anchor else None)

    return ChainResult(True, walker.checked, anchored_at_seq=anchor.last_seq if anchor else None)


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
