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

"""Re-link and re-hash an existing chain so it verifies again (remediation only).

READ THIS BEFORE RUNNING IT.

A hash chain's whole value is that it cannot be repaired. Recomputing the links
over rows that are already stored produces a chain that verifies — and it would
verify just as happily if a row had been edited or removed by someone hostile
before the repair ran. **Every guarantee about the period before a repair is
destroyed by the repair**, whatever the rows say afterwards.

That is an acceptable trade exactly once: when the breakage has a known,
non-malicious cause that has been fixed, and the log's value going forward
outweighs its value as evidence of a period nobody is relying on. Here the cause
was two writers appending to one chain without serialization (see
``writer._lock_chain``), which orphaned rows without touching their content —
verification failed on linkage only, never on integrity, which is what makes the
content trustworthy enough to re-link.

What this does NOT do: change any row's content. It rewrites ``prev_hash`` and
``row_hash`` only, and refuses to run if any row fails its own integrity check
under the hash it already carries — because a content mismatch is the one thing
this tool must never paper over.

It records itself. The last thing a repair writes is an ``admin`` event into the
chain it just repaired, naming the rows relinked and the seq the chain first
broke at, so the repair is visible in the log rather than inferred from its
absence. A counterfeit that declares itself is a different object from one that
does not.
"""
from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass

from .hashing import canonical_json, canonical_row, compute_row_hash
from .naming import schema_for_tenant
from .verify import verify_chain
from .writer import _lock_chain, GLOBAL_KEY

log = logging.getLogger(__name__)

_COLS = ("seq, ts, event_id, category, action, outcome, actor, actor_roles, "
         "target_uid, target_name, target_type, detail, source_iface, "
         "source_addr, request_id, prev_hash, row_hash")


@dataclass
class RechainResult:
    chain: str
    rows: int = 0
    relinked: int = 0
    was_broken_at: int | None = None
    ok_before: bool = False
    ok_after: bool = False


def _parent_and_key(tenant: str | None) -> tuple[str, str]:
    if tenant is None:
        return "audit_log_global", GLOBAL_KEY
    return f'"{schema_for_tenant(tenant)}".audit_log', tenant


def rechain(conn, tenant: str | None, *, dry_run: bool = False) -> RechainResult:
    """Re-link ``tenant``'s chain (or the global chain) in ``seq`` order.

    Runs inside the caller's transaction and does NOT commit — the caller decides,
    which is what makes ``--dry-run`` honest rather than a separate code path.
    """
    parent, key = _parent_and_key(tenant)
    res = RechainResult(chain=(tenant or GLOBAL_KEY))

    before = verify_chain(conn, tenant)
    res.ok_before, res.was_broken_at = before.ok, before.first_broken_seq
    if before.ok:
        res.rows = before.checked
        res.ok_after = True
        return res

    # Hold the chain against appends for the whole repair. Without this a writer
    # could append to the old tail while the rows underneath it are being
    # re-linked, and the repair would finish by producing a fresh break.
    with conn.cursor() as cur:
        _lock_chain(cur, key)

        include_tenant = tenant is None
        cols = _COLS + (", tenant" if include_tenant else "")
        cur.execute(f"SELECT {cols} FROM {parent} ORDER BY seq")
        rows = cur.fetchall()

        prev: bytes | None = None
        updates: list[tuple] = []
        for rec in rows:
            (seq, ts, event_id, category, action, outcome, actor, actor_roles,
             target_uid, target_name, target_type, detail, source_iface,
             source_addr, request_id, old_prev, old_hash) = rec[:17]
            row_tenant = rec[17] if include_tenant else None

            canon = canonical_row(
                event_id=str(event_id), ts=ts, category=category, action=action,
                outcome=outcome, actor=actor, actor_roles=actor_roles,
                target_uid=target_uid, target_name=target_name,
                target_type=target_type,
                detail=(canonical_json(detail) if detail is not None else None),
                source_iface=source_iface, source_addr=source_addr,
                request_id=request_id, tenant=row_tenant)

            # The row must be self-consistent under the link it ALREADY carries.
            # If it is not, its content changed after it was written, and
            # re-linking would bury that — the one outcome this tool exists to
            # avoid. Bail out with the seq so a human can look at that row.
            old_prev_b = bytes(old_prev) if old_prev is not None else None
            if bytes(old_hash) != compute_row_hash(old_prev_b, canon):
                raise IntegrityMismatch(
                    f"{res.chain}: seq {seq} does not match its own stored hash. "
                    "Its CONTENT differs from what was hashed, which re-linking "
                    "would conceal. Refusing to repair this chain.")

            new_hash = compute_row_hash(prev, canon)
            if new_hash != bytes(old_hash) or old_prev_b != prev:
                updates.append((prev, new_hash, seq, ts))
            prev = new_hash

        res.rows = len(rows)
        res.relinked = len(updates)

        if not dry_run and updates:
            # executemany, not a statement per row. A real repair here is ~1M
            # rows (measured: 1,012,643 across five chains), and a round trip per
            # row would hold the chain lock — and therefore stall every writer on
            # that tenant — for the duration. psycopg pipelines these.
            #
            # Keyed on the full primary key (seq, ts) because the table is
            # partitioned by ts: without it the planner has no partition to prune
            # to and every update scans them all.
            cur.executemany(
                f"UPDATE {parent} SET prev_hash = %s, row_hash = %s "
                f"WHERE seq = %s AND ts = %s", updates)

    res.ok_after = True if dry_run else verify_chain(conn, tenant).ok
    return res


class IntegrityMismatch(Exception):
    """A row's content does not match the hash it carries — do not re-link."""


def record_repair(conn, tenant: str | None, res: RechainResult, actor: str) -> None:
    """Append an ``admin`` event describing the repair, into the repaired chain.

    Written through the normal writer so it is chained, partitioned and
    deduplicated like any other row — the repair is a fact about the system and
    belongs in the log, not only in an operator's memory.
    """
    import uuid
    from datetime import datetime, timezone
    from .envelope import parse_envelope
    from .writer import write_batch

    env = {
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(),
        "category": "admin",
        "action": "chain.repair",
        "outcome": "ok",
        "actor": actor,
        "scope": "global" if tenant is None else "tenant",
        "source_iface": "rest",
        "detail": {"rows": res.rows, "relinked": res.relinked,
                   "was_broken_at_seq": res.was_broken_at,
                   "cause": "concurrent writers appending without a chain lock",
                   "note": "links recomputed; row content unchanged and verified "
                           "against its stored hash before relinking"},
    }
    if tenant is not None:
        env["tenant"] = tenant
    write_batch(conn, [parse_envelope(env)], {})


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Re-link a broken audit chain (destroys tamper-evidence for "
                    "the period before the repair — read the module docstring)")
    p.add_argument("--tenant", action="append", default=[],
                   help="tenant to repair; repeatable. Use --global for the global chain.")
    p.add_argument("--global", dest="do_global", action="store_true",
                   help="also repair public.audit_log_global")
    p.add_argument("--all", action="store_true",
                   help="every tenant with an audit_log, plus the global chain")
    p.add_argument("--dry-run", action="store_true",
                   help="report what would change; write nothing")
    p.add_argument("--confirm", action="store_true",
                   help="required to write. Without it, --dry-run is forced.")
    p.add_argument("--actor", default="operator",
                   help="who is performing the repair; recorded in the log")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    from .config import Config
    from .db import connect
    config = Config()
    conn = connect(config)

    targets: list[str | None] = list(args.tenant)
    if args.all:
        with conn.cursor() as cur:
            cur.execute("SELECT schemaname FROM pg_tables WHERE tablename = 'audit_log' "
                        "AND schemaname LIKE 'tenant\\_%' ORDER BY 1")
            targets = [r[0][len("tenant_"):] for r in cur.fetchall()]
        conn.rollback()
    if args.do_global or args.all:
        targets.append(None)
    if not targets:
        p.error("nothing to do: pass --tenant, --global or --all")

    dry = args.dry_run or not args.confirm
    if dry and not args.dry_run:
        log.info("no --confirm given; running as a dry run")

    failures = 0
    for t in targets:
        try:
            res = rechain(conn, t, dry_run=dry)
            if dry:
                conn.rollback()
            else:
                if res.relinked and not res.ok_after:
                    raise RuntimeError("chain still does not verify after relinking")
                if res.relinked:
                    record_repair(conn, t, res, args.actor)
                conn.commit()
            log.info("%-24s rows=%-7d relinked=%-7d was_broken_at=%-8s ok_before=%-5s ok_after=%s%s",
                     res.chain, res.rows, res.relinked, res.was_broken_at,
                     res.ok_before, res.ok_after, "  (dry run)" if dry else "")
        except Exception as e:
            conn.rollback()
            failures += 1
            log.error("%-24s REFUSED: %s", t or GLOBAL_KEY, e)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
