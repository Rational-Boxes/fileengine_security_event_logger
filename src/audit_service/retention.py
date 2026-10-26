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

"""Retention: two calendar months in Postgres, the rest archived monthly (§7).

The full contract is design_documents/SPEC_retention_and_archival.md; the short
version, per scope (a tenant chain, or the global one), in ONE transaction:

1. take the writer's advisory lock on every aged partition, so no late row can
   land between being read and being dropped;
2. keep only the aged partitions that form a PREFIX of the chain in ``seq``
   order — a partition holding a late-arriving row waits for a later run, or
   dropping it would cut a hole in the middle of the chain;
3. stream those rows in ``seq`` order, a bounded part at a time, into
   encrypted objects in the main store, reading each one back before going on;
4. write the manifest, record the segment in the catalog (the new anchor), drop
   the partitions, commit.

Nothing is dropped that has not been written, read back and verified, and the
catalog rows and the drops become visible together or not at all.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timezone

from . import catalog
from .archive import (ArchiveError, make_archive, make_cipher, manifest_key, part_key,
                      segment_prefix, validate_reserved)
from .chain import ChainWalker, record_to_dict, select_cols
from .naming import schema_for_tenant
from .writer import _partition_of

log = logging.getLogger("audit_service.retention")

FORMAT = "fileengine.audit-archive/1"


# --------------------------------------------------------------------------- scopes

@dataclass(frozen=True)
class Scope:
    scope_id: str          # the tenant id, or the global scope id — the S3 folder owner
    tenant: str | None     # None for the global chain
    schema: str
    relname: str           # the parent table's bare name
    parent: str            # the parent as the WRITER spells it (its lock keys use this)

    @property
    def include_tenant(self) -> bool:
        return self.tenant is None

    @property
    def partition_prefix(self) -> str:
        return f"{self.relname}_p"

    def qualified(self, partition: str) -> str:
        return partition if self.tenant is None else f'"{self.schema}".{partition}'


def scope_for(tenant: str | None, config) -> Scope:
    if tenant is None:
        return Scope(config.archive_global_scope, None, "public", "audit_log_global",
                     "audit_log_global")
    schema = schema_for_tenant(tenant)
    return Scope(schema[len("tenant_"):], tenant, schema, "audit_log", f'"{schema}".audit_log')


def discover_scopes(conn, config) -> list[Scope]:
    """The global chain (if its table exists) and every tenant schema that has a
    partitioned audit_log — discovered, never assumed, so a tenant provisioned
    after this deploy is covered without a config change."""
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.audit_log_global')")
        has_global = cur.fetchone()[0] is not None
        cur.execute(
            "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relname = 'audit_log' AND c.relkind = 'p' "
            "AND n.nspname LIKE 'tenant\\_%' ORDER BY 1")
        schemas = [r[0] for r in cur.fetchall()]
    conn.commit()
    scopes = [scope_for(None, config)] if has_global else []
    return scopes + [scope_for(s[len("tenant_"):], config) for s in schemas]


# --------------------------------------------------------------------------- the window

def cutoff_for(today: date, months: int) -> date:
    """First day of (month(today) − months): everything before it is aged."""
    if months < 1:
        raise ValueError("FILEENGINE_AUDIT_RETENTION_MONTHS must be at least 1")
    index = today.year * 12 + (today.month - 1) - months
    return date(index // 12, index % 12 + 1, 1)


def resolve_today(config, override: str | None = None) -> date:
    """The run's date. An override (``--today`` or AUDIT_RETENTION_TODAY) is the
    lifecycle simulation's clock and is refused unless AUDIT_ALLOW_DATE_OVERRIDE
    is set: a future date archives live data."""
    value = override or config.retention_today
    if not value:
        return datetime.now(timezone.utc).date()
    if not config.allow_date_override:
        raise ArchiveError("a retention date override was given but "
                           "AUDIT_ALLOW_DATE_OVERRIDE is not set — refusing")
    return date.fromisoformat(value)


# --------------------------------------------------------------------------- partitions

@dataclass
class PartStat:
    name: str
    day: date
    rows: int = 0
    min_seq: int | None = None
    max_seq: int | None = None


def list_partitions(conn, scope: Scope) -> list[tuple[str, date]]:
    pattern = f"^{scope.partition_prefix}[0-9]{{8}}$"  # underscores are literal in POSIX regex
    with conn.cursor() as cur:
        cur.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = %s AND c.relkind = 'r' AND c.relname ~ %s", (scope.schema, pattern))
        out = []
        for (name,) in cur.fetchall():
            try:
                day = datetime.strptime(name[len(scope.partition_prefix):], "%Y%m%d").date()
            except ValueError:
                continue
            out.append((name, day))
    return sorted(out, key=lambda x: x[1])


def select_droppable(aged: list[PartStat], kept_min: int | None
                     ) -> tuple[list[PartStat], list[PartStat]]:
    """The chain-prefix rule (§4): keep from ``aged`` only partitions whose rows
    all precede every row that stays. Returns (droppable, held).

    ``kept_min`` is the smallest seq in the partitions that are not aged (None
    when there are none). Holding a partition back lowers the bound for the
    rest, so this iterates until nothing more is held."""
    candidates = {p.name: p for p in aged}
    held: list[PartStat] = []
    bound = kept_min
    while bound is not None:
        newly = [p for p in candidates.values() if p.rows and p.max_seq > bound]
        if not newly:
            break
        for p in newly:
            del candidates[p.name]
            held.append(p)
            bound = min(bound, p.min_seq)
    return (sorted(candidates.values(), key=lambda p: p.day),
            sorted(held, key=lambda p: p.day))


def _stats(cur, scope: Scope, name: str, day: date) -> PartStat:
    cur.execute(f"SELECT count(*), min(seq), max(seq) FROM {scope.qualified(name)}")
    rows, lo, hi = cur.fetchone()
    return PartStat(name, day, rows, lo, hi)


# --------------------------------------------------------------------------- archiving

def new_run_id() -> str:
    """Wall-clock + randomness, deliberately NOT the overridden date: two runs
    must never share a key, and a simulation runs many in one second."""
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"


def _put_verified(archive, cipher, key: str, body: bytes, expect_lines: int | None = None,
                  expect_last_hash: str | None = None) -> str:
    """Encrypt, write, then read back and prove it. Returns the ciphertext's
    sha256 hex. Any mismatch raises, which aborts the scope's transaction."""
    token = cipher.encrypt(body)
    digest = hashlib.sha256(token).hexdigest()
    archive.put(key, token)
    back = archive.get(key)
    if hashlib.sha256(back).hexdigest() != digest:
        raise ArchiveError(f"archive read-back mismatch for {key}")
    plain = cipher.decrypt(back)
    if plain != body:
        raise ArchiveError(f"archive decrypt mismatch for {key}")
    if expect_lines is not None:
        lines = plain.decode("utf-8").splitlines()
        if len(lines) != expect_lines or json.loads(lines[-1]).get("row_hash") != expect_last_hash:
            raise ArchiveError(f"archive verification failed for {key}")
    return digest


def run_scope(conn, scope: Scope, config, *, today: date, run_id: str | None = None,
              archive=None, cipher=None, dry_run: bool = False) -> dict:
    """Archive and drop one scope's aged prefix. Commits on success, rolls back
    (and re-raises) on any failure, so Postgres is either fully updated or
    untouched."""
    cutoff = cutoff_for(today, config.retention_months)
    run_id = run_id or new_run_id()
    part_rows = config.archive_part_rows
    if not 1 <= part_rows <= 100000:
        raise ArchiveError("AUDIT_ARCHIVE_PART_ROWS must be between 1 and 100000")
    result = {"scope": scope.scope_id, "table": scope.parent, "cutoff": cutoff.isoformat(),
              "run_id": run_id, "dropped": [], "held": [], "rows": 0, "parts": 0,
              "manifest_key": None, "chain_ok": None, "chain_reason": None,
              "dry_run": dry_run}
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET LOCAL statement_timeout = {int(config.retention_statement_timeout_ms)}")
            aged_names = [(n, d) for (n, d) in list_partitions(conn, scope) if d < cutoff]
            if not aged_names:
                conn.rollback()
                return result
            # The writer's own lock keys, in the writer's (sorted) order.
            for _, day in sorted(aged_names, key=lambda x: _partition_of(scope.parent, x[1])):
                cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                            (_partition_of(scope.parent, day),))
            # Re-list under the locks: a partition may have appeared meanwhile.
            aged_names = [(n, d) for (n, d) in list_partitions(conn, scope) if d < cutoff]
            aged = [_stats(cur, scope, n, d) for n, d in aged_names]
            cur.execute(f"SELECT min(seq) FROM {scope.parent} WHERE ts >= %s",
                        (datetime(cutoff.year, cutoff.month, cutoff.day, tzinfo=timezone.utc),))
            kept_min = cur.fetchone()[0]

        drop, held = select_droppable(aged, kept_min)
        result["dropped"] = [p.name for p in drop]
        result["held"] = [{"partition": p.name, "min_seq": p.min_seq, "max_seq": p.max_seq}
                          for p in held]
        for p in held:
            log.warning("%s: holding %s back (seq %s..%s) — it holds rows that arrived "
                        "after later days; it is archived once the chain has moved past it",
                        scope.scope_id, p.name, p.min_seq, p.max_seq)
        with_rows = [p for p in drop if p.rows]
        result["rows"] = sum(p.rows for p in with_rows)
        if dry_run or not drop:
            conn.rollback()
            return result

        if with_rows:
            _archive_segment(conn, scope, config, cutoff, today, run_id, with_rows,
                             [p.name for p in drop], archive, cipher, result)

        with conn.cursor() as cur:
            cur.execute(f"SET LOCAL lock_timeout = {int(config.retention_lock_timeout_ms)}")
            for p in drop:
                cur.execute(f"DROP TABLE {scope.qualified(p.name)}")
        conn.commit()
        log.info("%s: archived %s row(s) in %s part(s), dropped %s partition(s)",
                 scope.scope_id, result["rows"], result["parts"], len(drop))
        return result
    except BaseException:
        conn.rollback()
        raise


def _archive_segment(conn, scope, config, cutoff, today, run_id, partitions, dropped_names,
                     archive, cipher, result) -> None:
    anchor = catalog.anchor(conn, scope.parent)
    walker = ChainWalker(anchor.last_row_hash if anchor else None,
                         anchor.last_seq if anchor else None)
    seg = segment_prefix(scope.scope_id, config.archive_folder, today.year, today.month, run_id)
    union = " UNION ALL ".join(
        f"SELECT {select_cols(scope.include_tenant)} FROM {scope.qualified(p.name)}"
        for p in partitions)
    parts: list[dict] = []
    first_prev = last_hash = None
    min_ts = max_ts = None

    # A server-side cursor: the memory bound is one part, never a month.
    with conn.cursor(name=f"audit_retention_{secrets.token_hex(4)}") as stream:
        stream.execute(f"SELECT * FROM ({union}) AS aged ORDER BY seq")
        while True:
            recs = stream.fetchmany(config.archive_part_rows)
            if not recs:
                break
            rows = [record_to_dict(r, scope.include_tenant) for r in recs]
            for row in rows:
                walker.step_dict(row, scope.include_tenant)
            ts = [datetime.fromisoformat(r["ts"]) for r in rows]
            part_no = len(parts) + 1
            header = {"format": FORMAT, "scope": scope.scope_id, "table": scope.parent,
                      "run_id": run_id, "part": part_no, "row_count": len(rows),
                      "first_seq": rows[0]["seq"], "last_seq": rows[-1]["seq"],
                      "first_prev_hash": rows[0]["prev_hash"],
                      "last_row_hash": rows[-1]["row_hash"],
                      "min_ts": min(ts).isoformat(), "max_ts": max(ts).isoformat()}
            body = (json.dumps({"header": header}) + "\n"
                    + "".join(json.dumps(r) + "\n" for r in rows)).encode("utf-8")
            key = part_key(seg, part_no)
            digest = _put_verified(archive, cipher, key, body, len(rows) + 1,
                                   rows[-1]["row_hash"])
            parts.append({"part_no": part_no, "key": key, "object_key": archive.object_key(key),
                          "row_count": len(rows), "first_seq": rows[0]["seq"],
                          "last_seq": rows[-1]["seq"], "min_ts": min(ts), "max_ts": max(ts),
                          "sha256": digest})
            if part_no == 1:
                first_prev = rows[0]["prev_hash"]
            last_hash = rows[-1]["row_hash"]
            min_ts = min(ts) if min_ts is None else min(min_ts, min(ts))
            max_ts = max(ts) if max_ts is None else max(max_ts, max(ts))

    if not walker.ok:
        # Archived as-is, never refused: refusing would stop retention forever on
        # a chain audit-rechain exists to repair, and an archive must be a
        # faithful copy rather than a corrected one.
        log.warning("%s: chain break at seq %s (%s) inside the archived range; "
                    "archiving faithfully", scope.scope_id, walker.broken_seq, walker.reason)
    mkey = manifest_key(seg)
    manifest = {"format": FORMAT, "scope": scope.scope_id, "table": scope.parent,
                "run_id": run_id, "cutoff": cutoff.isoformat(), "run_date": today.isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "row_count": sum(p["row_count"] for p in parts),
                "first_seq": parts[0]["first_seq"], "last_seq": parts[-1]["last_seq"],
                "first_prev_hash": first_prev, "last_row_hash": last_hash,
                "min_ts": min_ts.isoformat(), "max_ts": max_ts.isoformat(),
                "partitions": dropped_names,
                "chain_ok": walker.ok, "chain_broken_seq": walker.broken_seq,
                "chain_reason": walker.reason,
                "anchor_before": ({"last_seq": anchor.last_seq,
                                   "last_row_hash": anchor.last_row_hash.hex()
                                   if anchor.last_row_hash else None} if anchor else None),
                "parts": [{"part": p["part_no"], "key": p["object_key"], "rows": p["row_count"],
                           "first_seq": p["first_seq"], "last_seq": p["last_seq"],
                           "min_ts": p["min_ts"].isoformat(), "max_ts": p["max_ts"].isoformat(),
                           "sha256": p["sha256"]} for p in parts]}
    _put_verified(archive, cipher, mkey, json.dumps(manifest).encode("utf-8"))

    with conn.cursor() as cur:
        catalog.record_segment(cur, {
            "scope": scope.scope_id, "scope_table": scope.parent, "run_id": run_id,
            "manifest_key": archive.object_key(mkey), "cutoff": cutoff,
            "row_count": manifest["row_count"], "first_seq": manifest["first_seq"],
            "last_seq": manifest["last_seq"],
            "first_prev_hash": bytes.fromhex(first_prev) if first_prev else None,
            "last_row_hash": bytes.fromhex(last_hash) if last_hash else None,
            "min_ts": min_ts, "max_ts": max_ts, "partitions": dropped_names,
            "chain_ok": walker.ok},
            [{**p, "sha256": bytes.fromhex(p["sha256"])} for p in parts])
    result.update(parts=len(parts), manifest_key=archive.object_key(mkey),
                  chain_ok=walker.ok, chain_reason=walker.reason)


def _validate(config) -> None:
    validate_reserved(config.archive_folder, "AUDIT_ARCHIVE_FOLDER")
    validate_reserved(config.archive_global_scope, "AUDIT_ARCHIVE_GLOBAL_SCOPE")
    cutoff_for(date.today(), config.retention_months)


def run(conn, tenant, config, *, today=None, dry_run: bool = False,
        run_id: str | None = None) -> list[dict]:
    """Archive + drop one scope (a tenant, or None for global). Returns the
    segments written: [] when there was nothing aged, else one result dict."""
    _validate(config)
    archive = make_archive(config)
    if archive is None:
        log.info("archive backend is 'none'; retention disabled")
        return []
    cipher = make_cipher(config.archive_key)
    catalog.ensure_tables(conn)
    res = run_scope(conn, scope_for(tenant, config), config,
                    today=today or datetime.now(timezone.utc).date(), run_id=run_id,
                    archive=archive, cipher=cipher, dry_run=dry_run)
    return [res] if res["dropped"] or res["held"] else []


def run_all(conn, config, *, today=None, dry_run: bool = False,
            scopes: list[Scope] | None = None) -> tuple[list[dict], list[tuple[str, str]]]:
    """Every scope, each independently. Returns (results, failures)."""
    _validate(config)
    archive = make_archive(config)
    if archive is None:
        log.info("archive backend is 'none'; retention disabled")
        return [], []
    cipher = make_cipher(config.archive_key)
    catalog.ensure_tables(conn)
    today = today or datetime.now(timezone.utc).date()
    run_id = new_run_id()
    results, failures = [], []
    for scope in scopes if scopes is not None else discover_scopes(conn, config):
        try:
            results.append(run_scope(conn, scope, config, today=today, run_id=run_id,
                                     archive=archive, cipher=cipher, dry_run=dry_run))
        except Exception as e:  # one scope's failure must not stop the others
            log.exception("%s: retention failed; nothing was dropped", scope.scope_id)
            failures.append((scope.scope_id, str(e)))
    return results, failures


def main() -> None:  # pragma: no cover
    import argparse
    import sys

    from . import db
    from .config import Config, load_dotenv

    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    p = argparse.ArgumentParser(prog="audit-retention",
                                description="Archive audit rows older than the retention "
                                            "window to the main store, then drop them.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--all", action="store_true", help="every scope (the default)")
    g.add_argument("--global", dest="global_", action="store_true", help="the global chain only")
    g.add_argument("--tenant", help="one tenant only")
    g.add_argument("legacy_tenant", nargs="?", help=argparse.SUPPRESS)
    p.add_argument("--today", help="simulation clock (YYYY-MM-DD); needs AUDIT_ALLOW_DATE_OVERRIDE")
    p.add_argument("--dry-run", action="store_true", help="report the plan; change nothing")
    args = p.parse_args()

    config = Config()
    if config.legacy_retention_days:
        log.warning("FILEENGINE_AUDIT_RETENTION_DAYS is retired and ignored; the window is "
                    "FILEENGINE_AUDIT_RETENTION_MONTHS=%s", config.retention_months)
    try:
        today = resolve_today(config, args.today)
    except (ArchiveError, ValueError) as e:
        print(f"audit-retention: {e}", file=sys.stderr)
        sys.exit(2)
    conn = db.connect(config)
    try:
        if args.global_ or args.legacy_tenant == "--global":
            scopes = [scope_for(None, config)]
        elif args.tenant or args.legacy_tenant:
            scopes = [scope_for(args.tenant or args.legacy_tenant, config)]
        else:
            scopes = None
        results, failures = run_all(conn, config, today=today, dry_run=args.dry_run,
                                    scopes=scopes)
    finally:
        conn.close()
    for r in results:
        print(json.dumps(r))
    for scope_id, err in failures:
        print(f"audit-retention: {scope_id} FAILED: {err}", file=sys.stderr)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
