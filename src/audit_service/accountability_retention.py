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

"""Retention for the core's accountability record (SPEC_retention_and_archival.md §14).

The core's ``accountability_record`` tables are the system of record for the
operations it owns; the Redis hint is only a nudge to read them. They are kept on
the audit log's window and the aged prefix is archived into the main store under
``<scope>/_accountability/`` with the same encrypted, write-once, catalogued
format, then DELETEd — the table is not partitioned, and does not need to be: the
core claims ``seq`` and a strictly increasing ``ts`` under one per-chain lock, so
"older than the cutoff" is always a ``seq`` prefix.

What differs from the audit log, and why:

* **Only rows the puller has already copied may go.** The audit service's
  puller reads ``ts > recorded_until`` and checks every batch for contiguity; a
  row deleted before it was pulled would be a gap — an integrity alarm — and a
  record that never reached the audit log. So the archived prefix is capped at
  the chain's ``accountability_cursor.last_seq``, and a halted or absent cursor
  holds the whole chain back.
* **A break is refused, not archived faithfully.** The core's chain is
  written under a lock and verified by the puller on every read, so a break here
  is tampering until shown otherwise. Deleting the evidence would be the worst
  response to it; the scope fails and nothing is removed.
* **The anchor is shared with the puller.** A puller rebuilt from an empty
  cursor resumes from the catalog's anchor instead of from genesis, which no
  longer exists (puller.py).
"""
from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

from . import catalog
from .accountability import (GLOBAL_CHAIN_KEY, CoreRecord, IntegrityBreak, canonical_json,
                             verify_batch)
from .archive import ArchiveError, manifest_key, part_key, segment_prefix
from .naming import schema_for_tenant

log = logging.getLogger("audit_service.accountability_retention")

FORMAT = "fileengine.accountability-archive/1"
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_COLS = ("seq, ts, actor, actor_roles, source_iface, source_addr, category, action, "
         "target_uid, target_type, principal, detail, prev_hash, hash")


@dataclass(frozen=True)
class AccScope:
    scope_id: str       # the S3 folder owner: tenant id, or the global scope id
    tenant: str | None  # None for the global chain
    table: str          # as the catalog names it (scope_table)
    cursor_key: str     # the puller's accountability_cursor key

    @property
    def include_tenant(self) -> bool:
        return self.tenant is None


def acc_scope_for(tenant: str | None, config) -> AccScope:
    if tenant is None:
        return AccScope(config.archive_global_scope, None, "accountability_record_global",
                        GLOBAL_CHAIN_KEY)
    schema = schema_for_tenant(tenant)
    return AccScope(schema[len("tenant_"):], tenant, f'"{schema}".accountability_record',
                    tenant)


def table_for_cursor_key(key: str) -> str:
    """The catalog table name of a puller chain key (the inverse the puller needs)."""
    if key == GLOBAL_CHAIN_KEY:
        return "accountability_record_global"
    return f'"{schema_for_tenant(key)}".accountability_record'


def discover_acc_scopes(conn, config) -> list[AccScope]:
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('public.accountability_record_global')")
        has_global = cur.fetchone()[0] is not None
        cur.execute(
            "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relname = 'accountability_record' AND c.relkind = 'r' "
            "AND n.nspname LIKE 'tenant\\_%' ORDER BY 1")
        schemas = [r[0] for r in cur.fetchall()]
    conn.commit()
    scopes = [acc_scope_for(None, config)] if has_global else []
    return scopes + [acc_scope_for(s[len("tenant_"):], config) for s in schemas]


# --------------------------------------------------------------------------- rows

def _micros(ts: datetime) -> int:
    return (ts - _EPOCH) // timedelta(microseconds=1)


def row_to_dict(rec, include_tenant: bool) -> dict:
    (seq, ts, actor, roles, iface, addr, category, action, target_uid, target_type,
     principal, detail, prev_hash, row_hash, *rest) = rec
    out = {"seq": seq, "ts": ts.isoformat(), "ts_micros": _micros(ts), "actor": actor,
           "actor_roles": list(roles or []), "source_iface": iface, "source_addr": addr,
           "category": category, "action": action, "target_uid": target_uid,
           "target_type": target_type, "principal": principal, "detail": detail or {},
           "prev_hash": bytes(prev_hash).hex() if prev_hash is not None else None,
           "row_hash": bytes(row_hash).hex()}
    if include_tenant:
        out["tenant"] = rest[0]
    return out


def record_from_dict(d: dict) -> CoreRecord:
    """The archived row as the record the core hashed. An empty detail is the
    core's ``null``, not ``{}`` (accountability.cpp ``canonical_record``)."""
    return CoreRecord(
        seq=d["seq"], ts_micros=d["ts_micros"], ts=datetime.fromisoformat(d["ts"]),
        actor=d["actor"], actor_roles=d["actor_roles"], source_iface=d["source_iface"] or "",
        source_addr=d["source_addr"] or "", category=d["category"], action=d["action"],
        target_uid=d["target_uid"] or "", target_type=d["target_type"] or "",
        principal=d["principal"] or "",
        detail=canonical_json(d["detail"]) if d["detail"] else "",
        prev_hash=bytes.fromhex(d["prev_hash"]) if d["prev_hash"] else None,
        hash=bytes.fromhex(d["row_hash"]), global_tenant=d.get("tenant") or "")


class AccWalker:
    """Every §4.3.2 check, one row at a time, from a starting link. ``after_seq``
    0 means genesis: the first row must be seq 1 with no prev_hash."""

    def __init__(self, key: str, start_hash: bytes | None, after_seq: int,
                 after_ts_micros: int | None = None):
        self.key = key
        self.prev, self.prev_seq, self.prev_ts = start_hash, after_seq, after_ts_micros
        self.broken_seq: int | None = None
        self.reason: str | None = None

    @property
    def ok(self) -> bool:
        return self.reason is None

    def step(self, row: dict) -> bool:
        rec = record_from_dict(row)
        try:
            verify_batch(self.key, [rec], last_seq=self.prev_seq, last_hash=self.prev,
                         last_ts_micros=self.prev_ts)
        except IntegrityBreak as e:
            if self.ok:
                self.broken_seq, self.reason = e.seq, e.reason
            # Carry on from the row as stored, so one break is reported once.
        self.prev, self.prev_seq, self.prev_ts = rec.hash, rec.seq, rec.ts_micros
        return self.ok


# --------------------------------------------------------------------------- the run

def run_scope(conn, scope: AccScope, config, *, today: date, run_id: str,
              archive=None, cipher=None, dry_run: bool = False) -> dict:
    """Archive and delete one chain's aged, already-pulled prefix in ONE
    transaction. Commits on success; rolls back and re-raises on any failure."""
    from .retention import _put_verified, cutoff_for

    cutoff = cutoff_for(today, config.retention_months)
    cutoff_dt = datetime(cutoff.year, cutoff.month, cutoff.day, tzinfo=timezone.utc)
    result = {"family": "accountability", "scope": scope.scope_id, "table": scope.table,
              "cutoff": cutoff.isoformat(), "run_id": run_id, "rows": 0, "parts": 0,
              "first_seq": None, "last_seq": None, "held": None, "manifest_key": None,
              "dry_run": dry_run}
    try:
        with conn.cursor() as cur:
            cur.execute(f"SET LOCAL statement_timeout = {int(config.retention_statement_timeout_ms)}")
            # The core creates the table lazily, on a tenant's first record.
            cur.execute("SELECT to_regclass(%s)", (scope.table,))
            if cur.fetchone()[0] is None:
                conn.rollback()
                return result
            # Two runs on one chain would each archive the same prefix.
            cur.execute("SELECT pg_advisory_xact_lock(hashtext(%s))",
                        (f"accountability_retention:{scope.table}",))
            cur.execute(f"SELECT max(seq) FROM {scope.table} WHERE ts < %s", (cutoff_dt,))
            aged_max = cur.fetchone()[0]
            if aged_max is None:
                conn.rollback()
                return result
            cur.execute("SELECT to_regclass('public.accountability_cursor')")
            pulled, why = 0, "the audit puller has never read this chain"
            if cur.fetchone()[0] is not None:
                cur.execute("SELECT last_seq, halted_reason FROM accountability_cursor "
                            "WHERE tenant = %s", (scope.cursor_key,))
                row = cur.fetchone()
                if row is not None and row[1] is not None:
                    why = f"the audit puller is HALTED on this chain: {row[1]}"
                elif row is not None:
                    pulled, why = int(row[0]), "not yet copied into the audit log"
            limit = min(aged_max, pulled)
            if limit < aged_max:
                result["held"] = {"from_seq": limit + 1, "to_seq": aged_max, "reason": why}
                log.warning("%s: holding accountability seq %s..%s back — %s",
                            scope.scope_id, limit + 1, aged_max, why)
            anchor = catalog.anchor(conn, scope.table)
            after = anchor.last_seq if anchor else 0
            cur.execute(f"SELECT count(*) FROM {scope.table} WHERE seq <= %s", (limit,))
            count = cur.fetchone()[0]
        if count == 0 or limit <= after:
            conn.rollback()
            return result
        result.update(rows=count, first_seq=after + 1, last_seq=limit)
        if dry_run:
            conn.rollback()
            return result

        seg = segment_prefix(scope.scope_id, config.archive_accountability_folder,
                             today.year, today.month, run_id)
        walker = AccWalker(scope.cursor_key, anchor.last_row_hash if anchor else None, after,
                           _micros(anchor.max_ts) if anchor and anchor.max_ts else None)
        parts: list[dict] = []
        first_prev = None
        with conn.cursor(name=f"acc_retention_{secrets.token_hex(4)}") as stream:
            cols = _COLS + (", tenant" if scope.include_tenant else "")
            stream.execute(f"SELECT {cols} FROM {scope.table} WHERE seq <= %s ORDER BY seq",
                           (limit,))
            while True:
                recs = stream.fetchmany(config.archive_part_rows)
                if not recs:
                    break
                rows = [row_to_dict(r, scope.include_tenant) for r in recs]
                for row in rows:
                    walker.step(row)
                if not walker.ok:
                    raise ArchiveError(
                        f"{scope.scope_id}: accountability chain break at seq "
                        f"{walker.broken_seq} ({walker.reason}) — refusing to archive or "
                        "delete; investigate before anything is removed")
                part_no = len(parts) + 1
                ts = [datetime.fromisoformat(r["ts"]) for r in rows]
                header = {"format": FORMAT, "scope": scope.scope_id, "table": scope.table,
                          "run_id": run_id, "part": part_no, "row_count": len(rows),
                          "first_seq": rows[0]["seq"], "last_seq": rows[-1]["seq"],
                          "first_prev_hash": rows[0]["prev_hash"],
                          "last_row_hash": rows[-1]["row_hash"],
                          "min_ts": ts[0].isoformat(), "max_ts": ts[-1].isoformat()}
                body = (json.dumps({"header": header}) + "\n"
                        + "".join(json.dumps(r) + "\n" for r in rows)).encode("utf-8")
                key = part_key(seg, part_no)
                digest = _put_verified(archive, cipher, key, body, len(rows) + 1,
                                       rows[-1]["row_hash"])
                parts.append({"part_no": part_no, "object_key": archive.object_key(key),
                              "row_count": len(rows), "first_seq": rows[0]["seq"],
                              "last_seq": rows[-1]["seq"], "min_ts": ts[0], "max_ts": ts[-1],
                              "sha256": digest})
                if part_no == 1:
                    first_prev = rows[0]["prev_hash"]
        archived = sum(p["row_count"] for p in parts)
        if archived != count or parts[-1]["last_seq"] != limit:
            raise ArchiveError(f"{scope.scope_id}: streamed {archived} rows, expected {count}")

        last_hash = walker.prev.hex()
        mkey = manifest_key(seg)
        manifest = {"format": FORMAT, "scope": scope.scope_id, "table": scope.table,
                    "run_id": run_id, "cutoff": cutoff.isoformat(),
                    "run_date": today.isoformat(),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "row_count": archived, "first_seq": after + 1, "last_seq": limit,
                    "first_prev_hash": first_prev, "last_row_hash": last_hash,
                    "min_ts": parts[0]["min_ts"].isoformat(),
                    "max_ts": parts[-1]["max_ts"].isoformat(), "chain_ok": True,
                    "anchor_before": ({"last_seq": anchor.last_seq,
                                       "last_row_hash": anchor.last_row_hash.hex()}
                                      if anchor else None),
                    "parts": [{"part": p["part_no"], "key": p["object_key"],
                               "rows": p["row_count"], "first_seq": p["first_seq"],
                               "last_seq": p["last_seq"], "min_ts": p["min_ts"].isoformat(),
                               "max_ts": p["max_ts"].isoformat(), "sha256": p["sha256"]}
                              for p in parts]}
        _put_verified(archive, cipher, mkey, json.dumps(manifest).encode("utf-8"))

        with conn.cursor() as cur:
            catalog.record_segment(cur, {
                "scope": scope.scope_id, "scope_table": scope.table, "run_id": run_id,
                "manifest_key": archive.object_key(mkey), "cutoff": cutoff,
                "row_count": archived, "first_seq": after + 1, "last_seq": limit,
                "first_prev_hash": bytes.fromhex(first_prev) if first_prev else None,
                "last_row_hash": walker.prev, "min_ts": parts[0]["min_ts"],
                "max_ts": parts[-1]["max_ts"], "partitions": [], "chain_ok": True},
                [{**p, "sha256": bytes.fromhex(p["sha256"])} for p in parts])
            cur.execute(f"SET LOCAL lock_timeout = {int(config.retention_lock_timeout_ms)}")
            cur.execute(f"DELETE FROM {scope.table} WHERE seq <= %s", (limit,))
            if cur.rowcount != count:
                raise ArchiveError(f"{scope.scope_id}: deleted {cur.rowcount} rows, "
                                   f"archived {count}")
        conn.commit()
        result.update(parts=len(parts), manifest_key=archive.object_key(mkey))
        log.info("%s: archived accountability seq %s..%s (%s rows, %s parts)",
                 scope.scope_id, after + 1, limit, archived, len(parts))
        return result
    except BaseException:
        conn.rollback()
        raise


# --------------------------------------------------------------------------- reading back

def verify_acc_archive(conn, archive, cipher, scope: AccScope):
    """Walk the chain's archive from the catalog, then the rows still in the
    table from the anchor — every link, every recomputed hash."""
    from .archive_cli import ArchiveVerifyResult, _read_part

    res = ArchiveVerifyResult(scope.scope_id, scope.table)
    walker = None
    manifests: dict[int, dict] = {}

    def fail(seq, reason):
        if res.ok:
            res.ok, res.broken_seq, res.reason = False, seq, reason

    for (segment_id, _run, mkey, seg_first_prev, part_no, object_key, row_count,
         first_seq, last_seq, sha256) in catalog.parts_in_order(conn, scope.table):
        if walker is None:
            start = bytes(seg_first_prev) if seg_first_prev is not None else None
            res.starts_at_genesis = start is None and first_seq == 1
            walker = AccWalker(scope.cursor_key, start, first_seq - 1)
        if segment_id not in manifests:
            try:
                manifest = json.loads(cipher.decrypt(archive.get_object(mkey)))
                manifests[segment_id] = {p["key"]: p["sha256"] for p in manifest["parts"]}
            except Exception as e:
                manifests[segment_id] = {}
                fail(first_seq, f"{mkey}: {e}")
        if manifests[segment_id].get(object_key) != bytes(sha256).hex():
            fail(first_seq, f"{object_key}: not listed with this sha256 in {mkey}")
        try:
            header, rows = _read_part(archive, cipher, object_key, sha256)
        except Exception as e:
            fail(first_seq, f"{object_key}: {e}")
            continue
        if (header.get("part") != part_no or header.get("row_count") != row_count
                or len(rows) != row_count or header.get("first_seq") != first_seq
                or header.get("last_seq") != last_seq):
            fail(first_seq, f"{object_key}: header or row count disagrees with the catalog")
        for row in rows:
            if not walker.step(row):
                fail(walker.broken_seq, walker.reason)
        res.parts += 1
        res.rows += len(rows)

    anchor = catalog.anchor(conn, scope.table)
    if anchor is not None and walker is not None and walker.prev != anchor.last_row_hash:
        fail(anchor.last_seq, "the archive's last row is not the catalog anchor")
    # The table continues from the anchor (or from genesis, if nothing was archived).
    db = AccWalker(scope.cursor_key, anchor.last_row_hash if anchor else None,
                   anchor.last_seq if anchor else 0)
    checked = 0
    with conn.cursor(name=f"acc_verify_{secrets.token_hex(4)}") as stream:
        cols = _COLS + (", tenant" if scope.include_tenant else "")
        stream.execute(f"SELECT {cols} FROM {scope.table} ORDER BY seq")
        while True:
            recs = stream.fetchmany(5000)
            if not recs:
                break
            for r in recs:
                db.step(row_to_dict(r, scope.include_tenant))
                checked += 1
    res.db = {"ok": db.ok, "checked": checked, "first_broken_seq": db.broken_seq,
              "reason": db.reason, "anchored_at_seq": anchor.last_seq if anchor else None}
    conn.rollback()
    return res


def export_acc_rows(conn, archive, cipher, scope: AccScope, ts_from=None, ts_to=None):
    from .archive_cli import _read_part

    for (*_, object_key, _rc, _fs, _ls, sha256) in catalog.parts_in_order(
            conn, scope.table, ts_from=ts_from, ts_to=ts_to):
        _, rows = _read_part(archive, cipher, object_key, sha256)
        for row in rows:
            ts = datetime.fromisoformat(row["ts"])
            if (ts_from is None or ts >= ts_from) and (ts_to is None or ts < ts_to):
                yield row
    conn.rollback()
