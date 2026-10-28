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

"""``audit-archive``: read the archive back (SPEC_retention_and_archival.md §8).

An archive nobody can verify or read is a deletion with extra steps, so the
read side ships with the write side:

* ``verify`` walks a chain's archive from the catalog in ``seq`` order — every
  object's sha256, decryption, header, and every row's integrity and linkage,
  across part and segment boundaries — then checks the database chain continues
  from the archive's last link. Memory is one part.
* ``export`` streams archived rows as NDJSON for a ``ts`` range, reading only
  the parts whose range overlaps it.

Both take ``--accountability`` for the core's accountability record (§14).
``key-check`` and ``derive-key`` serve the key escrow (§10): the archive key is
derived from AT_REST_KEY, so the sealed copy of that key must reproduce it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from . import catalog
from .archive import ArchiveError
from .chain import ChainWalker
from .verify import verify_chain


@dataclass
class ArchiveVerifyResult:
    scope: str
    table: str
    ok: bool = True
    parts: int = 0
    rows: int = 0
    broken_seq: int | None = None
    reason: str | None = None
    starts_at_genesis: bool | None = None
    db: dict = field(default_factory=dict)


def _read_part(archive, cipher, object_key: str, sha256: bytes) -> tuple[dict, list[dict]]:
    blob = archive.get_object(object_key)
    if hashlib.sha256(blob).digest() != bytes(sha256):
        raise ArchiveError(f"{object_key}: ciphertext sha256 does not match the catalog")
    lines = cipher.decrypt(blob).decode("utf-8").splitlines()
    header = json.loads(lines[0])["header"]
    return header, [json.loads(ln) for ln in lines[1:]]


def verify_archive(conn, archive, cipher, scope) -> ArchiveVerifyResult:
    res = ArchiveVerifyResult(scope.scope_id, scope.parent)
    parts = catalog.parts_in_order(conn, scope.parent)
    walker = None
    manifests: dict[int, dict] = {}

    def fail(seq, reason):
        if res.ok:
            res.ok, res.broken_seq, res.reason = False, seq, reason

    for (segment_id, run_id, manifest_key, seg_first_prev, part_no, object_key,
         row_count, first_seq, last_seq, sha256) in parts:
        if walker is None:
            start = bytes(seg_first_prev) if seg_first_prev is not None else None
            res.starts_at_genesis = start is None
            walker = ChainWalker(start)
        if segment_id not in manifests:
            try:
                manifest = json.loads(cipher.decrypt(archive.get_object(manifest_key)))
                manifests[segment_id] = {p["key"]: p["sha256"] for p in manifest["parts"]}
            except Exception as e:  # an unreadable manifest is a finding, not a crash
                manifests[segment_id] = {}
                fail(first_seq, f"{manifest_key}: {e}")
        if manifests[segment_id].get(object_key) != bytes(sha256).hex():
            fail(first_seq, f"{object_key}: not listed with this sha256 in {manifest_key}")
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
            if not walker.step_dict(row, scope.include_tenant) and res.ok:
                fail(walker.broken_seq, walker.reason)
        res.parts += 1
        res.rows += len(rows)

    anchor = catalog.anchor(conn, scope.parent)
    if anchor is not None and walker is not None and walker.prev != anchor.last_row_hash:
        fail(anchor.last_seq, "the archive's last row is not the catalog anchor")
    db = verify_chain(conn, scope.tenant)
    res.db = {"ok": db.ok, "checked": db.checked, "first_broken_seq": db.first_broken_seq,
              "reason": db.reason, "anchored_at_seq": db.anchored_at_seq}
    conn.rollback()
    return res


def export_rows(conn, archive, cipher, scope, ts_from: datetime | None = None,
                ts_to: datetime | None = None):
    """Yield archived rows (dicts) of ``scope`` with ts in [ts_from, ts_to), in seq order."""
    for (*_, object_key, _rc, _fs, _ls, sha256) in catalog.parts_in_order(
            conn, scope.parent, ts_from=ts_from, ts_to=ts_to):
        _, rows = _read_part(archive, cipher, object_key, sha256)
        for row in rows:
            ts = datetime.fromisoformat(row["ts"])
            if (ts_from is None or ts >= ts_from) and (ts_to is None or ts < ts_to):
                yield row
    conn.rollback()


def _catalogued_scopes(conn, config):
    """Every chain the catalog holds, as (family, scope)."""
    from .accountability_retention import acc_scope_for
    from .retention import scope_for
    if not catalog.exists(conn):
        return []
    with conn.cursor() as cur:
        cur.execute(f"SELECT DISTINCT scope_table FROM {catalog.SEGMENTS} ORDER BY 1")
        tables = [r[0] for r in cur.fetchall()]
    conn.rollback()
    out = []
    for t in tables:
        tenant = t.split('"')[1][len("tenant_"):] if '"' in t else None
        if t.endswith("accountability_record") or t == "accountability_record_global":
            out.append(("accountability", acc_scope_for(tenant, config)))
        else:
            out.append(("audit", scope_for(tenant, config)))
    return out


def _read_secret(prompt: str) -> str:
    import getpass
    import sys
    return getpass.getpass(prompt) if sys.stdin.isatty() else sys.stdin.readline()


def _parse_day(value: str | None) -> datetime | None:
    if not value:
        return None
    d = datetime.fromisoformat(value)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def main() -> None:  # pragma: no cover
    import argparse
    import sys

    from . import db
    from .archive import make_archive, make_cipher
    from .config import Config, load_dotenv
    from .retention import scope_for

    load_dotenv()
    p = argparse.ArgumentParser(prog="audit-archive")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("key-check", help="read AT_REST_KEY (from the recovery kit) and prove it "
                                     "derives the configured archive key; prints fingerprints only")
    sub.add_parser("derive-key", help="read AT_REST_KEY on stdin and print the archive key "
                                      "(recovery: the server and its env file are gone)")
    for name in ("verify", "export"):
        sp = sub.add_parser(name)
        sp.add_argument("--accountability", action="store_true",
                        help="the core's accountability record rather than the audit log")
        g = sp.add_mutually_exclusive_group(required=(name == "export"))
        g.add_argument("--tenant")
        g.add_argument("--global", dest="global_", action="store_true")
        if name == "verify":
            g.add_argument("--all", action="store_true")
        else:
            sp.add_argument("--from", dest="ts_from", help="ISO date/time, inclusive")
            sp.add_argument("--to", dest="ts_to", help="ISO date/time, exclusive")
    args = p.parse_args()

    config = Config()
    if args.cmd in ("key-check", "derive-key"):
        from .keys import KeyFormatError, derive_archive_key, fingerprint, primary_key
        try:
            derived = derive_archive_key(_read_secret("AT_REST_KEY: "))
            if args.cmd == "derive-key":
                print(derived)
                return
            configured = primary_key(config.archive_key)
        except KeyFormatError as e:
            print(f"audit-archive: {e}", file=sys.stderr)
            sys.exit(2)
        match = fingerprint(derived) == fingerprint(configured)
        print(json.dumps({"derived": fingerprint(derived), "configured": fingerprint(configured),
                          "match": match}))
        sys.exit(0 if match else 1)
    archive = make_archive(config)
    if archive is None:
        print("audit-archive: AUDIT_ARCHIVE_BACKEND is 'none'", file=sys.stderr)
        sys.exit(2)
    cipher = make_cipher(config.archive_key)
    from .accountability_retention import acc_scope_for, export_acc_rows, verify_acc_archive
    family = "accountability" if args.accountability else "audit"
    conn = db.connect(config)
    try:
        if args.cmd == "export":
            tenant = None if args.global_ else args.tenant
            rows = (export_acc_rows(conn, archive, cipher, acc_scope_for(tenant, config),
                                    _parse_day(args.ts_from), _parse_day(args.ts_to))
                    if args.accountability else
                    export_rows(conn, archive, cipher, scope_for(tenant, config),
                                _parse_day(args.ts_from), _parse_day(args.ts_to)))
            for row in rows:
                sys.stdout.write(json.dumps(row) + "\n")
            return
        if args.tenant or args.global_:
            tenant = None if args.global_ else args.tenant
            scopes = [(family, acc_scope_for(tenant, config) if args.accountability
                       else scope_for(tenant, config))]
        else:
            scopes = _catalogued_scopes(conn, config)
        bad = False
        for fam, scope in scopes:
            r = (verify_acc_archive if fam == "accountability" else verify_archive)(
                conn, archive, cipher, scope)
            print(json.dumps({"family": fam, **asdict(r)}))
            bad = bad or not r.ok or not r.db.get("ok")
        sys.exit(1 if bad else 0)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
