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

"""Retention: 30-day rolling DB window + daily encrypted archive (§7).

A daily job: for every ``audit_log`` daily partition older than the window, export
its rows (complete, including the hash columns) to a Fernet-encrypted NDJSON file
in the archive, verify the write, then DROP the partition. Each archive carries a
manifest with the day's first ``prev_hash`` and last ``row_hash`` so the chain
stays verifiable across the DB→archive boundary. Nothing is dropped before the
encrypted archive is written and read back.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from .archive import make_archive, make_cipher
from .naming import schema_for_tenant

log = logging.getLogger("audit_service.retention")

_COLS = ("seq, event_id, ts, category, action, outcome, actor, actor_roles, "
         "target_uid, target_name, target_type, detail, source_iface, "
         "source_addr, request_id, prev_hash, row_hash")


def _target(tenant: str | None) -> tuple[str, str, str]:
    """(partition-name prefix, schema, qualified parent table)."""
    if tenant is None:
        return "audit_log_global_p", "public", "audit_log_global"
    schema = schema_for_tenant(tenant)
    return "audit_log_p", schema, f'"{schema}".audit_log'


def list_partitions(conn, tenant: str | None) -> list[tuple[str, "datetime.date"]]:
    prefix, schema, _ = _target(tenant)
    pattern = f"^{prefix}[0-9]{{8}}$"  # underscores are literal in POSIX regex
    with conn.cursor() as cur:
        cur.execute(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = %s AND c.relkind = 'r' AND c.relname ~ %s", (schema, pattern))
        out = []
        for (name,) in cur.fetchall():
            try:
                day = datetime.strptime(name[len(prefix):], "%Y%m%d").date()
            except ValueError:
                continue
            out.append((name, day))
    return sorted(out, key=lambda x: x[1])


def aged_partitions(conn, tenant, keep_days, today=None):
    today = today or datetime.now(timezone.utc).date()
    cutoff = today - timedelta(days=keep_days)
    return [(n, d) for (n, d) in list_partitions(conn, tenant) if d < cutoff]


def _row_dict(rec) -> dict:
    (seq, event_id, ts, category, action, outcome, actor, actor_roles, target_uid,
     target_name, target_type, detail, source_iface, source_addr, request_id,
     prev_hash, row_hash) = rec
    return {"seq": seq, "event_id": str(event_id), "ts": ts.isoformat(),
            "category": category, "action": action, "outcome": outcome, "actor": actor,
            "actor_roles": actor_roles, "target_uid": target_uid, "target_name": target_name,
            "target_type": target_type, "detail": detail, "source_iface": source_iface,
            "source_addr": source_addr, "request_id": request_id,
            "prev_hash": bytes(prev_hash).hex() if prev_hash is not None else None,
            "row_hash": bytes(row_hash).hex() if row_hash is not None else None}


def archive_and_drop(conn, tenant, partition_name, day, archive, cipher) -> dict:
    _, schema, _ = _target(tenant)
    qpart = partition_name if tenant is None else f'"{schema}".{partition_name}'

    rows = []
    with conn.cursor() as cur:
        cur.execute(f"SELECT {_COLS} FROM {qpart} ORDER BY seq")
        rows = [_row_dict(r) for r in cur.fetchall()]

    if rows:
        manifest = {"tenant": tenant, "scope": "global" if tenant is None else "tenant",
                    "day": day.isoformat(), "count": len(rows),
                    "first_seq": rows[0]["seq"], "last_seq": rows[-1]["seq"],
                    "first_prev_hash": rows[0]["prev_hash"], "last_row_hash": rows[-1]["row_hash"]}
        body = json.dumps({"manifest": manifest}) + "\n"
        body += "".join(json.dumps(r) + "\n" for r in rows)
        token = cipher.encrypt(body.encode("utf-8"))
        key = f"{'global' if tenant is None else tenant}/{partition_name}.ndjson.enc"
        # Write, then read it back + decrypt + count before dropping anything.
        archive.put(key, token)
        verify_lines = cipher.decrypt(archive.get(key)).decode("utf-8").splitlines()
        if len(verify_lines) != len(rows) + 1:
            raise RuntimeError(f"archive verification failed for {key}")
        result = {**manifest, "key": key}
    else:
        result = {"tenant": tenant, "day": day.isoformat(), "count": 0}

    with conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {qpart}")
    result["dropped"] = partition_name
    return result


def run(conn, tenant, config, *, today=None) -> list[dict]:
    """Archive + drop every aged partition for a tenant (or None for global)."""
    archive = make_archive(config)
    if archive is None:
        log.info("archive backend is 'none'; retention disabled")
        return []
    cipher = make_cipher(config.archive_key)
    results = []
    for name, day in aged_partitions(conn, tenant, config.retention_days, today):
        res = archive_and_drop(conn, tenant, name, day, archive, cipher)
        conn.commit()
        results.append(res)
        log.info("archived + dropped %s (%s rows)", res.get("key", name), res.get("count", 0))
    return results


def main() -> None:  # pragma: no cover
    import sys

    from . import db
    from .config import Config, load_dotenv

    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    config = Config()
    arg = sys.argv[1] if len(sys.argv) > 1 else "--global"
    tenant = None if arg == "--global" else arg
    conn = db.connect(config)
    try:
        res = run(conn, tenant, config)
    finally:
        conn.close()
    print(f"archived + dropped {len(res)} partition(s) for "
          f"{'global' if tenant is None else tenant}")


if __name__ == "__main__":
    main()
