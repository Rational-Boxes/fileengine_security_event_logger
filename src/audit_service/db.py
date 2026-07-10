"""Postgres connection for the audit writer (the core database).

The session TimeZone is pinned to UTC so daily partition routing/boundaries are
deterministic (see writer.py), and a statement timeout guards against a stuck
write blocking the single writer.
"""
from __future__ import annotations

import psycopg


def connect(config):
    conn = psycopg.connect(config.pg_dsn, autocommit=False)
    with conn.cursor() as cur:
        cur.execute("SET TimeZone = 'UTC'")
        # SET does not accept bound parameters; inline the int (validated, safe).
        cur.execute(f"SET statement_timeout = {int(config.db_statement_timeout_ms)}")
    conn.commit()
    return conn
