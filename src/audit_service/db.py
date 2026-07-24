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
