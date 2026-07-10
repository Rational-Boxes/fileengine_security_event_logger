"""Configuration for audit_service, read from the environment.

Mirrors the discussion/CSAI convention: a ``.env`` in the working directory is
loaded without overriding values already set in the real environment. The
service reaches the SAME Redis broker (``FILEENGINE_REDIS_*``) and the SAME
Postgres the core writes (``FILEENGINE_PG_*`` — the tenant schemas and their
``audit_log`` tables live there). Service-specific knobs use the ``AUDIT_*``
prefix.
"""
from __future__ import annotations

import os


def load_dotenv(path: str = ".env") -> None:
    if not os.path.isfile(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), _strip_value(val))


def _strip_value(val: str) -> str:
    val = val.strip()
    if val[:1] in ("'", '"'):
        q = val[0]
        end = val.find(q, 1)
        return val[1:end] if end != -1 else val[1:]
    if val.startswith("#"):
        return ""
    hi = val.find(" #")
    if hi != -1:
        val = val[:hi]
    return val.strip()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)))
    except ValueError:
        return default


class Config:
    def __init__(self) -> None:
        # --- Redis: the aggregating security-event sink (shared broker) ---
        # The audit stream is a SEPARATE pipeline from fileengine:events (§2):
        # complete + durable, not the fail-open notification stream.
        self.redis_host = _env("FILEENGINE_REDIS_HOST", "localhost")
        self.redis_port = _int("FILEENGINE_REDIS_PORT", 6379)
        self.redis_password = _env("FILEENGINE_REDIS_PASSWORD", "")
        self.redis_db = _int("FILEENGINE_REDIS_DB", 0)
        self.audit_stream = _env("FILEENGINE_AUDIT_STREAM", "fileengine:audit")
        self.audit_group = _env("AUDIT_CONSUMER_GROUP", "audit-writer")
        self.consumer_name = _env("AUDIT_CONSUMER_NAME", "writer-1")
        self.read_count = _int("AUDIT_READ_COUNT", 256)
        self.read_block_ms = _int("AUDIT_READ_BLOCK_MS", 5000)

        # --- Postgres: the CORE database (tenant schemas + audit_log live here) ---
        self.pg_host = _env("FILEENGINE_PG_HOST", "localhost")
        self.pg_port = _int("FILEENGINE_PG_PORT", 5432)
        self.pg_database = _env("FILEENGINE_PG_DATABASE", "fileengine")
        self.pg_user = _env("FILEENGINE_PG_USER", "postgres")
        self.pg_password = _env("FILEENGINE_PG_PASSWORD", "postgres")
        self.db_statement_timeout_ms = _int("AUDIT_DB_STATEMENT_TIMEOUT_MS", 10000)

    @property
    def pg_dsn(self) -> str:
        return (f"host={self.pg_host} port={self.pg_port} dbname={self.pg_database} "
                f"user={self.pg_user} password={self.pg_password}")
