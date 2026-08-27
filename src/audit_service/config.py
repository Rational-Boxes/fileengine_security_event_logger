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
        # The rules engine reads the same stream as a SEPARATE group (§11), so it
        # sees every event independently of the writer.
        self.rules_group = _env("AUDIT_RULES_GROUP", "audit-rules")
        self.read_count = _int("AUDIT_READ_COUNT", 256)
        self.read_block_ms = _int("AUDIT_READ_BLOCK_MS", 5000)

        # --- Postgres: the CORE database (tenant schemas + audit_log live here) ---
        self.pg_host = _env("FILEENGINE_PG_HOST", "localhost")
        self.pg_port = _int("FILEENGINE_PG_PORT", 5432)
        self.pg_database = _env("FILEENGINE_PG_DATABASE", "fileengine")
        self.pg_user = _env("FILEENGINE_PG_USER", "postgres")
        self.pg_password = _env("FILEENGINE_PG_PASSWORD", "postgres")
        self.db_statement_timeout_ms = _int("AUDIT_DB_STATEMENT_TIMEOUT_MS", 10000)

        # --- Query/export API (§9) — read side, gated by AUDIT_READ ---
        # AUDIT_READ = tenant admin (a member of the tenant's admin role) or
        # system_admin, resolved from the http_bridge-issued HS256 JWT.
        self.jwt_secret = _env("FILEENGINE_JWT_SECRET", "")
        self.admin_role = _env("AUDIT_ADMIN_ROLE", "administrators")
        self.system_admin_role = _env("AUDIT_SYSTEM_ADMIN_ROLE", "system_admin")
        self.api_host = _env("AUDIT_API_HOST", "127.0.0.1")
        self.api_port = _int("AUDIT_API_PORT", 8097)  # 8095/8096 are discussion-mcp/core-mcp
        self.query_max_page = _int("AUDIT_QUERY_MAX_PAGE", 500)

        # --- The core's accountability record (§4.3) — the PULL path ---------
        # The guarantee path for core security records. We read them forward by
        # cursor over gRPC rather than trusting the Redis stream, which is
        # trimmed and fail-open: a fine transport, an unacceptable system of
        # record. gRPC is never network-exposed, so this is an in-cluster address.
        self.core_grpc_host = _env("FILEENGINE_GRPC_HOST", "localhost")
        self.core_grpc_port = _int("FILEENGINE_GRPC_PORT", 50051)
        self.core_grpc_timeout_s = _int("AUDIT_CORE_GRPC_TIMEOUT_S", 30)
        self.core_grpc_max_message_bytes = _int("AUDIT_CORE_GRPC_MAX_MESSAGE_BYTES",
                                                32 * 1024 * 1024)
        # The identity we present to the core. The role is DEDICATED, not an
        # admin role: reading this chain across tenants reconstructs who did what
        # to whom platform-wide, so least privilege applies even inside the trust
        # boundary. Granting a service gRPC access must not grant it the security
        # log.
        self.core_identity = _env("AUDIT_CORE_IDENTITY", "audit_service")
        self.core_reader_role = _env("AUDIT_CORE_READER_ROLE", "accountability_reader")
        # Polling cadence. The Redis hint only shortens this; correctness never
        # depends on either the hint arriving or the interval being short.
        self.pull_interval_s = _int("AUDIT_PULL_INTERVAL_S", 15)
        self.pull_page_size = _int("AUDIT_PULL_PAGE_SIZE", 500)
        # A bound on how much one drain will chase in a single pass, so a huge
        # backlog cannot starve the rest of the loop. It is a fairness limit, not
        # a cap on what is delivered — the next pass continues where this stopped.
        self.pull_max_pages = _int("AUDIT_PULL_MAX_PAGES", 100)
        # The hint stream (§4.3). Hints ride the fail-open file-activity stream,
        # not the durable audit one, because that is exactly what a hint is.
        self.events_stream = _env("FILEENGINE_EVENTS_STREAM", "fileengine:events")
        self.hint_group = _env("AUDIT_HINT_GROUP", "audit-accountability")

        # --- Retention (§7) — 30-day rolling DB window + daily encrypted archive ---
        self.retention_days = _int("FILEENGINE_AUDIT_RETENTION_DAYS", 30)
        self.archive_backend = _env("AUDIT_ARCHIVE_BACKEND", "local")   # local|s3|none
        self.archive_dir = _env("AUDIT_ARCHIVE_DIR", "audit-archive")
        self.archive_s3_bucket = _env("AUDIT_ARCHIVE_S3_BUCKET", "")
        self.archive_s3_prefix = _env("AUDIT_ARCHIVE_S3_PREFIX", "audit")
        self.archive_s3_endpoint = _env("AUDIT_ARCHIVE_S3_ENDPOINT", "")  # for S3-compatible stores
        # Fernet key (base64) — archives are encrypted at rest; required to archive.
        self.archive_key = _env("FILEENGINE_AUDIT_ARCHIVE_KEY", "")

    @property
    def pg_dsn(self) -> str:
        return (f"host={self.pg_host} port={self.pg_port} dbname={self.pg_database} "
                f"user={self.pg_user} password={self.pg_password}")
