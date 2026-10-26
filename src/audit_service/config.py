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


def _bool(key: str, default: bool) -> bool:
    val = _env(key, "")
    if not val:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


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

        # --- Telling a deployment administrator (§5) -------------------------
        # The AdminNotifier was a stub that logged a notification it never sent,
        # so a deployment could run for a year believing it was covered. With
        # these unset the notifier now says so at ERROR for every mandatory
        # incident, rather than being quietly absent.
        #
        # Comma-separated, because a single address is a single point of leave.
        self.admin_emails = tuple(
            a.strip() for a in _env("AUDIT_ADMIN_EMAILS", "").split(",") if a.strip())
        self.smtp_host = _env("AUDIT_SMTP_HOST", _env("FILEENGINE_SMTP_HOST", ""))
        self.smtp_port = _int("AUDIT_SMTP_PORT", _int("FILEENGINE_SMTP_PORT", 25))
        self.smtp_from = _env("AUDIT_SMTP_FROM", _env("FILEENGINE_SMTP_FROM", ""))
        self.smtp_user = _env("AUDIT_SMTP_USER", _env("FILEENGINE_SMTP_USER", ""))
        self.smtp_password = _env("AUDIT_SMTP_PASSWORD", _env("FILEENGINE_SMTP_PASSWORD", ""))
        self.smtp_tls = _env("AUDIT_SMTP_TLS", "false").lower() in ("1", "true", "yes")

        # --- The deployment tier reading across tenants (§3.4) ---------------
        # admin_master_control's token audience, and the deployment roles that
        # confer AUDIT_READ over every tenant. Deliberately NOT system_admin:
        # that is the core's ACL bypass and reads every file in every tenant,
        # which is far more than "read the audit ledger".
        self.deployment_audience = _env("AUDIT_DEPLOYMENT_AUDIENCE", "fileengine-system-admin")
        # The console signs its sessions with its OWN secret (it must not be able
        # to mint a tenant token), and forwards the signed-in administrator's
        # session here. Tokens under this secret are admitted only as deployment
        # identities — see auth.verify_jwt. Empty: the console cannot read here.
        self.deployment_jwt_secret = _env("AUDIT_DEPLOYMENT_JWT_SECRET", "")
        self.deployment_require_mfa = _env("AUDIT_DEPLOYMENT_REQUIRE_MFA", "true").lower() \
            not in ("0", "false", "no")
        self.deployment_read_roles = tuple(
            r.strip() for r in _env("AUDIT_DEPLOYMENT_READ_ROLES",
                                    "system_observer,system_security").split(",") if r.strip())

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

        # --- Retention (§7) — see design_documents/SPEC_retention_and_archival.md ---
        # Complete calendar months kept in Postgres; a monthly run archives the rest.
        self.retention_months = _int("FILEENGINE_AUDIT_RETENTION_MONTHS", 2)
        # Retired: the window is months now. Kept only so the job can warn when a
        # deploy still sets it, rather than silently meaning something else.
        self.legacy_retention_days = _env("FILEENGINE_AUDIT_RETENTION_DAYS", "")
        # s3 (default) = the MAIN content bucket, under a per-tenant virtual folder.
        # local is for development and must be an absolute directory; a relative
        # one inside a --rm container is how an archive silently disappears.
        self.archive_backend = _env("AUDIT_ARCHIVE_BACKEND", "s3")   # s3|local|none
        self.archive_dir = _env("AUDIT_ARCHIVE_DIR", "")
        # Every S3 setting defaults to the core's own, so "the main store" is the
        # zero-configuration answer; the AUDIT_ARCHIVE_S3_* names override it.
        self.archive_s3_bucket = _env("AUDIT_ARCHIVE_S3_BUCKET", _env("FILEENGINE_S3_BUCKET", ""))
        self.archive_s3_endpoint = _env("AUDIT_ARCHIVE_S3_ENDPOINT", _env("FILEENGINE_S3_ENDPOINT", ""))
        self.archive_s3_region = _env("AUDIT_ARCHIVE_S3_REGION", _env("FILEENGINE_S3_REGION", "us-east-1"))
        self.archive_s3_access_key = _env("AUDIT_ARCHIVE_S3_ACCESS_KEY", _env("FILEENGINE_S3_ACCESS_KEY", ""))
        self.archive_s3_secret_key = _env("AUDIT_ARCHIVE_S3_SECRET_KEY", _env("FILEENGINE_S3_SECRET_KEY", ""))
        self.archive_s3_path_style = _bool("AUDIT_ARCHIVE_S3_PATH_STYLE",
                                           _bool("FILEENGINE_S3_PATH_STYLE", False))
        self.archive_s3_prefix = _env("AUDIT_ARCHIVE_S3_PREFIX", "")
        # The virtual folder beside the core's <tenant>/<uid>/<version> keys, and
        # the scope id of the global chain. Both must start with "_" so neither
        # can ever be a tenant id ([a-z][a-z0-9]+) or a file uid.
        self.archive_folder = _env("AUDIT_ARCHIVE_FOLDER", "_audit")
        self.archive_global_scope = _env("AUDIT_ARCHIVE_GLOBAL_SCOPE", "_global")
        # Rows per encrypted part object: the memory bound of a run.
        self.archive_part_rows = _int("AUDIT_ARCHIVE_PART_ROWS", 5000)
        # The core's accountability record is retained on the same window and
        # archived beside the audit log, under its own reserved folder (§14).
        self.accountability_retention = _bool("AUDIT_ACCOUNTABILITY_RETENTION", True)
        self.archive_accountability_folder = _env("AUDIT_ARCHIVE_ACCOUNTABILITY_FOLDER",
                                                  "_accountability")
        # Comma-separated Fernet keys; the first encrypts, all decrypt (rotation).
        # Required to archive — the job refuses to write audit data unencrypted.
        # Deployments derive it from AT_REST_KEY (keys.py, §10) rather than
        # minting a second secret; the job itself is only ever given the result.
        self.archive_key = _env("FILEENGINE_AUDIT_ARCHIVE_KEY", "")
        # A run streams a month of rows inside one transaction, so the writer's
        # 10 s statement bound is far too short for it; the DROP's lock wait is
        # bounded separately so a busy writer cannot stall the job indefinitely.
        self.retention_statement_timeout_ms = _int("AUDIT_RETENTION_STATEMENT_TIMEOUT_MS", 600000)
        self.retention_lock_timeout_ms = _int("AUDIT_RETENTION_LOCK_TIMEOUT_MS", 30000)
        # The lifecycle simulation's clock. Honoured ONLY when the second flag is
        # set: a future date archives live data, which a test wants and
        # production must never do by accident.
        self.retention_today = _env("AUDIT_RETENTION_TODAY", "")
        self.allow_date_override = _bool("AUDIT_ALLOW_DATE_OVERRIDE", False)

    @property
    def pg_dsn(self) -> str:
        return (f"host={self.pg_host} port={self.pg_port} dbname={self.pg_database} "
                f"user={self.pg_user} password={self.pg_password}")
