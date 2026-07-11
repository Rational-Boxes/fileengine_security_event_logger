-- Append-only audit DB role (usage_logging_and_auditing §7) — DEFENSE IN DEPTH.
--
-- The hash chain (row_hash/prev_hash, verified by `audit-verify`) already makes
-- the audit log tamper-EVIDENT: any edit, deletion, or reordering is detectable.
-- These grants make it additionally tamper-RESISTANT at the DB level, so the
-- runtime role cannot UPDATE or DELETE existing audit rows at all.
--
-- Run as a Postgres superuser / the DB owner. Re-apply the per-schema block for
-- every tenant schema, including new tenants as they are provisioned.
--
-- IMPORTANT — partition ownership (the append-only caveat):
--   The audit_service writer creates daily partitions on demand. A role that
--   CREATEs a partition OWNS it, and an owner can UPDATE/DELETE its own table
--   regardless of REVOKEs on the parent. So there are two deployment models:
--
--   (A) Writer creates partitions (simplest; what the code does today).
--       The writer role needs CREATE on the schema, and therefore owns the
--       partitions — REVOKE below still blocks mutation of the PARENT, but the
--       writer could technically mutate rows in partitions it owns. The hash
--       chain still detects any such tampering. Acceptable when the writer host
--       is trusted and the chain is the primary control.
--
--   (B) A separate maintenance role pre-creates partitions (strongest).
--       Partitions are owned by a non-writer role; the writer gets ONLY
--       INSERT+SELECT and cannot create/own/mutate anything. Requires a small
--       partition-maintenance job (create tomorrow's partition ahead of time)
--       and disabling the writer's on-demand creation. Recommended for
--       high-assurance deployments.
--
-- The blocks below configure model (A). For (B): drop the CREATE grant from the
-- writer, run partition creation as <maintenance_role>, and keep the rest.

-- === 1. Roles ===
-- The append-only writer the audit_service connects as (FILEENGINE_PG_USER).
CREATE ROLE fileengine_audit_writer LOGIN PASSWORD :'writer_password';
-- Optional read-only role for the query/export API (§9); app-gated by AUDIT_READ.
CREATE ROLE fileengine_audit_reader LOGIN PASSWORD :'reader_password';

-- === 2. Per tenant schema (repeat for each <schema>, e.g. tenant_acme) ===
--   :schema is a psql variable; run e.g.
--   psql -v schema=tenant_acme -v writer_password=... -f append_only_grants.sql
GRANT USAGE, CREATE ON SCHEMA :"schema" TO fileengine_audit_writer;   -- CREATE: model (A) only
GRANT INSERT, SELECT ON :"schema".audit_log TO fileengine_audit_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON :"schema".audit_log FROM fileengine_audit_writer;
GRANT USAGE ON SCHEMA :"schema" TO fileengine_audit_reader;
GRANT SELECT ON :"schema".audit_log TO fileengine_audit_reader;
-- Future daily partitions inherit these table privileges automatically.
ALTER DEFAULT PRIVILEGES IN SCHEMA :"schema"
    GRANT INSERT, SELECT ON TABLES TO fileengine_audit_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA :"schema"
    GRANT SELECT ON TABLES TO fileengine_audit_reader;

-- === 3. Global table (public) ===
GRANT INSERT, SELECT ON audit_log_global TO fileengine_audit_writer;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log_global FROM fileengine_audit_writer;
GRANT SELECT ON audit_log_global TO fileengine_audit_reader;
