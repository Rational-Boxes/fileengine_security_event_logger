# audit_service

The single deployment-wide **audit writer** for FileEngine. It is the sole
writer of the append-only `audit_log` tables (one per tenant schema) and the
`public.audit_log_global` table (usage_logging_and_auditing §5).

Every emitter — the core gRPC handlers, `ldap_manager`, and each authenticating
door — publishes one tenant-tagged entry per audited action to a single
aggregating **Redis Stream** (`fileengine:audit`, separate from the fail-open
`fileengine:events`). This service:

1. drains the stream through a consumer group (at-least-once);
2. parses each envelope (see [`AUDIT_CONTRACT.md`](AUDIT_CONTRACT.md));
3. demultiplexes by `tenant` and appends to that tenant's `audit_log` — creating
   the day's range partition on demand;
4. commits, then **acks only after the commit** — so an ack always means
   "durably in the DB", and a crash between commit and ack re-delivers safely
   (the `(event_id, ts)` unique key makes the re-insert a no-op).

Being the only writer, it also owns row ordering and (Phase 7) the per-tenant
hash chain, and (Phase 9) it will host the security rules engine that rides the
same stream.

## Run

```sh
pip install -e .
audit-consumer          # reads .env in the working directory
```

## Test

Unit tests always run; the `live` integration tests light up only when Redis and
Postgres are reachable (point them with the standard `FILEENGINE_*` env vars):

```sh
pip install -e '.[dev]'
PYTHONPATH=src python -m pytest src/tests -q
```

## Layout

| module | role |
|---|---|
| `config.py` | env-driven config (shared Redis + core Postgres) |
| `codes.py` | string ⇄ SMALLINT maps for the enum columns (source of truth) |
| `naming.py` | tenant → schema name, a faithful port of the core's logic |
| `envelope.py` | parse/validate an envelope into a typed `AuditRow` |
| `writer.py` | on-demand daily partitions + deduplicating, hash-chained insert |
| `hashing.py` | the per-tenant tamper-evidence hash chain (§7) |
| `verify.py` | walk + verify a chain (`audit-verify`), surfaced as VerifyAuditChain |
| `auth.py` / `api.py` / `queries.py` | the AUDIT_READ-gated query/export/verify HTTP API (§9) |
| `retention.py` / `archive.py` | 30-day window + daily encrypted archival (§7) |
| `rules.py` / `windows.py` / `engine.py` | the security rules engine (§11) |
| `db.py` | Postgres connection (UTC session, statement timeout) |
| `consumer.py` | the drain→write→commit→ack loop + Redis source |

## Security rules engine (§11)  — `audit-rules`

Rides the same audit stream as a **separate consumer group**, keeps per-rule
event-time sliding windows, and evaluates a deterministic rule catalog. A rule is
data (`rules.Rule`): a `when` match counted in `window_s` grouped by
actor/source_addr/tenant; at `threshold` it fires with a `severity` and a
graduated `response` — **flag** (record an incident), **alert** (+ notify), or
**auto_disable** (opt-in, with `dry_run`). A `then` action makes it a sequence
rule (login_failure ×k *then* login_success = a likely successful guess).

**Serious/critical severities always email tenant admins** (mandatory, §11) —
regardless of response mode. The default pack (brute-force login, source-IP
spray, credential-guess, bulk-exfiltration, mass-delete) ships in flag/alert;
auto-disable is opt-in. Side effects (incident store, admin email, ldap_manager
auto-disable) go through injectable interfaces — real implementations are wired
at deployment. The guided/raw-DSL **rule builder** and the **console** UI (folded
into the ldap_manager admin area) consume this engine + the §9 API.

## Query/export API (§9)  — `audit-api`

AUDIT_READ-gated (tenant admin via the http_bridge JWT; system_admin bypasses;
REST only, no MCP). Every read is itself audited.

- `GET /v1/audit/query?tenant=&actor=&category=&…&page=&page_size=` — filtered page
- `GET /v1/audit/export?…` — streaming NDJSON compliance dump
- `GET /v1/audit/verify?tenant=` — VerifyAuditChain

## Retention (§7)  — `audit-retention`

A daily job archives every `audit_log` partition older than
`FILEENGINE_AUDIT_RETENTION_DAYS` (default 30) to a **Fernet-encrypted** NDJSON
file (local dir or S3), verifies the write, then drops the partition. Each archive
carries a manifest with the day's first `prev_hash` / last `row_hash` so the chain
stays verifiable across the DB→archive boundary. Requires
`FILEENGINE_AUDIT_ARCHIVE_KEY` — it refuses to write audit data unencrypted.

## Tamper-evidence (§7)

Being the sole writer, the consumer chains every row:
`row_hash = SHA-256(prev_hash ‖ canonical(row))`, where `prev_hash` is the previous
row's `row_hash`. `seq` is *not* in the hash, so reordering also breaks the chain.
The chain is deterministic, so at-least-once re-delivery recomputes identical
hashes and `INSERT … ON CONFLICT DO NOTHING RETURNING` advances the head correctly.

Verify a chain (exit non-zero on tampering):

```sh
audit-verify <tenant>     # a tenant's audit_log
audit-verify --global     # public.audit_log_global
```

For DB-level append-only enforcement (defense in depth beyond the chain), apply
[`scripts/append_only_grants.sql`](scripts/append_only_grants.sql) — note the
partition-ownership caveat documented there.
