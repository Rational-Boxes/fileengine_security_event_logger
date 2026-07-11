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
| `db.py` | Postgres connection (UTC session, statement timeout) |
| `consumer.py` | the drain→write→commit→ack loop + Redis source |

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
