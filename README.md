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
| `writer.py` | on-demand daily partitions + deduplicating batch insert |
| `db.py` | Postgres connection (UTC session, statement timeout) |
| `consumer.py` | the drain→write→commit→ack loop + Redis source |
