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
| `retention.py` / `archive.py` / `catalog.py` | two-month window + monthly encrypted archival to the main store (§7) |
| `archive_cli.py` | `audit-archive`: verify the archive end to end, export archived rows |
| `chain.py` | the one chain walk + row codec shared by verify, archive and read-back |
| `rules.py` / `windows.py` / `engine.py` | the security rules engine (§11) |
| `db.py` | Postgres connection (UTC session, statement timeout) |
| `consumer.py` | the drain→write→commit→ack loop + Redis source |
| `accountability.py` | the core's guaranteed record: canonical form, chain hash, per-batch verification |
| `core_client.py` | gRPC client for the core's `ListAccountabilityRecords` pull endpoint |
| `cursors.py` | per-tenant `recorded_until` watermarks |
| `puller.py` | drain a chain → verify → append → advance the cursor; tenant-deletion handling |
| `poller.py` | the scheduled drain + queue-hint reaction (`audit-accountability`) |

## The core's accountability records — `audit-accountability`

The stream above is a fine transport and an unacceptable system of record: it is
trimmed, sampled and fail-open. For the core's security-relevant operations —
ACL grants and revokes, role changes, version culls, tenant lifecycle — the core
writes a hash-chained record **in the same transaction as the operation**, and
this service reads it forward by cursor over gRPC instead of trusting the queue.

```sh
audit-accountability     # the scheduled drain + queue-hint reaction
```

Points worth knowing before touching it:

- **The cursor is a timestamp, not a sequence number.** The question it has to
  answer is "are there core records older than this incoming subsystem event?",
  and time is the only axis the sources share. `seq` still travels, for gap
  detection.
- **A gap, a broken link, a non-increasing `ts` or a row that does not re-hash is
  an ALARM, not a retry.** The drain stops advancing that tenant's cursor and
  halts it. A consumer that skips a gap to keep draining converts an integrity
  failure into silent data loss, which is the failure the record exists to
  prevent.
- **Per tenant, all the way down.** The chain, the cursor and the drain are all
  per tenant, so one tenant's backlog or alarm never affects another's.
- **Redis is optional here.** A hint shortens latency; nothing depends on it.
- **A halt is durable and needs a human.** It is a row on
  `accountability_cursor`, not process state, so a restart does not clear it —
  an alarm cleared by a restart is not an alarm. Inspect and clear it with
  `audit-accountability-ack` (no argument lists what is halted and the seq to
  look at). Draining resumes from the cursor, which never moved, so the records
  after the break are re-read and re-verified rather than skipped.

### Is the drain actually running?

An unmonitored backstop is not a backstop: a drain that stops throws nothing and
looks exactly like a quiet period. Both failure modes are answerable from
outside the process, because the state lives in the shared cursor table rather
than in counters that reset on restart:

| Surface | Shows |
|---|---|
| `GET /drainz` | every chain's cursor, its age, and any halt with its seq and reason |
| `GET /readyz` | 503 while a chain is halted or the drain has gone stale |
| `GET /metrics` | `fileengine_accountability_halted_chains` (above zero is a security page), `..._drain_age_seconds` (rising without bound means stopped), `..._cursor_seq` and `..._chain_halted` per tenant |

A halted chain is deliberately excluded from the staleness calculation — its
cursor is frozen on purpose, and letting that read as "stale" would make one
alarm mask the other.

See `file_engine_core/design_documents/PROPOSAL_accountability_record.md`, and
`scripts/e2e_accountability.py` for the end-to-end proof against a real core
running with auditing and Redis both switched off.

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

## Retention (§7) — `audit-retention` / `audit-archive`

Postgres keeps **two complete calendar months** (`FILEENGINE_AUDIT_RETENTION_MONTHS`,
default 2). A monthly job (the 1st, 03:30 UTC) archives everything older into the
**main S3 store** under each tenant's virtual folder, then drops it:

```
<tenant>/_audit/<YYYY>/<MM>/<run id>/part-<NNNNN>.ndjson.enc   (Fernet, ≤ AUDIT_ARCHIVE_PART_ROWS rows)
<tenant>/_audit/<YYYY>/<MM>/<run id>/manifest.json.enc
_global/_audit/…                                                (the deployment-wide chain)
```

Per scope, in one transaction: lock the aged partitions against the writer, keep
only those forming a **prefix of the chain in `seq` order** (a late-arriving row
holds its day back), stream the rows a bounded part at a time, write and **read
back** every object, record the segment in `public.audit_archive_segments` /
`audit_archive_parts`, drop, commit. Requires `FILEENGINE_AUDIT_ARCHIVE_KEY` — it
refuses to write audit data unencrypted. S3 settings default to the core's own
`FILEENGINE_S3_*`.

The catalog's newest segment is the chain's **anchor**: `audit-verify`,
`audit-rechain` and the writer all continue the chain from it, so archiving
never makes a retained chain look tampered.

```sh
audit-retention [--all | --global | --tenant T] [--dry-run]
audit-archive verify [--all | --global | --tenant T]     # archive + DB, end to end
audit-archive export --tenant T [--from 2026-08-01] [--to 2026-09-01] > rows.ndjson
```

The lifecycle is simulated with a clock override — `--today YYYY-MM-DD` or
`AUDIT_RETENTION_TODAY` — honoured **only** with `AUDIT_ALLOW_DATE_OVERRIDE=true`.
The full contract: [`design_documents/SPEC_retention_and_archival.md`](design_documents/SPEC_retention_and_archival.md).

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
