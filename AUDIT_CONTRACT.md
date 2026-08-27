# Audit envelope contract

The aggregating security-event sink is a **Redis Stream** (default
`fileengine:audit`, separate from the fail-open `fileengine:events`). Every
emitter — the core gRPC handlers, `ldap_manager`, and each authenticating door —
publishes one entry per audited action with `XADD <stream> * payload <json>`,
where `<json>` is the envelope below. The single `audit-service` consumer drains
the stream, demultiplexes by `tenant`, and appends to that tenant's append-only
`audit_log` (or `public.audit_log_global`). See
`file_engine_core/design_documents/usage_logging_and_auditing.md` (§4, §5).

## Envelope fields

| field | required | type | notes |
|---|---|---|---|
| `event_id` | ✅ | UUID string | idempotency key — a re-delivered event with the same `event_id`+`ts` is a no-op (`UNIQUE (event_id, ts)`). The emitter generates it. |
| `ts` | ✅ | ISO-8601 string or epoch seconds | **emit-time**, authoritative (the consumer writes asynchronously later). Naive timestamps are treated as UTC. Drives the daily partition. |
| `scope` | – | `"tenant"` \| `"global"` | default `"tenant"`. `"global"` → `public.audit_log_global`. |
| `tenant` | ✅ if `scope=tenant` | string | the tenant identifier (NOT the schema name — the consumer derives `tenant_<id>` exactly as the core does). Also stored as a column on the global table. |
| `category` | ✅ | enum string | `access` \| `mutate` \| `permission` \| `user` \| `auth` \| `admin`. |
| `action` | ✅ | string (≤32) | e.g. `read`, `write`, `acl_grant`, `login_failure`. |
| `outcome` | ✅ | enum string | `ok` \| `denied` \| `error`. |
| `actor` | ✅ | string (≤255) | resolved end-user identity, or the *attempted* identity for `auth`. |
| `actor_roles` | – | array or string | effective roles at decision time; arrays are stored CSV. |
| `target_uid` | – | string (≤64) | file/dir/role/principal uid. |
| `target_name` | ⛔ | — | **Removed. Do not send it.** Filenames are party data, and this log is immutable, hash-chained and long-lived — so a name recorded here is one the platform has committed to keeping and cannot easily remove on request. The rule is that the log records identifiers and structure, never payload: send `target_uid`, and let a viewer join to the current name at read time. After an erasure that join finds nothing and the log automatically stops disclosing it, which makes compliance a property of the architecture rather than an operation someone must remember to run. The column survives (nullable, always NULL) so existing rows and the hash chain's canonical form are unaffected; the consumer discards the field if an emitter still sends one. See `file_engine_core/design_documents/PROPOSAL_accountability_record.md` §5.4.7. |
| `target_type` | – | enum string | `file` \| `dir` \| `role` \| `acl` \| `version` \| `principal`. |
| `detail` | – | object or JSON string | action-specific (`{before,after}` perms, move dest, version, byte range, …). Stored as JSONB. |
| `source_iface` | – | string (≤16) | `grpc` \| `rest` \| `webdav` \| `mcp`. |
| `source_addr` | – | string (≤64) | client IP (forwarded by the bridge). |
| `request_id` | – | string (≤64) | correlates multi-hop (bridge→core). |

The string enums map to compact SMALLINTs in `audit_service.codes` — that module
is the single source of truth and must stay in lockstep with the C++ emitter.

## The core's accountability records are NOT delivered this way

Everything above describes the **push** path: emitters publish to the stream and
the consumer drains it. That path is fine for most of the taxonomy and
structurally incapable of carrying the records that matter most.

For the operations that matter most to accountability — who was granted access,
who revoked it, who destroyed what — the core writes a **guaranteed** record to
its own `accountability_record` table, in the **same transaction as the operation
it describes**. `audit_service` reads those forward by cursor over gRPC
(`ListAccountabilityRecords`), not off this stream:

```
operation ──┬─▶ commit (state + accountability_record, one transaction)
            ├─▶ audit_service polls  ts > recorded_until      ← the guarantee
            └─▶ Redis hint on fileengine:events               ← latency only
```

The reason is that this stream cannot make the promise. Push audit entries are
best-effort for mutations, silently absent when auditing is unconfigured,
non-transactional (the DB commit and the WAL append are separate, so a crash
between them loses the record for a committed operation), and node-local. There
is no moment at which "the operation happened" and "a record exists" are atomic.
The pull path makes them the same moment.

What that buys, concretely:

- **No broker outage, outbox overflow or lost node can lose a record.**
- **`audit_service` can be rebuilt from zero** by resetting its cursor and
  replaying core history — impossible when the record's only home was a stream
  that trims.
- **Backlog is visible and bounded by disk**, not by an outbox capacity that
  drops oldest under pressure.

Two rules follow for anything consuming this log:

1. **Precedence.** On any incoming queue event, from any subsystem, the core
   table is consulted and drained *before* that event is recorded. The chain
   records the order it was written in and cannot be re-sorted afterwards, so
   appending a subsystem event while older core records are unread would place
   them out of order permanently. The core is the anchor everything else is
   sequenced against.
2. **Two timestamps.** `ts` is when an event *occurred*; `recorded_at` is when it
   was appended. The chain is ordered by the latter, and the former can
   legitimately run slightly backwards between adjacent entries from different
   sources — cross-source ordering is only accurate to within the queue latency.
   Recording both makes that visible rather than looking like clock corruption.
   Causal order survives regardless: if B depends on A, B could only occur after
   A was *visible*, which is strictly later than A being recorded.

## Delivery semantics

- **At-least-once** (consumer group `XREADGROUP` + `XACK`). The consumer acks only
  after the DB commit; the `(event_id, ts)` unique key absorbs re-delivery.
- **Poison messages** (structurally invalid envelopes) are logged and dropped
  (acked) with a counter — they can never be written and must not block the
  stream. A durable dead-letter is a later refinement.
