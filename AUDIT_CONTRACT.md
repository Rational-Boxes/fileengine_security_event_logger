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
| `target_name` | – | string (≤1024) | name/path snapshot (best-effort). |
| `target_type` | – | enum string | `file` \| `dir` \| `role` \| `acl` \| `version` \| `principal`. |
| `detail` | – | object or JSON string | action-specific (`{before,after}` perms, move dest, version, byte range, …). Stored as JSONB. |
| `source_iface` | – | string (≤16) | `grpc` \| `rest` \| `webdav` \| `mcp`. |
| `source_addr` | – | string (≤64) | client IP (forwarded by the bridge). |
| `request_id` | – | string (≤64) | correlates multi-hop (bridge→core). |

The string enums map to compact SMALLINTs in `audit_service.codes` — that module
is the single source of truth and must stay in lockstep with the C++ emitter.

## Delivery semantics

- **At-least-once** (consumer group `XREADGROUP` + `XACK`). The consumer acks only
  after the DB commit; the `(event_id, ts)` unique key absorbs re-delivery.
- **Poison messages** (structurally invalid envelopes) are logged and dropped
  (acked) with a counter — they can never be written and must not block the
  stream. A durable dead-letter is a later refinement.
