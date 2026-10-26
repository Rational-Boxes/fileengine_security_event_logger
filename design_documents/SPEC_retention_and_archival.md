# Audit retention and archival — specification

**Status:** Implemented on `feat/audit-records-culling` (audit_service, scripts);
not yet deployed. Supersedes the "30-day rolling window + daily archive" decision
in `file_engine_core/design_documents/usage_logging_and_auditing.md` §7/§13.

**Decided 2026-10-25:**

* Postgres keeps **two complete calendar months** of audit records.
* An archiver runs **monthly**. It moves everything older than that into the
  **main S3 store**, the core's own content bucket, under a **virtual folder for
  each tenant**. Then it drops those rows from Postgres.
* The goal is that the audit tables stop growing without bound.

**Decided 2026-10-26:**

* The core's **accountability record** is retained the same way: the tables are
  the source of truth, and the Redis hint is only an indicator of activity. It is
  truncated monthly and its aged rows archived beside the audit log (§14).
* The archive is encrypted under the deployment's **global at-rest key**, so
  archived metadata that reaches the backups is as protected as the content. The
  archive key is derived from `AT_REST_KEY` (§6), not a second secret.
* The first production run is **supervised**: an operator starts it by hand and
  watches it, then enables the timer (§10).

---

## 1. Why this exists

Every audit row is kept forever in Postgres today. On 2026-10-22 production held
2.8 GB across 208 daily partitions, the oldest from 2026-08-25, growing about
1.4 GB a month. The earlier retention job never ran successfully, for three
reasons:

1. **It was never given its encryption key.** It refused to run every night
   from at least 2026-09-14.
2. **Adding the key alone would have destroyed data.** The default backend was a
   *relative* local directory inside a `podman run --rm` container with no
   volume. The job would have written the archive, read it back (the check
   passes), dropped the partition, and then the container, and the archive with
   it, would have been deleted.
3. **It only ever processed the global scope.** The per-tenant logs, about 99%
   of the data, were never pruned, even in principle.

It also had two latent defects, which this design removes:

* **It would have made every chain look tampered.** `audit-verify` starts every
  chain at `prev_hash = NULL`. After the oldest rows are dropped, the first
  remaining row links to an archived row, so the chain reads as broken.
* **It archived by day, not by chain order.** Partitions are split on the
  event's occurrence time (`ts`), while the chain is ordered by `seq` (append
  order). A late-arriving event, for example from an accountability backlog,
  lands in an *old* partition with a *new* `seq`. Dropping that partition cuts a
  hole in the middle of the chain.

## 2. Terms

| Term | Meaning |
| --- | --- |
| **scope** | One hash chain: a tenant's `"tenant_<id>".audit_log`, or the deployment-wide `public.audit_log_global`. |
| **scope id** | The tenant id (`default`, `rationalboxes`, …) or the reserved global id `_global`. |
| **cutoff** | The first instant that stays in Postgres. Everything with `ts < cutoff` is *aged*. |
| **segment** | Everything one run archived for one scope: a contiguous run of the chain, in `seq` order. |
| **part** | One encrypted object in a segment, holding at most `AUDIT_ARCHIVE_PART_ROWS` rows. |
| **anchor** | The last archived row of a scope (`last_seq`, `last_row_hash`). The chain in Postgres continues from it. |

## 3. The retention window

```
cutoff = first day of (month(today) − FILEENGINE_AUDIT_RETENTION_MONTHS), 00:00 UTC
```

With the default of 2 and the job running on the 1st:

| Run date | Cutoff | Kept in Postgres | Archived and dropped |
| --- | --- | --- | --- |
| 2026-11-01 | 2026-09-01 | Sep, Oct, Nov so far | everything before Sep |
| 2026-12-01 | 2026-10-01 | Oct, Nov, Dec so far | Sep |
| 2027-01-01 | 2026-11-01 | Nov, Dec, Jan so far | Oct |

Postgres therefore always holds **at least two complete months**, and at most
two months plus the current month so far, just before a run. The window is
defined by calendar months, not by days, so it doesn't drift with month length
or the timer's exact firing time. A late or repeated run in the same month uses
the same cutoff and finds nothing new.

`FILEENGINE_AUDIT_RETENTION_DAYS` is retired. If it is still set, the job logs a
warning and ignores it.

## 4. What is eligible: the chain-prefix rule

A partition is *aged* when its whole day falls before the cutoff. Being aged is
necessary but **not sufficient** to drop it. The archiver drops only a set of
partitions whose rows form a **prefix of the chain in `seq` order**:

```
candidates = aged partitions
repeat
    bound = min(seq) over every row NOT in candidates   (∞ if none)
    held  = candidates whose max(seq) > bound
    candidates −= held
until held is empty
```

A held-back partition contains a late-arriving row. It stays in Postgres until a
later run, when the rest of the chain has moved past it, and it is archived
then. The job logs every held partition with its `seq` range. Empty aged
partitions are always dropped and archive nothing.

This rule is what makes three guarantees hold together:

* every row left in Postgres has `seq > anchor.last_seq`;
* the first row left in Postgres links to the anchor
  (`prev_hash == anchor.last_row_hash`), when the chain was intact;
* consecutive segments of a scope link to each other.

## 5. Storage layout (main S3 store)

The archive is written to the **same bucket the core stores content in**
(`FILEENGINE_S3_BUCKET`). It uses the core's own credentials and endpoint,
unless the `AUDIT_ARCHIVE_S3_*` overrides below are set. The core keeps content
at `<tenant>/<file-uid>/<version-ts>`. The archive takes a reserved virtual
folder beside it:

```
[<AUDIT_ARCHIVE_S3_PREFIX>/]<scope id>/<AUDIT_ARCHIVE_FOLDER>/<YYYY>/<MM>/<run id>/part-<NNNNN>.ndjson.enc
[<AUDIT_ARCHIVE_S3_PREFIX>/]<scope id>/<AUDIT_ARCHIVE_FOLDER>/<YYYY>/<MM>/<run id>/manifest.json.enc

e.g. rationalboxes/_audit/2026/11/20261101T033000Z-3f9c2a1b/part-00001.ndjson.enc
     _global/_audit/2026/11/20261101T033000Z-3f9c2a1b/manifest.json.enc
```

* **Folder** `AUDIT_ARCHIVE_FOLDER` (default `_audit`) and **global scope id**
  `AUDIT_ARCHIVE_GLOBAL_SCOPE` (default `_global`) must both start with `_`.
  Tenant ids match `^[a-z][a-z0-9]{1,30}$` (admin_master_control) and core file
  uids are UUIDs, so neither can ever collide with a reserved name.
* **`YYYY/MM`** is the month of the run, which is the date-override month in a
  simulation. The run id is `<UTC wall-clock>-<8 random hex>`, so two runs never
  share a key. **Objects are write-once:** nothing in this design overwrites or
  deletes an archive object.
* **Safe beside the core:** the core never enumerates the bucket to delete
  objects. Its only listing is a one-key existence probe. It deletes only keys
  it derives from its own version rows. Verified in `s3_storage.cpp` and
  `object_store_sync.cpp`.
* **Offsite and undo:** the offsite job mirrors the whole bucket to AWS with no
  `--remove`, under a no-delete bucket policy, so archives get an offsite copy
  automatically. Bucket versioning remains the undo layer for deletes.
* **Restore:** see §9. Restores copy only the keys the databases reference, so
  the archive catalog is part of that reference set.

A local backend (`AUDIT_ARCHIVE_BACKEND=local`) exists for development. It uses
the same key layout under `AUDIT_ARCHIVE_DIR`, which **must be absolute**. A
relative directory is refused, because a relative directory is exactly the
container trap described in §1.

## 6. Object formats

Every object is a **Fernet token** (AES-128-CBC + HMAC-SHA256) over UTF-8 text.
No audit content is ever written in the clear.

**Part**: NDJSON. Line 1 is a header, then one line per row in ascending `seq`:

```json
{"header": {"format": "fileengine.audit-archive/1", "scope": "rationalboxes",
            "table": "\"tenant_rationalboxes\".audit_log", "run_id": "…", "part": 1,
            "row_count": 5000, "first_seq": 101, "last_seq": 5100,
            "first_prev_hash": "…hex…", "last_row_hash": "…hex…",
            "min_ts": "…", "max_ts": "…"}}
{"seq": 101, "event_id": "…", "ts": "…", "recorded_at": "…", "category": 1, "action": "read",
 "outcome": 0, "actor": "…", "actor_roles": "…", "target_uid": "…", "target_name": null,
 "target_type": 1, "detail": {…}, "source_iface": "rest", "source_addr": "…",
 "request_id": "…", "prev_hash": "…hex…", "row_hash": "…hex…"}
```

Rows carry **every** column. That includes `recorded_at`, and `tenant` on the
global scope, because the global chain's hash covers it. The archive is a
faithful copy of the rows, not a summary.

**Manifest**: one JSON document, written **after** every part has been
verified. It lists every part's key, row count, `seq` range, `ts` range and the
SHA-256 of its ciphertext. It also records the segment's chain boundary
(`first_prev_hash`, `last_row_hash`), the cutoff, the partitions dropped, and
whether the chain verified while it was being archived (`chain_ok`).

**Keys and rotation:** `FILEENGINE_AUDIT_ARCHIVE_KEY` is a comma-separated list
of Fernet keys. The first key encrypts; every key decrypts (`MultiFernet`).
To rotate, prepend a new key and keep the old ones. **Losing every key makes the
archive permanently unreadable.**

**The key is derived from the global at-rest key.** The deploy computes

```
archive_key = base64url( HKDF-SHA256( ikm  = AT_REST_KEY as 32 bytes,
                                      salt = "" (32 zero bytes, RFC 5869),
                                      info = "fileengine/archive-key/v1",
                                      L    = 32 ) )
```

`AT_REST_KEY` is parsed as the core parses it: 64 characters are hex, anything
else is base64, and either must give 32 bytes. Three consequences:

* **One secret to escrow.** The recovery kit's copy of `AT_REST_KEY` recovers
  every archive: `audit-archive derive-key` reproduces the key from it, and
  `audit-archive key-check` proves the two agree, printing fingerprints only.
* **The job never holds the master key.** HKDF is one-way. The retention
  container gets the derived key, which cannot decrypt file content.
* **Rotating `AT_REST_KEY` changes the archive key.** Rotation is not supported by
  the core today (`versions.key_id` is always 0). When it is, the old derived key
  must be appended to the list so older archives still decrypt.

`audit_service/keys.py` and the Ansible filter `fileengine_archive_key`
implement the same function, and both pin the same test vector.

## 7. The run, per scope

All of a scope's work happens in **one Postgres transaction**. Scopes are
independent: a failure in one is logged, the others continue, and the process
exits non-zero.

1. **Lock.** Take the writer's partition advisory lock,
   `pg_advisory_xact_lock(hashtext(<partition>))`, for every aged partition, in
   sorted order. The writer takes that lock before it creates or inserts into a
   day's partition. Holding it means no late row can land in a partition between
   being read and being dropped. Sorted order matches the writer, so the two
   cannot deadlock. Writers appending to *current* days are not blocked.
2. **Select.** Apply the chain-prefix rule (§4).
3. **Stream.** Read the candidate rows in `seq` order with a server-side
   cursor, `AUDIT_ARCHIVE_PART_ROWS` at a time (default 5000). Memory is
   bounded by one part, never by a day, a month or a tenant. While streaming,
   walk the chain: integrity is recomputed for every row, and linkage is
   checked starting from the current anchor. The result is recorded as
   `chain_ok`. A broken historical chain is **archived as it is, not refused**.
   Refusing would stop retention forever on a chain that `audit-rechain` was
   written to repair, and the archive must be a faithful copy, not a corrected
   one.
4. **Write and prove each part.** `PUT` the part, then `GET` it back and check
   that the ciphertext's SHA-256 matches, that it decrypts, and that its row
   count and last `row_hash` are right. Any failure aborts the scope's
   transaction, so nothing is dropped.
5. **Write the manifest.** Then read it back and check it the same way.
6. **Catalog.** Insert the segment and its parts into
   `public.audit_archive_segments` and `public.audit_archive_parts`.
7. **Drop** the candidate partitions, with `lock_timeout` bounded.
8. **Commit.** The catalog rows and the drops become visible together, or not
   at all.

**Failure behaviour.** A crash or error before the commit leaves Postgres
exactly as it was. The objects already uploaded are orphans. They are harmless,
never referenced, and never overwritten, because the next run uses a new run
id. They are encrypted and inert. No step ever deletes data that has not
already been written, read back and verified.

**Lock duration.** The transaction stays open while one scope's parts upload.
Only writers that try to insert into an aged day wait: a late row, which is
rare. Writers on current days proceed normally. The final `DROP` briefly needs
an exclusive lock on the parent table.

## 8. Chain verification across the boundary

* **`audit-verify` / `GET /v1/audit/verify`** start each scope's chain from its
  anchor rather than from `NULL`. They report `anchored_at_seq`. A row with
  `seq <= anchor.last_seq` still in Postgres is reported as a break, because it
  should not exist.
* **`audit-rechain`** re-links from the anchor as well. Re-linking the first
  remaining row to `NULL` would sever it from the archive.
* **The writer** reads a chain's head from Postgres. When the table is
  *empty*, it reads the anchor instead. A quiet tenant can have every row
  archived, and its next event must link to the archived tail rather than start
  a second chain at `NULL`.
* **`audit-archive verify`** walks a scope's archive from the catalog in `seq`
  order and checks, for every part:
    * the ciphertext's SHA-256 matches the catalog;
    * the part decrypts, and its header matches the catalog;
    * every row's integrity holds, and every row links to the one before it,
      including across part and segment boundaries.

  Finally it checks that the newest segment's `last_row_hash` is the anchor the
  database chain continues from. Together, `audit-archive verify` and
  `audit-verify` cover the whole chain from its first row to now. Memory is
  bounded by one part.
* **`audit-archive export --tenant T [--from D] [--to D]`** streams archived
  rows as NDJSON for a `ts` range. It reads only the parts whose `ts` range
  overlaps the request.

The query API (§9 of the core doc) still reads Postgres only. Records older than
the window are reached through `audit-archive export`. Transparent read-back in
the API is **deferred**.

## 9. Catalog, backups and restore

```sql
public.audit_archive_segments(
    segment_id BIGSERIAL PRIMARY KEY, scope TEXT, scope_table TEXT, run_id TEXT,
    manifest_key TEXT UNIQUE, cutoff DATE, row_count BIGINT,
    first_seq BIGINT, last_seq BIGINT, first_prev_hash BYTEA, last_row_hash BYTEA,
    min_ts TIMESTAMPTZ, max_ts TIMESTAMPTZ, partitions TEXT[], chain_ok BOOLEAN,
    archived_at TIMESTAMPTZ DEFAULT now())
public.audit_archive_parts(
    segment_id BIGINT REFERENCES audit_archive_segments, part_no INT, object_key TEXT UNIQUE,
    row_count INT, first_seq BIGINT, last_seq BIGINT, min_ts TIMESTAMPTZ, max_ts TIMESTAMPTZ,
    sha256 BYTEA, PRIMARY KEY (segment_id, part_no))
```

* The catalog lives in `public`, so it outlives a tenant schema that is dropped.
  A decommissioned tenant's audit history stays recoverable.
* **The anchor** for a scope is its segment with the greatest `last_seq`.
* **The catalog is the archive's index, not a convenience.** The backup
  script's restore manifest (`--referenced-keys`) and its offsite sync gate
  include every catalog key alongside the `versions` keys. Without that, a
  restore would bring back the databases, which reference the archive, and
  silently leave the archive behind.
* Losing the catalog does not lose the archive. Every object is
  self-describing, and the manifests can be listed under `<scope>/_audit/`.
* The tables are created by the archiver with `CREATE TABLE IF NOT EXISTS`
  under an advisory lock. Idempotent DDL is not concurrency-safe DDL on its
  own.

## 10. Schedule and deployment

* **Timer:** `fileengine-audit-retention.timer`, `OnCalendar=*-*-01 03:30:00`
  (UTC), `Persistent=true`. A host that is down on the 1st runs the job on
  boot. `audit_retention_timer_enabled: false` installs the unit and timer but
  leaves the timer stopped, for a supervised first run:
  `systemctl start fileengine-audit-retention.service` while following
  `journalctl -fu fileengine-audit-retention`. Then set it back to `true` and
  redeploy.
* **Unit:** a one-shot `podman run --rm` of the audit image running
  `audit-retention --all`. Secrets are passed via `--env-file
  /etc/fileengine/audit-retention.env` (root, `0600`), never as inline `-e`
  flags in the world-readable unit file.
* **Required configuration:** the deploy asserts that the archive key (or the
  at-rest key it is derived from) and the S3 settings are present whenever
  retention is enabled. A deploy that cannot
  archive fails loudly instead of installing a job that fails quietly.
* **Database role:** the job needs `SELECT` on the audit tables, `DROP` on
  their partitions, `SELECT`/`DELETE` on the accountability tables, `SELECT` on
  `accountability_cursor`, and `CREATE`/`INSERT` on the catalog in `public`. That is
  the migration role from §7 of the core doc, not the append-only writer role.

## 11. Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `FILEENGINE_AUDIT_RETENTION_MONTHS` | `2` | Complete calendar months kept in Postgres (≥ 1). |
| `FILEENGINE_AUDIT_ARCHIVE_KEY` | — (required) | Comma-separated Fernet keys; the first encrypts. Deployments derive it from `AT_REST_KEY` (§6). |
| `AUDIT_ACCOUNTABILITY_RETENTION` | `true` | Also retain and archive the core's accountability record (§14). |
| `AUDIT_ARCHIVE_ACCOUNTABILITY_FOLDER` | `_accountability` | Its per-scope virtual folder; must start with `_` and differ from `AUDIT_ARCHIVE_FOLDER`. |
| `AUDIT_ARCHIVE_BACKEND` | `s3` | `s3`, `local` (dev; absolute dir), or `none` (retention disabled). |
| `AUDIT_ARCHIVE_S3_BUCKET` | `FILEENGINE_S3_BUCKET` | Target bucket: the main store. |
| `AUDIT_ARCHIVE_S3_ENDPOINT` | `FILEENGINE_S3_ENDPOINT` | S3-compatible endpoint (DO Spaces, MinIO). |
| `AUDIT_ARCHIVE_S3_REGION` | `FILEENGINE_S3_REGION` | Region. |
| `AUDIT_ARCHIVE_S3_ACCESS_KEY` / `_SECRET_KEY` | `FILEENGINE_S3_ACCESS_KEY` / `_SECRET_KEY` | Credentials. |
| `AUDIT_ARCHIVE_S3_PATH_STYLE` | `FILEENGINE_S3_PATH_STYLE` | Path-style addressing (MinIO). |
| `AUDIT_ARCHIVE_S3_PREFIX` | empty | Optional outer prefix, for a dedicated bucket. |
| `AUDIT_ARCHIVE_FOLDER` | `_audit` | Per-tenant virtual folder; must start with `_`. |
| `AUDIT_ARCHIVE_GLOBAL_SCOPE` | `_global` | Scope id for the global chain; must start with `_`. |
| `AUDIT_ARCHIVE_DIR` | — | Local backend root; must be absolute. |
| `AUDIT_ARCHIVE_PART_ROWS` | `5000` | Rows per part object (1–100000). |
| `AUDIT_RETENTION_STATEMENT_TIMEOUT_MS` | `600000` | Statement timeout for the run's session. |
| `AUDIT_RETENTION_LOCK_TIMEOUT_MS` | `30000` | Lock wait bound for the final `DROP`. |
| `AUDIT_RETENTION_TODAY` | — | Date override (§12); honoured only with the next variable. |
| `AUDIT_ALLOW_DATE_OVERRIDE` | `false` | Must be `true` for any date override to take effect. |

## 12. Simulating the lifecycle (date overrides)

The data lifecycle spans months, so the test harness drives it with a clock
override instead of waiting:

* `audit-retention --today YYYY-MM-DD` (or `AUDIT_RETENTION_TODAY`) sets the
  date the cutoff is computed from. `retention.run(..., today=)` is the library
  form.
* **An override is refused unless `AUDIT_ALLOW_DATE_OVERRIDE=true`.** A future
  date moves the cutoff forward and archives live data. That is exactly what a
  simulation wants and exactly what production must never do by accident.
* Event time is already controllable: the writer partitions on the envelope's
  `ts`, so seeding an event "in" any past month creates that month's partition.

The live suite (`src/tests/test_retention_lifecycle_live.py`) uses this to
replay a multi-month history against a real Postgres and a real S3 (MinIO),
with a fresh run on each simulated 1st. After every step it checks: the
partitions kept and dropped, the catalog, the database chain from its anchor,
the archive chain end to end, an export round trip, a late-arriving row being
held and then archived without overwriting anything, an injected S3 failure
dropping nothing, and a tampered object being detected.

It also covers:

* a quiet tenant archived to empty that then continues one chain;
* `audit-rechain` repairing a retained chain without severing it from its
  archive;
* the global chain, whose `tenant` column is hashed and archived;
* `--dry-run` changing nothing;
* one scope's failure not stopping the others.

The guard on the override is tested at the process boundary: the CLI exits 2
before it connects to anything.

```sh
FILEENGINE_PG_HOST=… FILEENGINE_PG_PORT=… \
AUDIT_TEST_S3_ENDPOINT=http://127.0.0.1:9000 AUDIT_TEST_S3_BUCKET=… \
AUDIT_TEST_S3_ACCESS_KEY=… AUDIT_TEST_S3_SECRET_KEY=… \
AUDIT_TEST_DISPOSABLE_DB=1 \
python3 -m pytest src/tests/test_retention_unit.py src/tests/test_retention_lifecycle_live.py
```

Without `AUDIT_TEST_S3_*`, the S3 variants skip and the local backend still
runs. The global-chain test runs only with `AUDIT_TEST_DISPOSABLE_DB=1`,
because it truncates the shared `public.audit_log_global`.

## 13. Out of scope (this version)

* Transparent read-back of archived records in the query API.
* External notarisation of anchors.
* Deleting archives. Archives are kept indefinitely. A retention period for the
  archive itself is a policy decision not yet made, and the offsite bucket
  could not honour one anyway.

## 14. The core's accountability record

The core writes `"<tenant>".accountability_record` and
`public.accountability_record_global` in the same transaction as each operation
it guarantees (ACL and role changes, culls, erasure, tenant lifecycle, service
credentials). Each is a hash chain: `seq` is gap-free and `ts` strictly increases,
both claimed under one per-chain lock, and the hash covers `seq`. audit_service
pulls each chain into the audit log by cursor (`accountability_cursor`); the
Redis `accountability.committed` hint only says "read now". **The tables are the
source of truth**, and they used to be "never culled". They are now retained on
the audit log's window.

**What is eligible.** In each chain, the rows with `ts` before the cutoff (§3).
Because `ts` follows `seq`, that is always a `seq` prefix, so the table needs no
partitions. The prefix is capped at the chain's `accountability_cursor.last_seq`:
only rows the puller has already copied into the audit log may go. An absent
cursor, or one HALTED on an integrity break, holds the whole chain back. Removing
rows the puller had not read would show up as a seq gap, which is an integrity
alarm, and as a record that never reached the audit log.

**The run.** It runs per chain, in one transaction, after the audit log's scopes
in the same `audit-retention --all`:

1. take an advisory lock on the chain, so two runs cannot archive it at once;
2. stream the eligible rows in `seq` order from the catalog anchor, checking every
   §4.3.2 property: contiguity, increasing `ts`, the `prev_hash` link, and the
   hash recomputed from the row exactly as the core computes it;
3. on any break, **fail the scope and remove nothing.** Unlike the audit log
   (§7), a break here is not archived faithfully. The core's chain is
   lock-ordered and verified on every pull, so a break is tampering until shown
   otherwise, and deleting the evidence is the wrong response;
4. write parts and a manifest, each read back (§6), under
   `<scope>/_accountability/YYYY/MM/<run_id>/`;
5. record the segment in the catalog (`scope_table` =
   `"tenant_<id>".accountability_record` or `accountability_record_global`,
   `partitions` empty); this is the chain's new anchor;
6. `DELETE` the archived prefix, check the row count, and commit.

Rows are archived with the column names, plus `ts_micros` (the integer the core
hashed), `row_hash` for `hash`, `detail` as a JSON object, and `tenant` on the
global chain. Format id: `fileengine.accountability-archive/1`.

**The puller after retention.** A puller whose cursor is reset ("rebuild from
zero") cannot start from genesis any more, because genesis is archived. When its
cursor is empty it resumes from the catalog anchor (`last_seq`, `last_row_hash`,
`max_ts`). The core's append path is not affected: it chains from
`accountability_chain_head`, never from the table.

**Reading back.** `audit-archive verify --accountability --tenant T` (or
`--global`) walks the archive and then the surviving table from the anchor, with
the same checks. `audit-archive export --accountability` streams archived rows.
`audit-archive verify --all` covers both families.

**Recording the run.** Each run is recorded in the catalog (`run_id`,
`archived_at`, seq range, row count, last hash) and by the job's own exit
status and log. The rows it removed were already copied into the audit log,
whose own archive keeps them too.

**Tenant deletion** still drops the tenant's table with its schema. Its archive
stays in the bucket, and its catalog rows stay in `public`.
