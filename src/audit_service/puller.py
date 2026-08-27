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

"""Drain the core's accountability records into the audit chain (§4.3).

Pull, not push. The Redis stream is a fine transport and an unacceptable system
of record — it is trimmed, sampled and fail-open — so the guarantee path is a
cursor read over the core's transactional outbox:

    operation ──┬─▶ commit (state + accountability_record, one transaction)
                ├─▶ we poll  ts > recorded_until          ← the guarantee
                └─▶ Redis hint                            ← latency only

Three properties fall out of that, and they are the reason this module exists
rather than the consumer simply trusting the stream:

* **Node loss stops mattering.** The record is in PostgreSQL, replicated and
  backed up, not in a local WAL file that dies with its host.
* **This service can be rebuilt from zero** by resetting its cursor and replaying
  core history — impossible when the record's only home was a stream that trims.
* **Backlog is visible and bounded by disk**, not by an outbox capacity that
  drops oldest under pressure.

The cursor is a **timestamp**, not a sequence number, and that is load-bearing.
The precedence question (§4.3.3) is "are there core records older than this
incoming subsystem event?" — a comparison against the event's own time. A seq
cursor answers "have I read everything the core wrote", which is a weaker and
differently-shaped question that cannot be compared against an event from a
subsystem that has no seq. Time is the only axis the sources share.
"""
from __future__ import annotations

import logging

from . import codes
from .accountability import (GLOBAL_CHAIN_KEY, IntegrityBreak, StaleRead,
                             datetime_to_micros, verify_batch)
from .envelope import AuditRow
from .hashing import canonical_json
from .writer import write_batch

log = logging.getLogger("audit_service.puller")

# How the core's accountability taxonomy lands in the audit log's own.
#
# They are deliberately different vocabularies: the accountability categories
# describe what KIND of guarantee a record carries, the audit categories describe
# where an event sits in the platform-wide taxonomy. Mapping rather than merging
# keeps both readable, and keeps the audit log's existing queries working.
_CATEGORY = {
    "authorization": "permission",   # who could do what
    "identity": "user",              # who is who
    "destruction": "admin",          # culls, tenant deletion, (later) erasure
    "lifecycle": "admin",            # tenant create
}


def _to_audit_row(rec, tenant: str | None) -> AuditRow:
    """Map one core record onto an audit row.

    Note what is NOT carried across: there is no ``target_name``. The chain
    records identifiers and structure, never payload — a viewer joins the uid to
    the current name at read time, so after an erasure the join finds nothing and
    the log automatically stops disclosing it (§5.4.7).
    """
    target_type = codes.TARGET_TYPE.get(rec.target_type)
    detail = canonical_json({
        # The core's own detail, verbatim as a nested object, plus the two fields
        # that make a pulled record traceable back to its source chain. Keeping
        # seq and principal here means an auditor can go from an audit row to the
        # exact core record it came from and re-verify it independently.
        "accountability_seq": rec.seq,
        "principal": rec.principal or None,
        "detail": __import__("json").loads(rec.detail or "{}"),
    })
    return AuditRow(
        event_id=rec.event_id,
        ts=rec.ts,
        category=codes.CATEGORY[_CATEGORY.get(rec.category, "admin")],
        action=rec.action[:32],
        # Only committed operations are ever recorded, so the outcome is not in
        # question. A denied attempt never reaches the chain — it is recorded on
        # the best-effort permission-audit path, which is the right place for it.
        outcome=codes.OUTCOME["ok"],
        actor=rec.actor[:255],
        actor_roles=(",".join(rec.actor_roles) or None),
        target_uid=(rec.target_uid or None),
        target_name=None,
        target_type=target_type,
        detail=detail,
        source_iface=(rec.source_iface or None),
        source_addr=(rec.source_addr or None),
        request_id=None,
        scope=("global" if tenant is None else "tenant"),
        tenant=(rec.global_tenant or None) if tenant is None else tenant,
    )


class AccountabilityPuller:
    """Drains one tenant's chain at a time, per-tenant state and all.

    **Each tenant has an independent history** (§4.3.5). The chain, the seq, the
    ts monotonicity, the cursor and the drain-before-process rule are all per
    tenant, because tenants are isolated by design down to separate schemas and
    there is no question that needs a cross-tenant order. That makes per-tenant
    polling the correct shape rather than an inefficiency to engineer around: a
    busy tenant never gates a quiet one, and the work per event is bounded by
    that tenant's own backlog.
    """

    def __init__(self, config, client, cursors):
        self.config = config
        self.client = client
        self.cursors = cursors
        # Tenants whose cursor must not advance until an operator acknowledges.
        # Held in memory deliberately: an integrity alarm should be re-evaluated
        # on restart against fresh state rather than persisted as a permanent
        # verdict.
        self.halted: dict = {}
        self.drained = 0

    # -- one tenant ---------------------------------------------------------

    def drain(self, conn, tenant: str | None, heads: dict,
              asserted_seq: int | None = None) -> int:
        """Drain a tenant's chain to current on ``conn``. Does NOT commit.

        ``tenant`` is None for the global lifecycle chain. Returns the number of
        records appended. The caller commits and only then advances the cursor,
        which makes redelivery-on-crash at-least-once; ``(tenant, seq)`` is the
        idempotency key and the audit table's ``UNIQUE (event_id, ts)`` absorbs
        the duplicate.
        """
        key = tenant if tenant is not None else GLOBAL_CHAIN_KEY
        if key in self.halted:
            # Still alarming. Draining past an unacknowledged integrity break
            # would be exactly the "skip the gap to keep going" behaviour that
            # turns a detectable failure into silent data loss.
            return 0

        state = self.cursors.get(conn, key)
        appended = 0
        pages = 0
        while True:
            records, has_more, head_seq = self.client.fetch(
                key, state.recorded_until_micros, self.config.pull_page_size)
            if not records and not asserted_seq:
                break
            try:
                verify_batch(key, records,
                             last_seq=state.last_seq or None,
                             last_hash=state.last_hash,
                             last_ts_micros=state.recorded_until_micros or None,
                             # Only assert on the first page: a hint names a seq
                             # that may legitimately be several pages away.
                             asserted_seq=(asserted_seq if not has_more else None))
            except IntegrityBreak as e:
                # A security event in its own right. Stop advancing this tenant's
                # cursor, alarm, and require operator acknowledgement.
                self.halted[key] = str(e)
                log.error("INTEGRITY ALARM — %s", e)
                raise
            except StaleRead as e:
                # Not tampering: we are reading state that has not caught up.
                # Retry later; do not advance.
                log.warning("stale accountability read: %s", e)
                raise

            if records:
                write_batch(conn, [_to_audit_row(r, tenant) for r in records], heads)
                last = records[-1]
                state.advance(last.seq, last.ts_micros, last.hash)
                appended += len(records)
                self.drained += len(records)
                # Tenant deletion has to reach this service's own store (§7.3):
                # without it we would poll a vanished schema forever and silently
                # retain history the platform believes it destroyed.
                for rec in records:
                    if rec.action == "tenant.delete" and rec.global_tenant:
                        self._forget_tenant(conn, rec.global_tenant)

            asserted_seq = None      # satisfied by the first page
            pages += 1
            if not has_more or pages >= self.config.pull_max_pages:
                break

        if appended:
            self.cursors.stage(conn, key, state)
        return appended

    # -- every tenant -------------------------------------------------------

    def drain_all(self, conn, heads: dict) -> int:
        """Drain the global chain and every registered tenant.

        The global chain goes FIRST: it carries tenant deletions, and acting on
        one before draining a tenant we are about to forget avoids re-creating
        that tenant's cursor moments after dropping it.
        """
        total = 0
        for tenant in [None] + self.list_tenants(conn):
            try:
                total += self.drain(conn, tenant, heads)
            except (IntegrityBreak, StaleRead):
                # Per-tenant isolation applies to failures too: one tenant's
                # alarm must not stop every other tenant's history being
                # recorded.
                continue
            except Exception:
                log.exception("accountability drain failed for tenant %r", tenant)
                continue
        return total

    def list_tenants(self, conn) -> list:
        with conn.cursor() as cur:
            cur.execute("SELECT tenant_id FROM tenants ORDER BY tenant_id")
            return [r[0] for r in cur.fetchall()]

    # -- tenant destruction (§7.3) -----------------------------------------

    def _forget_tenant(self, conn, tenant: str) -> None:
        """Stop polling a destroyed tenant, drop its cursor, purge its records.

        The tenant's contents are genuinely gone — its schema, and its own
        accountability history with it. What survives is the global lifecycle
        entry saying it existed and who removed it, which lives where the deleter
        cannot reach. Retaining anything else here would mean holding history the
        platform has told the world it destroyed.
        """
        self.halted.pop(tenant, None)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM accountability_cursor WHERE tenant = %s", (tenant,))
            # Keep the lifecycle entries; purge everything else we retained for
            # this tenant on the global table. (Its own per-tenant audit_log went
            # with the schema.)
            cur.execute(
                "DELETE FROM audit_log_global WHERE tenant = %s "
                "AND action NOT IN ('tenant.create', 'tenant.delete')", (tenant,))
        log.info("tenant %r destroyed — cursor dropped and retained records purged, "
                 "keeping the lifecycle entry", tenant)
