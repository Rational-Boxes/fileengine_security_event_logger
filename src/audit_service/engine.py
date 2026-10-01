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

"""The security rules engine (usage_logging §11): feed audit events → incidents →
graduated responses.

Runs as a consumer of the same aggregating audit stream (a separate group from
the writer), keeps small per-rule sliding-window counters, evaluates the
deterministic rule catalog, and dispatches responses. Side effects go through
injectable interfaces (IncidentStore / AdminNotifier / Enforcer) so the engine is
pure and unit-testable; real implementations (Postgres incidents, SMTP admin
email, ldap_manager auto-disable) are wired in at deployment.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from .rules import SERIOUS, Rule, default_rules
from .windows import DistinctWindows, SlidingWindows

log = logging.getLogger("audit_service.engine")


@dataclass
class Incident:
    rule_id: str
    tenant: str | None
    group_by: str
    group_key: str
    severity: str
    response: str
    count: int
    window_s: int
    actor: str | None
    last_ts: str
    dry_run: bool
    action_taken: str          # flagged | alerted | disabled | would_disable | disable_failed
    description: str
    # §3 / §3.5. `scope` says which windows produced the count, `audience` who
    # may see it. A global incident's count spans tenants, so showing it to one
    # tenant would disclose that the others exist — the Rule refuses that
    # combination, and carrying both here means a consumer never has to look the
    # rule up to route correctly.
    scope: str = "tenant"
    audience: str = "tenant"
    # For a fan-out incident: the distinct values seen. "8 tenants" without
    # naming them leaves the administrator to go and find out which.
    distinct_values: tuple = ()


class IncidentStore:            # default: log only
    def record(self, incident: Incident) -> None:
        log.info("incident recorded: %s", incident)


class AdminNotifier:
    """The default when no notifier is wired. IT SENDS NOTHING, AND SAYS SO.

    This used to log "MANDATORY admin email for serious incident", which reads
    like a notification and was not one — a deployment could run for a year
    believing serious incidents reached somebody. The behaviour is unchanged
    (there is nothing here to send with); the honesty is not.

    The real one is :class:`audit_service.notifier.EmailAdminNotifier`, and
    `audit-rules` wires it from configuration.
    """

    def alert(self, incident: Incident) -> None:
        log.info("alert: %s", incident.rule_id)

    def notify_admins_mandatory(self, incident: Incident) -> None:
        log.error("NO NOTIFIER WIRED — serious incident %s was recorded and NOT "
                  "sent to any administrator", incident.rule_id)


class Enforcer:                 # default: no-op
    def disable(self, tenant: str | None, actor: str | None) -> None:
        log.warning("auto-disable requested (no enforcer wired): %s/%s", tenant, actor)


def _ev_ts(ev: dict) -> float:
    ts = ev.get("ts")
    if isinstance(ts, bool):
        return 0.0
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
    return 0.0


class RulesEngine:
    def __init__(self, rules: list[Rule] | None = None, *, rules_provider=None,
                 store=None, notifier=None, enforcer=None):
        # rules_provider(tenant) -> list[Rule] gives per-tenant rule sets; a plain
        # `rules` list (or the defaults) applies to every tenant.
        if rules_provider is not None:
            self._provider = rules_provider
        elif rules is not None:
            self._provider = lambda _t: rules
        else:
            _defaults = default_rules()
            self._provider = lambda _t: _defaults
        self.store = store or IncidentStore()
        self.notifier = notifier or AdminNotifier()
        self.enforcer = enforcer or Enforcer()
        self._windows = SlidingWindows()       # threshold-rule counters
        self._primaries = SlidingWindows()     # sequence-rule primary counters
        self._fanout = DistinctWindows()       # distinct-value counters (§3.6)
        self._cooldowns: dict = {}             # (tenant, rule_id, group_key) -> until_ts

    def feed(self, ev: dict) -> list[Incident]:
        """Evaluate one audit envelope (dict of strings) against the tenant's rules."""
        ts = _ev_ts(ev)
        tenant = ev.get("tenant")
        out = []
        for rule in self._provider(tenant):
            if not rule.enabled:
                continue
            inc = self._eval(rule, ev, ts, tenant)
            if inc:
                out.append(inc)
        return out

    def _window_key(self, rule: Rule, key: str, tenant):
        """The window key, which is where scope actually lives.

        A tenant-scoped rule counts within one tenant, as every rule did. A
        GLOBAL rule drops the tenant, so one source accumulates across the whole
        platform — the case that is invisible from inside any single tenant: ten
        tenants hit four times each trips no per-tenant threshold of five, and
        with no incident anywhere there is nothing for a cross-tenant view to
        aggregate. Aggregating is not detecting (§3.5).
        """
        if rule.scope == "global":
            return (rule.id, key)
        return (tenant, rule.id, key)

    def _eval(self, rule: Rule, ev: dict, ts: float, tenant) -> Incident | None:
        key = rule.key_for(ev)
        if key is None:
            return None
        wkey = self._window_key(rule, key, tenant)

        if rule.is_fanout:
            # §3.6: the threshold counts DISTINCT values, not events. Low volume
            # is not a defence — one attempt per tenant still fans out.
            if not rule.matches_primary(ev):
                return None
            value = rule.distinct_value(ev)
            if value is None:
                return None
            n = self._fanout.add_and_count(wkey, value, ts, rule.window_s)
            if n >= rule.threshold:
                return self._fire(rule, ev, key, ts, n, tenant,
                                  distinct_values=tuple(self._fanout.values(wkey, ts, rule.window_s)))
            return None

        if rule.is_sequence:
            if rule.matches_primary(ev):
                self._primaries.add_and_count(wkey, ts, rule.window_s)
                return None
            if rule.matches_seal(ev) and self._primaries.count(wkey, ts, rule.window_s) >= rule.threshold:
                return self._fire(rule, ev, key, ts, self._primaries.count(wkey, ts, rule.window_s), tenant)
            return None

        if not rule.matches_primary(ev):
            return None
        n = self._windows.add_and_count(wkey, ts, rule.window_s)
        if n >= rule.threshold:
            return self._fire(rule, ev, key, ts, n, tenant)
        return None

    def _fire(self, rule: Rule, ev: dict, key: str, ts: float, count: int, tenant,
              *, distinct_values: tuple = ()) -> Incident | None:
        wkey = self._window_key(rule, key, tenant)
        until = self._cooldowns.get(wkey)
        if until is not None and ts < until:
            return None  # still cooling down — one incident per attack, not a storm
        self._cooldowns[wkey] = ts + rule.cooldown_s
        self._windows.reset(wkey)
        self._primaries.reset(wkey)
        self._fanout.reset(wkey)

        actor = ev.get("actor")
        if rule.response == "auto_disable":
            if rule.dry_run:
                action_taken = "would_disable"
            else:
                try:
                    self.enforcer.disable(tenant, actor)
                    action_taken = "disabled"
                except Exception:
                    log.exception("auto-disable failed for %s/%s", tenant, actor)
                    action_taken = "disable_failed"
        elif rule.response == "alert":
            action_taken = "alerted"
        else:
            action_taken = "flagged"

        inc = Incident(rule_id=rule.id,
                       # A global incident belongs to no single tenant, and
                       # naming one would be a lie the consumer would route on.
                       tenant=None if rule.scope == "global" else tenant,
                       group_by=rule.group_by, group_key=key,
                       severity=rule.severity, response=rule.response, count=count,
                       window_s=rule.window_s, actor=actor, last_ts=str(ev.get("ts")),
                       dry_run=rule.dry_run, action_taken=action_taken,
                       description=rule.description,
                       scope=rule.scope, audience=rule.audience,
                       distinct_values=distinct_values)
        self.store.record(inc)
        if rule.response == "alert":
            try:
                self.notifier.alert(inc)
            except Exception:
                log.exception("alert dispatch failed for %s", rule.id)
        # Serious/critical ALWAYS emails admins, regardless of response mode (§11).
        if rule.severity in SERIOUS:
            try:
                self.notifier.notify_admins_mandatory(inc)
            except Exception:
                log.exception("mandatory admin email failed for %s", rule.id)
        log.warning("SECURITY %s: %s=%s count=%d severity=%s -> %s",
                    rule.id, rule.group_by, key, count, rule.severity, action_taken)
        return inc


def main() -> None:  # pragma: no cover
    """`audit-rules` — ride the audit stream (separate group) and evaluate rules.

    Wires the Postgres incident store AND the real admin notifier. The docstring
    here used to say a deployment "wires in ... SMTP admin email", and no
    deployment did: main() built a real store and left the notifier at its
    default, which logged "MANDATORY admin email for serious incident" and sent
    nothing. A serious incident was recorded and nobody was told.

    The notifier is built from configuration and is NEVER None. Unconfigured, it
    logs at ERROR for every mandatory incident it could not deliver — which is
    the state the stub left deployments in, except now it says so.
    """
    import logging as _l
    import time

    from . import db
    from .config import Config, load_dotenv
    from .consumer import RedisAuditSource
    from .security import PgIncidentStore, RulesStore

    _l.basicConfig(level=_l.INFO)
    load_dotenv()
    config = Config()
    config.audit_group = config.rules_group  # a distinct group so we see every event

    # Per-tenant rules from the DB store (seeded with the default pack), cached
    # briefly so we don't hit the DB on every event; incidents persisted to Postgres.
    rules_store = RulesStore(lambda: db.connect(config))
    rules_store.seed_defaults()  # ensure the global default pack exists
    _cache: dict = {}
    def provider(tenant):
        now = time.time()
        hit = _cache.get(tenant)
        if hit and now - hit[0] < 30:
            return hit[1]
        rules = rules_store.rules_for(tenant)
        _cache[tenant] = (now, rules)
        return rules

    from .notifier import from_config as _notifier_from_config

    engine = RulesEngine(rules_provider=provider,
                         store=PgIncidentStore(lambda: db.connect(config)),
                         notifier=_notifier_from_config(config))
    source = RedisAuditSource(config)
    source.ensure_group()
    log.info("rules engine — stream=%s group=%s (rules from DB store, incidents -> Postgres)",
             config.audit_stream, config.rules_group)
    while True:
        try:
            for msg_id, env in source.read(config.read_count, config.read_block_ms):
                try:
                    engine.feed(env)
                except Exception:
                    log.exception("rules evaluation failed for %s", msg_id)
                source.ack([msg_id])
        except Exception:
            # A transient broker error (e.g. Redis closing an idle blocking read)
            # must not kill the engine — redis-py reconnects on the next command.
            log.exception("rules engine read loop error; backing off")
            time.sleep(2)


if __name__ == "__main__":
    main()
