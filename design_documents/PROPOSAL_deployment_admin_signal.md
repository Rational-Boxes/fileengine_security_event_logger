# Proposal: raising a signal to the deployment administrator

**Status:** **Captured for the future — not scheduled.** Nothing implemented.
Written down now because §2 is a live defect rather than a design gap, and it
should not have to be rediscovered.
**Scope:** `audit_service` (the audience field, the acknowledgement state, a real
notifier), `scripts/Ansible/roles/audit` (wire it), the planned deployment-admin
interface (where the queue is eventually read)

---

## 1. The requirement

Audit is scoped to **tenant** administration. Some events are important enough
that **full system administration** has to be told — the tier above any tenant,
the people who operate the deployment itself.

The motivating case is redaction. A redaction must be raised to the deployment
administrator, who confirms it with the end customer before any purge proceeds;
it is always a human-validated, human-confirmed procedure
(`scripts/Ansible/docs/PROPOSAL_offsite_redaction.md`). But it is not the only
case — serious security signals belong in the same channel.

---

## 2. What exists, and the part that does not work

Most of the machinery is already here, which makes this a smaller piece of work
than it looks. One link in it is a stub that reads like a feature.

`RulesEngine._fire` calls, for every incident whose severity is in
`SERIOUS = ("serious", "critical")`, **regardless of the rule's response mode**:

```python
# Serious/critical ALWAYS emails admins, regardless of response mode (§11).
if rule.severity in SERIOUS:
    self.notifier.notify_admins_mandatory(inc)
```

The seam is exactly right. The default implementation is:

```python
class AdminNotifier:            # default: log only
    def notify_admins_mandatory(self, incident: Incident) -> None:
        log.warning("MANDATORY admin email for serious incident: %s", incident.rule_id)
```

and `main()` — the `audit-rules` entrypoint the deployment actually runs
(`roles/audit/tasks/main.yml`) — constructs the engine with a real **store** and
**no notifier**:

```python
engine = RulesEngine(rules_provider=provider, store=PgIncidentStore(...))
```

**So every serious and critical security incident in production writes a log
line announcing that a mandatory admin email was sent, and no email is sent.**
`main()`'s own docstring says "a deployment wires in the real Postgres incident
store, SMTP admin email, and the ldap_manager auto-disable enforcer" — the store
is wired, the notifier is not.

This is worse than a missing feature, because the log line is affirmative. Anyone
grepping for evidence that notification happened finds the words *MANDATORY admin
email* next to the incident. It is the same shape as the `delete_file` refusal
recorded in `PROPOSAL_accountability_record.md` §5.4 — a stub that reported
success — and it should be fixed on those grounds alone, independently of
everything below.

**Fixing it is not the whole requirement**, and §4 is why.

---

## 3. Audience: the missing dimension

An `Incident` carries `tenant`, `severity`, `actor` and the rule that fired. It
does not carry *who should hear about it*, and severity is not a good proxy:
"serious" is a statement about the event, not about which tier of administration
owns the response. A tenant's own brute-force lockout is serious and is the
tenant admin's business; an audit sink that has stopped draining is serious and
is nobody's business but the deployment's.

So: an explicit `audience` on `Rule`, values `tenant | deployment | both`,
defaulting to `tenant`.

On the **rule**, not on the event, and not on the emitting service. The judgement
is editorial and it belongs in one reviewable place. Putting it on the emitter
means every service decides independently what the deployment tier needs to know,
and they will decide inconsistently and drift — which is the argument against
adding a `severity` or `audience` field to `AuditEntry` in the core as well.
Rules already live in a per-tenant store with a seeded default pack
(`RulesStore`), so this is data, and adding a new deployment-level concern
becomes a rule change rather than a code change in five services.

Candidates for `audience = deployment` in the default pack: redaction raised;
audit drain unhealthy or the sink unreachable; accountability chain verification
failing; tenant provisioned or decommissioned; service credential issued or
rotated; a link lockout adjudicated across tenants; erasure that could not reach
a durable copy.

---

## 3.5 Aggregating is not detecting

An `audience` on rules gets deployment-tier incidents *routed*. It does not make
the deployment tier able to see something no tenant can, and that is the more
valuable half.

Windows are keyed per tenant, and the engine says so:

```python
wkey = (tenant, rule.id, key)          # windows are per-tenant
```

So a rule grouped by `source_addr` with a threshold of 5 in 300s counts failures
**within one tenant**. One source hitting ten tenants four times each — forty
attempts in five minutes — trips nothing. Each tenant is below threshold, so no
incident exists in any tenant, so there is nothing for a cross-tenant view to
aggregate.

That is exactly the class of attack that is invisible to every tenant
administrator individually and obvious from above. Leaving breach detection to
tenant administrators does not merely distribute the work; for this shape it
loses the signal entirely.

**So `Rule` needs a scope as well as an audience:**

```python
scope: str = "tenant"        # tenant | global
```

A `global` rule evaluates with the tenant dropped from the window key —
`wkey = (rule.id, key)` — so `source_addr` and `actor` accumulate across the
whole platform. Its incidents are inherently deployment-audience; a tenant has
no standing to see a count that includes other tenants' events, and the incident
itself would disclose that they exist.

Candidates for the default pack: authentication failures by `source_addr`,
token-verification failures, permission denials by `source_addr`, and any rule
whose existing per-tenant version has a threshold low enough that a patient
attacker can stay under it in each tenant while exceeding it overall.

### 3.6 Fan-out is the better detector

A global rule catches *volume* spread across tenants. The stronger signal is
**how many tenants a single source touched at all**, independent of volume.

A legitimate principal belongs to one tenant, or to a small and stable set. A
source address that fails authentication three times in each of eight tenants is
not someone who forgot a password — and it trips neither a per-tenant threshold
(three) nor necessarily a global one (twenty-four, patiently spread). The
*fan-out itself* is the anomaly, and unlike a volume threshold it cannot be
evaded by patience: an attacker probing the platform is, by definition,
touching many tenants.

So a third rule shape, where the threshold counts **distinct tenants** rather
than events:

```python
distinct: str | None = None     # count distinct values of this field instead of events
                                # e.g. distinct="tenant", group_by="source_addr", threshold=3
```

Properties that make this worth having as its own shape rather than a tuning of
the others:

- **Low volume is not a defence.** One attempt per tenant still fans out.
- **Its false-positive set is small and enumerable** — a corporate NAT egress, a
  customer operating several tenants from one office, an uptime probe, an
  internal service if it ever appears as a source. That is an allowlist, not a
  threshold, and it is a much better thing to maintain than a number.
- **It is inherently deployment-audience.** A tenant cannot be shown "this
  source also hit seven others" without being told the others exist.

### 3.7 It rests on `source_addr`, which rests on a configuration

Everything in §3.6 — and any global rule grouped by `source_addr` — is only as
trustworthy as that field, and that field is derived from `X-Forwarded-For`.

`http_bridge` resolves it through `resolveClientIp(peer, xff, trusted_proxies)`,
which is trusted-proxy aware, and whose own comment records that with
`FILEENGINE_TRUSTED_PROXIES` unset it keeps the dev behaviour of taking the
first XFF hop — so that unset in production means **the client chooses the value
the platform records as its address**.

It is configured in the deployment (`fileengine_trusted_proxies`, templated by
every door that records a client IP), so this is not an open hole. But it has a
recorded drift mode that is directly relevant: a targeted `deploy.sh --service X`
run passes `--tags`, and before the `always` tag was added the discovery task was
filtered out while the play still reported success — measured as
`--service ldap_manager` shipping `FILEENGINE_TRUSTED_PROXIES=127.0.0.1/32`
minutes after a full deploy had set it correctly, silently reverting that door to
recording the container gateway as the client.

Two consequences:

1. **Verify the value is right on every door before shipping a fan-out rule**,
   not once. A door that records the gateway makes every request look like one
   source; a door that trusts XFF makes the source whatever the caller says.
   Both corrupt this detector, in opposite and equally quiet ways.
2. **Never attach `auto_disable` to a `source_addr` rule.** If the field is ever
   forgeable, an automated response keyed on it is a denial-of-service primitive
   pointed at whoever the attacker names. The defaults already ship
   `flag`/`alert` only, with auto-disable opt-in; this is the case where that
   default must not be relaxed.

Two cautions:

- **A global rule's `group_key` may name something that spans tenants** (an IP),
  which is fine, or a principal (an actor), which is not: a username in one
  tenant is not the same person as the same username in another, and a global
  rule grouped by `actor` would conflate them. Restrict global rules to
  `source_addr` until there is a platform-wide principal identity to group by.
- **Global windows are unbounded by tenant count**, so their memory is a
  different shape from per-tenant ones. Worth measuring before the default pack
  gains many.

---

## 4. A notification is not a procedure

The requirement is that a redaction is *confirmed with the end customer before
proceeding*. That is a workflow with states, and an email has none.

`fileengine:events` is fail-open, trimmed and drop-oldest by design, and the
notifier dispatch is wrapped in `try/except` that logs and continues. Both are
right for a doorbell and wrong for an obligation. The platform has already made
this exact call once, for erasure: *"The event triggers; it does not guarantee.
A dropped erasure event would leave a service holding data the platform has
certified destroyed, and would do so silently"* — answered with a push/pull
split, the event for latency and `ListPendingErasures` for the guarantee.

The same split applies. **The email is the doorbell; the durable queue is the
record.** Concretely, incidents with `audience` including `deployment` need an
acknowledgement state beyond the `PgIncidentStore` row they already get:

| State | Meaning |
|---|---|
| `raised` | the rule fired; nobody has looked |
| `acknowledged` | a named deployment administrator has seen it |
| `customer_confirmed` | the administrator asserts the customer confirmed — with who and when |
| `approved` / `declined` | the decision, with a reason recorded either way |
| `completed` | the action was carried out, with a pointer to its evidence |

`erasure_ack` already models the hard half of this — participants acknowledging
compliance, with `complied = false` recorded rather than silence — and is the
shape to copy rather than invent.

Two properties that make it a procedure rather than a list:

- **Unacknowledged items accumulate and are queryable.** A queue whose backlog is
  invisible is a log. The count of `raised` items older than N hours is the
  number worth alerting on, and it is the one number that cannot be satisfied by
  sending more email.
- **`customer_confirmed` records an assertion, not a fact.** The confirmation
  happens outside the system, on a call or in writing. What the platform can
  honestly store is that a named administrator stated it happened, and when. It
  must not be phrased as though the system verified it.

---

## 5. Delivery, given there is no interface yet

The deployment-admin UI is planned and does not exist, so the queue needs a
destination that does:

- **SMTP** to a configured deployment-admin address, for `audience` including
  `deployment` — the `AdminNotifier` implementation §2 is missing. It should
  carry the incident and a link/identifier for the queue item, and it should not
  carry content: the audit log holds identifiers and structure, never payload,
  and an email is a copy that escapes every retention rule the platform has.
- **The existing alerting path** (Prometheus / the rules-engine alert already
  used for `share_link_locked`) for the backlog metric in §4.
- **An API on `audit_service`** for the queue and its transitions, so the
  interface adopts it later rather than the queue being built inside a UI that
  does not exist yet.

Email is the weakest of the three and must not be the only one, for the reason in
§4: it is fire-and-forget, and a deployment administrator who was on leave has no
way to discover what they missed.

---

## 6. Sequencing

1. **Wire a real `AdminNotifier`** (§2). Small, independent, and it fixes a stub
   that currently reports a notification it does not send. Worth doing on its own.
2. **`audience` on `Rule`** (§3), defaulting to `tenant`, plus the default-pack
   entries. Data, not a migration of every producer.
3. **The acknowledgement state and its API** (§4). This is the substantial piece
   and the one redaction actually depends on.
4. **Adopt it in the deployment-admin interface** when that is built.

Steps 1 and 2 are useful with or without redaction. Step 3 is what makes
"always a human-validated and confirmed procedure" a property of the system
rather than of whoever happens to read the logs.

---

## 7. Open questions

**Q1 — Who is the deployment administrator, as an identity?** Tenant admins are
LDAP roles. The deployment tier has no modelled principal, and an acknowledgement
that cannot name who acknowledged is not much of one. It may need to be the same
separate administrator §7-Q1 of the redaction proposal assumes.

**Q2 — Does a deployment-audience incident cross tenant boundaries?** An incident
carries a tenant. A deployment administrator seeing incidents from every tenant
is the point, and it is also the first thing in this platform that reads across
the tenant boundary by design. That deserves its own review rather than arriving
as a consequence of this.

**Q3 — Should the core emit a distinct signal at all, or is deriving everything
from audit enough?** §3 argues for deriving, so producers stay ignorant. The
counter-case is an event a service knows is deployment-critical but that no rule
anticipates. Deriving is the better default; the question is whether there is a
case it cannot express.
