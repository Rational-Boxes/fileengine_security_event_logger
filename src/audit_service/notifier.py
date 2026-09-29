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

"""Telling a deployment administrator that something needs them.

PROPOSAL_deployment_admin_signal.md §5. This replaces the stub in `engine.py`,
which logged *"MANDATORY admin email for serious incident"* and sent nothing —
a notification path that reported a notification it did not make.

**An email carries identifiers and structure, never content.** The audit log
holds no payload by design, and an email is a copy that escapes every retention
rule the platform has: it sits in a mailbox, gets forwarded, and is indexed by
whoever runs the mail. So the message names the rule, the counts, the window and
the group key, and it does not name a file or quote a value. §5 says this
directly and it is the constraint most likely to be relaxed by someone adding
"just the filename" to make an alert more useful.

**Email is the weakest of the three destinations and must not be the only one.**
§4: it is fire-and-forget, and an administrator who was on leave has no way to
discover what they missed. So delivery FAILURE is loud here rather than
swallowed, and the notifier records what it sent so a queue built later can
reconcile against it.
"""
from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Iterable, Optional, Protocol

log = logging.getLogger("audit_service.notifier")

#: Severities that mean a deployment administrator must be told, rather than
#: being able to find out. Kept here rather than in the rule pack because it is
#: a delivery decision: a rule author choosing a severity should not also be
#: choosing whether somebody's phone goes off at 3am.
MANDATORY_SEVERITIES = frozenset({"serious", "critical"})


class Transport(Protocol):
    """Sends one message. Injectable so delivery can be tested without SMTP."""

    def send(self, subject: str, body: str, to: list[str]) -> None: ...


@dataclass
class SmtpTransport:
    host: str
    port: int = 25
    sender: str = ""
    username: str = ""
    password: str = ""
    use_tls: bool = False
    timeout_s: float = 10.0

    def send(self, subject: str, body: str, to: list[str]) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(to)
        # Not a hint to the recipient — a hint to every mail system in between.
        # These messages are operational and must not be filed as bulk.
        msg["Auto-Submitted"] = "auto-generated"
        msg.set_content(body)

        with smtplib.SMTP(self.host, self.port, timeout=self.timeout_s) as s:
            if self.use_tls:
                s.starttls(context=ssl.create_default_context())
            if self.username:
                s.login(self.username, self.password)
            s.send_message(msg)


@dataclass
class RecordingTransport:
    """Keeps messages instead of sending them. Real, for development and tests —
    a notifier whose behaviour can only be checked against a live mail server is
    a notifier nobody checks."""

    sent: list = field(default_factory=list)

    def send(self, subject: str, body: str, to: list[str]) -> None:
        self.sent.append({"subject": subject, "body": body, "to": list(to)})


def _fmt(incident) -> tuple[str, str]:
    """Subject and body for one incident. Identifiers and structure only."""
    scope = getattr(incident, "scope", "tenant")
    where = "platform-wide" if scope == "global" else f"tenant {incident.tenant}"
    subject = (f"[FileEngine {incident.severity}] {incident.rule_id} — {where}")

    lines = [
        f"rule:        {incident.rule_id}",
        f"description: {incident.description}",
        f"severity:    {incident.severity}",
        f"scope:       {scope}",
        f"audience:    {getattr(incident, 'audience', 'tenant')}",
        f"tenant:      {incident.tenant if incident.tenant else '(spans tenants)'}",
        f"grouped by:  {incident.group_by} = {incident.group_key}",
        f"count:       {incident.count} in {incident.window_s}s",
        f"actor:       {incident.actor or '(none recorded)'}",
        f"last event:  {incident.last_ts}",
        f"action:      {incident.action_taken}{' (dry run)' if incident.dry_run else ''}",
    ]

    values = tuple(getattr(incident, "distinct_values", ()) or ())
    if values:
        # The fan-out case. "8 tenants" without naming them leaves the
        # administrator to go and find out which, which is the first thing they
        # will want. Tenant NAMES are structure, not content.
        shown = ", ".join(values[:20])
        more = "" if len(values) <= 20 else f" (+{len(values) - 20} more)"
        lines.append(f"touched:     {len(values)} distinct — {shown}{more}")

    lines += [
        "",
        "This message deliberately carries no file names, paths or content —",
        "the audit log holds identifiers and structure only, and an email is a",
        "copy that escapes the platform's retention rules.",
        "",
        "Query the audit ledger for the events behind this incident.",
    ]
    return subject, "\n".join(lines)


@dataclass
class EmailAdminNotifier:
    """The real notifier. Sends to the deployment-admin address for incidents
    whose audience includes the deployment tier."""

    transport: Optional[Transport] = None
    recipients: tuple[str, ...] = ()
    #: Send for these severities. Anything below is recorded and queued, not
    #: mailed — §4's point that a notification is not a procedure cuts both
    #: ways, and mailing every `warn` is how an administrator learns to filter
    #: the whole address into a folder they stop reading.
    mandatory_severities: frozenset = MANDATORY_SEVERITIES

    #: Everything this notifier decided to send, for reconciliation by the queue
    #: when §4's acknowledgement state is built.
    sent: list = field(default_factory=list)

    def _deliverable(self, incident) -> bool:
        if getattr(incident, "audience", "tenant") != "deployment":
            return False
        return incident.severity in self.mandatory_severities

    def alert(self, incident) -> None:
        """The ordinary alert path, for `response == "alert"` rules."""
        log.info("alert: %s (%s, scope=%s)", incident.rule_id, incident.severity,
                 getattr(incident, "scope", "tenant"))

    def notify_admins_mandatory(self, incident) -> None:
        """Tell the deployment administrators. Loud on failure.

        The stub this replaces logged a warning that read like a notification
        and sent nothing, so a deployment could run for a year believing it was
        covered. A send that FAILS must therefore not be swallowed: it is
        logged at error with the incident id, and it re-raises so the caller's
        own error handling sees it. The engine already wraps dispatch, so a
        broken mail server cannot stop incident recording — but it will be
        visible instead of silent.
        """
        if not self._deliverable(incident):
            log.debug("not a deployment-audience mandatory incident: %s", incident.rule_id)
            return
        if not self.transport or not self.recipients:
            # NOT a silent no-op. This is precisely the state the stub left the
            # deployment in, and the whole point of the replacement is that it
            # says so.
            log.error("NO ADMIN NOTIFIER CONFIGURED — incident %s (%s) was NOT sent to "
                      "anyone. Set the deployment-admin address and SMTP host.",
                      incident.rule_id, incident.severity)
            return

        subject, body = _fmt(incident)
        try:
            self.transport.send(subject, body, list(self.recipients))
        except Exception:
            log.exception("FAILED to notify deployment admins of %s — nobody was told",
                          incident.rule_id)
            raise
        self.sent.append({"rule_id": incident.rule_id, "severity": incident.severity,
                          "scope": getattr(incident, "scope", "tenant"),
                          "to": list(self.recipients)})
        log.info("notified %d deployment admin(s) of %s",
                 len(self.recipients), incident.rule_id)


def from_config(cfg) -> EmailAdminNotifier:
    """Build a notifier from configuration, or one that says it is unconfigured.

    Returns a notifier either way rather than None: a caller that has to check
    for None will eventually forget, and the failure mode of forgetting is
    exactly the stub's — a deployment that believes it is covered.
    """
    host = getattr(cfg, "smtp_host", "") or ""
    recipients = tuple(r for r in (getattr(cfg, "admin_emails", ()) or ()) if r)
    if not host or not recipients:
        log.warning("admin notifier not configured (smtp_host=%r, recipients=%d) — "
                    "mandatory incidents will be logged as undelivered",
                    host, len(recipients))
        return EmailAdminNotifier(transport=None, recipients=recipients)
    return EmailAdminNotifier(
        transport=SmtpTransport(
            host=host,
            port=int(getattr(cfg, "smtp_port", 25) or 25),
            sender=getattr(cfg, "smtp_from", "") or "",
            username=getattr(cfg, "smtp_user", "") or "",
            password=getattr(cfg, "smtp_password", "") or "",
            use_tls=bool(getattr(cfg, "smtp_tls", False)),
        ),
        recipients=recipients,
    )
