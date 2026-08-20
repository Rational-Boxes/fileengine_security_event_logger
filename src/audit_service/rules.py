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

"""Security rule DSL + the system-default rule pack (usage_logging §11).

A rule is deterministic: a ``when`` match (category / optional action / optional
outcome) counted in a sliding ``window_s`` grouped by ``group_by`` (actor,
source_addr, or tenant); when the count reaches ``threshold`` it fires with a
``severity`` and a graduated ``response``. A ``then`` action turns it into a
sequence rule (e.g. login_failure ×k *then* login_success = a successful guess).

Rules are data (dicts / JSON), so the console's guided builder and raw-DSL editor
produce the same shape. Defaults ship in ``flag``/``alert`` — auto-disable is an
explicit opt-in (§11).
"""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("info", "warn", "serious", "critical")
RESPONSES = ("flag", "alert", "auto_disable")
GROUP_BYS = ("actor", "source_addr", "tenant")

# Severities at/above this trigger the mandatory admin email (§11).
SERIOUS = ("serious", "critical")


@dataclass
class Rule:
    id: str
    description: str
    category: str                    # match event category, e.g. "auth"
    group_by: str = "actor"          # window key dimension
    window_s: int = 300
    threshold: int = 5
    action: str | None = None        # match action, None = any
    outcome: str | None = None       # match outcome, None = any
    then_action: str | None = None   # sequence seal action (same group key), None = threshold rule
    severity: str = "warn"
    response: str = "flag"
    dry_run: bool = False
    cooldown_s: int = 300            # suppress re-firing the same group for this long
    enabled: bool = True

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity: {self.severity!r}")
        if self.response not in RESPONSES:
            raise ValueError(f"bad response: {self.response!r}")
        if self.group_by not in GROUP_BYS:
            raise ValueError(f"bad group_by: {self.group_by!r}")

    @property
    def is_sequence(self) -> bool:
        return self.then_action is not None

    def matches_primary(self, ev: dict) -> bool:
        return (ev.get("category") == self.category
                and (self.action is None or ev.get("action") == self.action)
                and (self.outcome is None or ev.get("outcome") == self.outcome))

    def matches_seal(self, ev: dict) -> bool:
        return self.is_sequence and ev.get("category") == self.category \
            and ev.get("action") == self.then_action

    def key_for(self, ev: dict) -> str | None:
        val = ev.get(self.group_by)
        return str(val) if val else None

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        allowed = {f.name for f in fields_of(cls)}
        return cls(**{k: v for k, v in d.items() if k in allowed})


def fields_of(cls):
    import dataclasses
    return dataclasses.fields(cls)


def default_rules() -> list[Rule]:
    """Conservative system defaults (§11). All flag/alert — auto-disable is opt-in."""
    return [
        Rule(id="brute_force_login",
             description="Repeated login failures for one identity (brute force).",
             category="auth", action="login_failure", outcome="denied",
             group_by="actor", window_s=300, threshold=5,
             severity="serious", response="alert"),
        Rule(id="brute_force_source_ip",
             description="Repeated login failures from one source IP (spray/brute force).",
             category="auth", action="login_failure", outcome="denied",
             group_by="source_addr", window_s=300, threshold=15,
             severity="serious", response="alert"),
        Rule(id="credential_guess",
             description="Several login failures then a success for one identity "
                         "(a likely successful guess).",
             category="auth", action="login_failure", outcome="denied",
             then_action="login_success", group_by="actor", window_s=600, threshold=5,
             severity="serious", response="alert"),
        Rule(id="bulk_exfiltration",
             description="A burst of reads by one actor (possible bulk exfiltration).",
             category="access", action="read", outcome="ok",
             group_by="actor", window_s=600, threshold=100,
             severity="warn", response="flag"),
        Rule(id="mass_delete",
             description="A burst of deletions by one actor (mass deletion).",
             category="mutate", action="soft_delete",
             group_by="actor", window_s=300, threshold=20,
             severity="warn", response="flag"),

        # --- share links (OUTSIDE_SHARE_LINKS §8.4) ------------------------
        # THRESHOLD 1, deliberately. share_service only emits this once it has
        # already adjudicated a link as under attack — counted the failures,
        # weighted the timing trips, and locked the link. Re-deriving that
        # judgement from a burst here would mean two systems having to agree on
        # what an attack looks like, and the one WITHOUT the per-link state
        # would be the weaker judge.
        Rule(id="share_link_brute_force",
             description="A share link was locked after repeated failed codes "
                         "(adjudicated brute force against a public link).",
             # Grouped by actor, which for a share event IS the link:
             # share_service emits these as `share:<link_uid>`, so per-actor
             # grouping is per-link without needing a new dimension.
             category="auth", action="share_link_locked", outcome="denied",
             group_by="actor", window_s=3600, threshold=1,
             severity="serious", response="alert"),

        # The broader signal, for what the lockout does NOT catch: denials
        # spread thinly across MANY links from one source. Each link stays under
        # its own threshold, so no lockout ever fires; the source is the only
        # dimension that sees it. Grouped by source_addr for exactly that reason.
        Rule(id="share_link_denial_burst",
             description="A burst of share-link denials from one source "
                         "(scanning for live links).",
             category="access", action="share_link_denied", outcome="denied",
             group_by="source_addr", window_s=600, threshold=30,
             severity="warn", response="flag"),
    ]
