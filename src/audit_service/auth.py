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

"""Bridge-token (HS256 JWT) verification + the AUDIT_READ gate (§8).

The http_bridge issues HS256 JWTs with claims ``{sub, tenant, roles:{tenant:[...]},
exp}``. A caller may read a tenant's audit log iff they administer that tenant (a
member of ``admin_role`` for it) or hold ``system_admin`` — that is AUDIT_READ.
Verification is dependency-free (HMAC-SHA256) so the read API needs no PyJWT.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass


class AuthError(Exception):
    pass


@dataclass
class Identity:
    user: str
    roles_by_tenant: dict  # {tenant: [roles]}
    #: DEPLOYMENT-TIER roles, held in no tenant. These come from a token minted
    #: by admin_master_control, whose `roles` claim is a flat list because its
    #: authority is not per-tenant — that is the whole point of the tier.
    #:
    #: Kept OUT of roles_by_tenant deliberately. Putting them under a synthetic
    #: tenant key would make them show up in `roles_for(<that key>)` and in
    #: `all_roles()`, and `all_roles()` is what the system_admin check reads —
    #: so a deployment role would start satisfying a tenant-admin test by
    #: accident.
    deployment_roles: frozenset = frozenset()

    def roles_for(self, tenant: str) -> list:
        return self.roles_by_tenant.get(tenant, [])

    def all_roles(self) -> set:
        out: set = set()
        for rs in self.roles_by_tenant.values():
            out.update(rs)
        return out


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jwt(token: str, secret: str, *, leeway: int = 30,
               deployment_audience: str = "") -> Identity:
    """Verify a token and resolve who it is.

    TWO TOKEN SHAPES, and the second is admitted only on its audience:

      * a tenant door's token: `roles` is `{tenant: [roles]}`. Unchanged.
      * admin_master_control's: `roles` is a flat LIST, because deployment
        authority is not per-tenant. Accepted as deployment roles ONLY when
        `aud` equals ``deployment_audience``; without that the list is ignored
        and the caller gets nothing.

    NOTE, because it surprised me: this function does not otherwise check `aud`
    at all, and the bridge does not set one. So any token signed with the shared
    secret verifies here regardless of who minted it for whom. That is
    pre-existing and is NOT changed here — requiring `aud` would reject every
    bridge token in existence — but it is why the deployment path is gated on a
    positive audience match rather than on the shape of the roles claim. Shape
    alone would let a bridge token with a list-shaped roles claim become a
    deployment identity.
    """
    if not secret:
        raise AuthError("JWT verification is not configured (FILEENGINE_JWT_SECRET)")
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise AuthError("malformed token")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    try:
        sig = _b64url_decode(sig_b64)
    except Exception as e:
        raise AuthError("bad signature encoding") from e
    if not hmac.compare_digest(sig, expected):
        raise AuthError("bad signature")
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        raise AuthError("bad payload") from e
    exp = payload.get("exp")
    if exp is not None and time.time() > float(exp) + leeway:
        raise AuthError("token expired")
    raw = payload.get("roles")
    user = str(payload.get("sub") or payload.get("user") or "")

    if isinstance(raw, list):
        aud = payload.get("aud")
        if deployment_audience and aud == deployment_audience:
            return Identity(user=user, roles_by_tenant={},
                            deployment_roles=frozenset(str(r) for r in raw))
        # A list-shaped roles claim from anywhere else resolves to no authority
        # rather than to a guess.
        return Identity(user=user, roles_by_tenant={})

    roles = raw if isinstance(raw, dict) else {}
    return Identity(user=user, roles_by_tenant={k: list(v) for k, v in roles.items()})


def has_audit_read(identity: Identity, tenant: str | None, *,
                   admin_role: str, system_admin_role: str,
                   deployment_read_roles: tuple = ()) -> bool:
    """AUDIT_READ: system_admin, a deployment reader, or admin of `tenant`.

    ``deployment_read_roles`` is how the deployment tier reads across tenants
    without holding `system_admin`. That distinction is worth the parameter:
    `system_admin` is the core's ACL BYPASS — it reads every file in every
    tenant — while a deployment security role needs to read the audit ledger and
    nothing else. Handing admin_master_control a system_admin token to fetch
    incidents would give it the former to get the latter.
    """
    if system_admin_role in identity.all_roles():
        return True
    if deployment_read_roles and identity.deployment_roles.intersection(deployment_read_roles):
        return True     # the deployment tier reads every tenant, and global
    if tenant is None:
        return False  # a tenant admin may not read the global log
    return admin_role in identity.roles_for(tenant)
