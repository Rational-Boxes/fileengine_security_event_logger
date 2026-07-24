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

    def roles_for(self, tenant: str) -> list:
        return self.roles_by_tenant.get(tenant, [])

    def all_roles(self) -> set:
        out: set = set()
        for rs in self.roles_by_tenant.values():
            out.update(rs)
        return out


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jwt(token: str, secret: str, *, leeway: int = 30) -> Identity:
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
    roles = payload.get("roles")
    roles = roles if isinstance(roles, dict) else {}
    return Identity(user=str(payload.get("sub") or payload.get("user") or ""),
                    roles_by_tenant={k: list(v) for k, v in roles.items()})


def has_audit_read(identity: Identity, tenant: str | None, *,
                   admin_role: str, system_admin_role: str) -> bool:
    """AUDIT_READ: system_admin (any tenant + global) or admin of `tenant`."""
    if system_admin_role in identity.all_roles():
        return True
    if tenant is None:
        return False  # only system_admin may read the global log
    return admin_role in identity.roles_for(tenant)
