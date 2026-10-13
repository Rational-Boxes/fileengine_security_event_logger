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

"""admin_master_control forwards its administrator's session, signed with the
console's OWN secret. Admitted as a deployment identity, and as nothing else."""
import base64
import hashlib
import hmac
import json
import time

import pytest

from audit_service.auth import AuthError, has_audit_read, verify_jwt

PLATFORM = "platform-secret"
CONSOLE = "console-secret"
AUD = "fileengine-system-admin"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign(payload: dict, secret: str, alg: str = "HS256") -> str:
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = _b64(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


def session(**over) -> dict:
    p = {"sub": "james", "aud": AUD, "iss": "admin-master-control",
         "iat": int(time.time()), "exp": int(time.time()) + 600,
         "amr": ["pwd", "totp"], "roles": ["system_security", "system_tenants"]}
    p.update(over)
    return {k: v for k, v in p.items() if v is not None}


def verify(tok: str, **kw):
    return verify_jwt(tok, PLATFORM, deployment_audience=AUD, deployment_secret=CONSOLE, **kw)


def test_console_session_is_a_deployment_identity_that_reads_every_tenant():
    ident = verify(sign(session(), CONSOLE))
    assert ident.user == "james"
    assert ident.deployment_roles == {"system_security", "system_tenants"}
    assert ident.roles_by_tenant == {}
    roles = dict(admin_role="administrators", system_admin_role="system_admin",
                 deployment_read_roles=("system_observer", "system_security"))
    assert has_audit_read(ident, None, **roles)
    assert has_audit_read(ident, "acme", **roles)


def test_a_console_signed_token_can_never_be_a_tenant_identity():
    # A tenant-shaped claim under the console's secret: refused, not a tenant admin.
    with pytest.raises(AuthError):
        verify(sign(session(roles={"acme": ["administrators"]}), CONSOLE))
    with pytest.raises(AuthError):
        verify(sign({"sub": "x", "roles": {"acme": ["administrators"]},
                     "exp": int(time.time()) + 60}, CONSOLE))


@pytest.mark.parametrize("over,why", [
    ({"aud": "fileengine-tenant"}, "audience"),
    ({"aud": None}, "audience"),
    ({"iss": "http-bridge"}, "issuer"),
    ({"exp": None}, "expiry"),
    ({"exp": int(time.time()) - 3600}, "expired"),
    ({"amr": ["pwd"]}, "second factor"),
    ({"amr": None}, "second factor"),
    ({"sub": ""}, "subject"),
])
def test_console_session_refusals(over, why):
    with pytest.raises(AuthError) as e:
        verify(sign(session(**over), CONSOLE))
    assert why in str(e.value)


def test_mfa_requirement_can_be_relaxed_explicitly():
    ident = verify(sign(session(amr=["pwd"]), CONSOLE), deployment_require_mfa=False)
    assert ident.deployment_roles


def test_without_the_console_secret_configured_its_sessions_are_refused():
    with pytest.raises(AuthError, match="bad signature"):
        verify_jwt(sign(session(), CONSOLE), PLATFORM, deployment_audience=AUD)


def test_platform_tokens_are_unchanged():
    ident = verify(sign({"sub": "a", "roles": {"acme": ["administrators"]},
                         "exp": int(time.time()) + 60}, PLATFORM))
    assert ident.roles_for("acme") == ["administrators"]
    assert ident.deployment_roles == frozenset()


def test_only_hs256_is_accepted():
    with pytest.raises(AuthError, match="algorithm"):
        verify(sign(session(), CONSOLE, alg="none"))


def test_a_token_signed_with_neither_secret_is_refused():
    with pytest.raises(AuthError, match="bad signature"):
        verify(sign(session(), "someone-else"))


# ── through the route ──────────────────────────────────────────────────────
# `order=bogus` is refused with 400 AFTER authentication and AUDIT_READ and
# before the database, so it shows a token got through the gate without one.

def _client(monkeypatch, console_secret: str):
    from fastapi.testclient import TestClient

    from audit_service.api import create_app
    from audit_service.config import Config

    monkeypatch.setenv("FILEENGINE_JWT_SECRET", PLATFORM)
    if console_secret:
        monkeypatch.setenv("AUDIT_DEPLOYMENT_JWT_SECRET", console_secret)
    else:
        monkeypatch.delenv("AUDIT_DEPLOYMENT_JWT_SECRET", raising=False)
    return TestClient(create_app(Config()))


def _incidents(c, tok):
    return c.get("/v1/security/incidents", params={"order": "bogus"},
                 headers={"Authorization": f"Bearer {tok}"})


def test_route_admits_the_forwarded_console_session(monkeypatch):
    c = _client(monkeypatch, CONSOLE)
    assert _incidents(c, sign(session(), CONSOLE)).status_code == 400


def test_route_refuses_it_when_the_console_secret_is_not_configured(monkeypatch):
    c = _client(monkeypatch, "")
    assert _incidents(c, sign(session(), CONSOLE)).status_code == 401


def test_route_console_session_without_a_reading_role_is_forbidden(monkeypatch):
    c = _client(monkeypatch, CONSOLE)
    assert _incidents(c, sign(session(roles=["system_tenants"]), CONSOLE)).status_code == 403
