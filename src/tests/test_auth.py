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

import base64
import hashlib
import hmac
import json
import time

import pytest

from audit_service.auth import AuthError, Identity, has_audit_read, verify_jwt

SECRET = "test-secret"


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign(payload: dict, secret: str = SECRET) -> str:
    h = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = _b64(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64(sig)}"


def test_verify_valid_token():
    tok = sign({"sub": "alice", "roles": {"acme": ["administrators"]}, "exp": time.time() + 60})
    ident = verify_jwt(tok, SECRET)
    assert ident.user == "alice"
    assert ident.roles_for("acme") == ["administrators"]


def test_bad_signature_rejected():
    tok = sign({"sub": "alice", "exp": time.time() + 60})
    with pytest.raises(AuthError):
        verify_jwt(tok, "wrong-secret")


def test_expired_token_rejected():
    tok = sign({"sub": "alice", "exp": time.time() - 100})
    with pytest.raises(AuthError):
        verify_jwt(tok, SECRET)


@pytest.mark.parametrize("tok", ["abc", "a.b.c.d", ""])
def test_malformed_token_rejected(tok):
    with pytest.raises(AuthError):
        verify_jwt(tok, SECRET)


def test_missing_secret_rejected():
    with pytest.raises(AuthError):
        verify_jwt(sign({"sub": "a"}), "")


_KW = dict(admin_role="administrators", system_admin_role="system_admin")


def test_audit_read_gate():
    admin = Identity("alice", {"acme": ["administrators"]})
    user = Identity("bob", {"acme": ["editors"]})
    sysadmin = Identity("root", {"ops": ["system_admin"]})

    assert has_audit_read(admin, "acme", **_KW)          # tenant admin
    assert not has_audit_read(user, "acme", **_KW)       # non-admin
    assert not has_audit_read(admin, "other", **_KW)     # admin of acme, not other
    assert has_audit_read(sysadmin, "acme", **_KW)       # system_admin bypass
    assert has_audit_read(sysadmin, None, **_KW)         # global: only system_admin
    assert not has_audit_read(admin, None, **_KW)        # tenant admin cannot read global
