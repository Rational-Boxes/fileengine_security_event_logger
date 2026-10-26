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

"""The archive key is DERIVED from the deployment's at-rest key (SPEC §10).

One escrowed secret, not two: whoever holds AT_REST_KEY can recompute the
archive key, so recovering the archive needs nothing the deployment's recovery
kit does not already hold. The derivation is one-way, so the retention job is
handed only the derived key and never the master that decrypts file content.

    archive_key = urlsafe_b64( HKDF-SHA256(ikm=AT_REST_KEY bytes, salt="",
                                           info="fileengine/archive-key/v1", L=32) )

AT_REST_KEY is parsed exactly as the core parses it (crypto_utils.cpp
``parse_aes256_key``): 64 characters is hex, anything else is base64, and either
must yield 32 bytes. The Ansible filter ``fileengine_archive_key``
(scripts/Ansible/filter_plugins) implements the same function; both pin the same
vector in their tests, because a disagreement strands every archive.

Stdlib only, so the filter plugin and an offline recovery need no packages.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

ARCHIVE_INFO = b"fileengine/archive-key/v1"


class KeyFormatError(ValueError):
    pass


def parse_at_rest_key(value: str) -> bytes:
    v = (value or "").strip()
    try:
        raw = bytes.fromhex(v) if len(v) == 64 else base64.b64decode(v, validate=True)
    except (ValueError, binascii.Error) as e:
        raise KeyFormatError(f"AT_REST_KEY is neither 64 hex characters nor base64: {e}")
    if len(raw) != 32:
        raise KeyFormatError(f"AT_REST_KEY must decode to 32 bytes, got {len(raw)}")
    return raw


def hkdf_sha256(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """RFC 5869. An empty salt is HashLen zero bytes, as the RFC specifies."""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block, i = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        okm += block
        i += 1
    return okm[:length]


def derive_archive_key(at_rest_key: str) -> str:
    """The Fernet key the archive is encrypted with, from AT_REST_KEY."""
    return base64.urlsafe_b64encode(
        hkdf_sha256(parse_at_rest_key(at_rest_key), ARCHIVE_INFO)).decode("ascii")


def fingerprint(fernet_key: str) -> str:
    """A short, non-secret identifier for a key: safe to print, log and compare."""
    return hashlib.sha256(fernet_key.strip().encode("ascii")).hexdigest()[:16]


def primary_key(keys: str) -> str:
    """The encrypting key of a comma-separated MultiFernet list."""
    first = next((k.strip() for k in (keys or "").split(",") if k.strip()), "")
    if not first:
        raise KeyFormatError("FILEENGINE_AUDIT_ARCHIVE_KEY is not set")
    return first
