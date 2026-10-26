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

"""The archive key derivation (SPEC §10). The vector is pinned here AND in
scripts/Ansible/filter_plugins/test_fileengine_keys.py: if the two ever disagree
the deploy writes a key that cannot read what the last deploy archived."""
import base64

import pytest

from audit_service.archive import make_cipher
from audit_service.keys import (KeyFormatError, derive_archive_key, fingerprint,
                                parse_at_rest_key, primary_key)

HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PINNED = "7zutKZWoaA1zr5xeGIjr-Ej_gyfT4ke6MKO32Sldr5I="


def test_pinned_vector():
    assert derive_archive_key(HEX) == PINNED
    assert fingerprint(PINNED) == "fa981020975786b2"


def test_hex_and_base64_forms_derive_the_same_key():
    # The core accepts both spellings of AT_REST_KEY (crypto_utils.cpp).
    assert derive_archive_key(base64.b64encode(bytes(range(32))).decode()) == PINNED


def test_matches_the_reference_hkdf():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ref = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"fileengine/archive-key/v1").derive(bytes(range(32)))
    assert base64.urlsafe_b64encode(ref).decode() == PINNED


def test_derived_key_is_a_working_fernet_key():
    cipher = make_cipher(derive_archive_key(HEX))
    assert cipher.decrypt(cipher.encrypt(b"x")) == b"x"


@pytest.mark.parametrize("bad", ["", "zz" * 32, "c2hvcnQ=", "change-me-32-byte-key-keep-stable"])
def test_malformed_at_rest_keys_are_refused(bad):
    with pytest.raises(KeyFormatError):
        parse_at_rest_key(bad)


def test_primary_key_is_the_encrypting_one():
    assert primary_key(f" {PINNED} , other") == PINNED
    with pytest.raises(KeyFormatError):
        primary_key(" , ")
