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

"""Tenant → Postgres schema name, mirroring the core exactly.

The core provisions each tenant's tables under ``get_schema_prefix(tenant)``
(``Database::get_schema_prefix`` / ``validate_schema_name`` in
``file_engine_core/core/src/database.cpp``). The audit writer must resolve the
identical schema name from the ``tenant`` on each envelope, or it would write to
the wrong (or a non-existent) schema. This is a faithful port of that C++ logic;
keep the two in sync.
"""
from __future__ import annotations


def _is_ascii_alnum(c: str) -> bool:
    # std::isalnum under the default C locale is ASCII-only; Python's str.isalnum
    # is Unicode-aware, so restrict to ASCII to match the core byte-for-byte.
    return c.isascii() and c.isalnum()


def validate_schema_name(schema_name: str) -> str:
    # Remove any char that is not [A-Za-z0-9_].
    validated = "".join(c for c in schema_name if _is_ascii_alnum(c) or c == "_")
    # Ensure it starts with an alphanumeric or underscore.
    if validated and not (_is_ascii_alnum(validated[0]) or validated[0] == "_"):
        validated = "_" + validated
    # Cap length (Postgres identifiers are 63 bytes).
    return validated[:63]


def schema_for_tenant(tenant: str) -> str:
    """Return the schema name the core uses for ``tenant`` (e.g. ``tenant_acme``).

    An empty tenant maps to ``tenant_default`` — the same fallback the core uses
    so the reserved word "default" is never a bare schema name.
    """
    if not tenant:
        return "tenant_default"
    return validate_schema_name("tenant_" + tenant)
