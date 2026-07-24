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

"""Canonical integer codes for the ``audit_log`` SMALLINT columns.

The Redis envelope carries human-readable strings ("access", "ok", …); the DB
stores compact SMALLINTs. These maps are the single source of truth for that
translation and MUST stay in lockstep with the C++ emitter and every reader
(the §9 query/export API, the §10 console). Append new members; never renumber.
"""
from __future__ import annotations

# usage_logging_and_auditing.md §3 (taxonomy) / §4 (schema comment).
CATEGORY = {"access": 0, "mutate": 1, "permission": 2, "user": 3, "auth": 4, "admin": 5}
OUTCOME = {"ok": 0, "denied": 1, "error": 2}
TARGET_TYPE = {"file": 0, "dir": 1, "role": 2, "acl": 3, "version": 4, "principal": 5}

CATEGORY_NAME = {v: k for k, v in CATEGORY.items()}
OUTCOME_NAME = {v: k for k, v in OUTCOME.items()}
TARGET_TYPE_NAME = {v: k for k, v in TARGET_TYPE.items()}
