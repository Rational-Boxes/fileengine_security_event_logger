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

from audit_service import codes


def test_category_values_are_stable():
    assert codes.CATEGORY == {
        "access": 0, "mutate": 1, "permission": 2, "user": 3, "auth": 4, "admin": 5}


def test_outcome_values_are_stable():
    assert codes.OUTCOME == {"ok": 0, "denied": 1, "error": 2}


def test_target_type_values_are_stable():
    assert codes.TARGET_TYPE == {
        "file": 0, "dir": 1, "role": 2, "acl": 3, "version": 4, "principal": 5}


def test_reverse_maps_round_trip():
    for name, code in codes.CATEGORY.items():
        assert codes.CATEGORY_NAME[code] == name
    for name, code in codes.OUTCOME.items():
        assert codes.OUTCOME_NAME[code] == name
    for name, code in codes.TARGET_TYPE.items():
        assert codes.TARGET_TYPE_NAME[code] == name
