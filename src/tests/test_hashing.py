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

from datetime import datetime, timezone

from audit_service.hashing import canonical_json, canonical_row, compute_row_hash

TS = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)


def _canon(**over):
    base = dict(event_id="11111111-1111-1111-1111-111111111111", ts=TS, category=0,
                action="read", outcome=0, actor="alice", actor_roles=None, target_uid="f1",
                target_name=None, target_type=0, detail=None, source_iface="grpc",
                source_addr=None, request_id=None, tenant=None)
    base.update(over)
    return canonical_row(**base)


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_canonical_row_is_deterministic():
    assert _canon() == _canon()


def test_canonical_row_changes_with_any_field():
    base = _canon()
    assert _canon(actor="bob") != base
    assert _canon(action="write") != base
    assert _canon(outcome=1) != base
    assert _canon(detail='{"x":1}') != base
    assert _canon(ts=datetime(2026, 7, 10, 12, 0, 1, tzinfo=timezone.utc)) != base


def test_compute_row_hash_depends_on_prev_and_content():
    c = _canon()
    h_genesis = compute_row_hash(None, c)
    assert len(h_genesis) == 32                         # SHA-256
    assert compute_row_hash(None, c) == h_genesis        # deterministic
    assert compute_row_hash(h_genesis, c) != h_genesis   # prev_hash matters
    assert compute_row_hash(None, _canon(actor="bob")) != h_genesis  # content matters


def test_empty_prev_hash_equals_none():
    c = _canon()
    assert compute_row_hash(b"", c) == compute_row_hash(None, c)
