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

"""Tamper-evidence tests for the audit hash chain (offline).

The audit log's integrity guarantee is ``row_hash = SHA-256(prev_hash ‖ canonical(row))``:
any edit, deletion, or reordering of rows breaks the linkage and is detectable.
``test_hashing.py`` covers the single-row primitives; this suite builds a
multi-row chain and proves the *chain-level* properties a verifier relies on,
without needing a live Postgres (mirrors the linkage logic of verify.verify_chain).

Run: ``PYTHONPATH=src pytest src/tests/test_chain_tamper.py``
"""
from datetime import datetime, timezone

from audit_service.hashing import canonical_json, canonical_row, compute_row_hash


def _canonical(event_id, action, detail=None):
    ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return canonical_row(
        event_id=event_id, ts=ts, category=1, action=action, outcome=0,
        actor="alice", actor_roles=["users"], target_uid="F", target_name="f.txt",
        target_type=1,
        detail=canonical_json(detail) if detail is not None else None,
        source_iface="grpc", source_addr="10.0.0.1", request_id="req-1", tenant=None,
    )


def _build_chain(canonicals):
    """Return a list of {canonical, prev_hash, row_hash} exactly as the writer
    would persist them."""
    chain = []
    prev = None
    for c in canonicals:
        h = compute_row_hash(prev, c)
        chain.append({"canonical": c, "prev_hash": prev, "row_hash": h})
        prev = h
    return chain


def _verify(chain):
    """Recompute the chain the way verify.verify_chain does: each row's stored
    hash must equal SHA-256(prev ‖ canonical), and prev must equal the previous
    row's stored hash. Returns the 1-based index of the first broken row, or None."""
    expected_prev = None
    for i, row in enumerate(chain, start=1):
        if row["prev_hash"] != expected_prev:
            return i  # linkage broken (row moved/removed/inserted)
        if compute_row_hash(row["prev_hash"], row["canonical"]) != row["row_hash"]:
            return i  # content edited
        expected_prev = row["row_hash"]
    return None


def _sample_canonicals():
    return [
        _canonical("e1", "login_success"),
        _canonical("e2", "get_file", {"bytes": 10}),
        _canonical("e3", "grant_permission", {"perm": "READ"}),
        _canonical("e4", "soft_delete"),
    ]


def test_clean_chain_verifies():
    chain = _build_chain(_sample_canonicals())
    assert _verify(chain) is None


def test_edited_content_is_detected():
    chain = _build_chain(_sample_canonicals())
    # An attacker rewrites row 3's content (e.g. hides a privilege grant) but
    # cannot recompute every downstream hash without breaking linkage.
    chain[2]["canonical"] = _canonical("e3", "grant_permission", {"perm": "NONE"})
    assert _verify(chain) == 3


def test_deleted_row_is_detected():
    chain = _build_chain(_sample_canonicals())
    # Drop row 2 to erase evidence; row 3's prev_hash no longer matches row 1.
    del chain[1]
    assert _verify(chain) == 2


def test_reordered_rows_are_detected():
    chain = _build_chain(_sample_canonicals())
    chain[1], chain[2] = chain[2], chain[1]
    assert _verify(chain) is not None


def test_forged_row_recompute_still_breaks_downstream():
    """Even if the attacker recomputes the tampered row's own hash, the NEXT
    row's prev_hash still points at the original, so the break is preserved."""
    chain = _build_chain(_sample_canonicals())
    forged = _canonical("e2", "get_file", {"bytes": 0})
    chain[1]["canonical"] = forged
    chain[1]["row_hash"] = compute_row_hash(chain[1]["prev_hash"], forged)  # self-consistent
    # Row 2 now verifies in isolation, but row 3's stored prev_hash is stale.
    assert _verify(chain) == 3
