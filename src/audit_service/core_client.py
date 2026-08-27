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

"""gRPC client for the core's accountability pull endpoint (§4.3.1).

We deliberately do **not** read the core's tables directly, even though this
service already holds a connection to the same Postgres for its own writes.
Reaching into another service's schema would couple us to the core's internals,
bypass the core's own access control, and make any future schema change of the
core's a cross-repo release. The core exposes ``ListAccountabilityRecords`` on
the existing gRPC surface instead; this is the only door we use.

The generated stubs live in the ``python_interface`` SDK, which is the single
place the proto is compiled for Python. It is resolved by relative path the same
way the other Python services in this workspace resolve it.
"""
from __future__ import annotations

import logging
import os
import sys

from .accountability import CoreRecord, micros_to_datetime

log = logging.getLogger("audit_service.core_client")


def _import_stubs():
    """Import the SDK's generated stubs, adding the sibling checkout to sys.path.

    Kept lazy and in one place so importing this module never fails in an
    environment that has no gRPC — the unit tests exercise the verification and
    mapping logic against fake records, and should not need the SDK present.
    """
    try:
        from fileengine import fileservice_pb2, fileservice_pb2_grpc  # type: ignore
        return fileservice_pb2, fileservice_pb2_grpc
    except ImportError:
        pass
    sdk = os.environ.get("FILEENGINE_PYTHON_SDK") or os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "python_interface"))
    if sdk not in sys.path:
        sys.path.insert(0, sdk)
    from fileengine import fileservice_pb2, fileservice_pb2_grpc  # type: ignore
    return fileservice_pb2, fileservice_pb2_grpc


class CoreAccountabilityClient:
    """Reads a tenant's accountability chain forward by cursor."""

    def __init__(self, config):
        self.config = config
        self._channel = None
        self._stub = None
        self._pb = None

    # -- connection ---------------------------------------------------------

    def _connect(self):
        if self._stub is not None:
            return self._stub
        import grpc
        pb, pb_grpc = _import_stubs()
        from fileengine.service_token import authenticated_channel  # type: ignore
        self._pb = pb
        target = f"{self.config.core_grpc_host}:{self.config.core_grpc_port}"
        # Insecure, matching every other in-cluster caller: the core does not
        # authenticate, and gRPC is never network-exposed. The trust boundary is
        # positional, and the endpoint's own role gate is what limits us to the
        # security log rather than to everything.
        self._channel = grpc.insecure_channel(
            target,
            options=[("grpc.max_receive_message_length",
                      self.config.core_grpc_max_message_bytes)])
        # Present this service's credential on every call. The core resolves it
        # to `audit_service` and gates the call on the `accountability`
        # capability — so a compromised audit consumer cannot write files, which
        # today nothing stops it doing. A no-op when no token is configured,
        # which keeps the migration workable.
        self._channel = authenticated_channel(self._channel)
        self._stub = pb_grpc.FileServiceStub(self._channel)
        log.info("accountability puller connected to core at %s", target)
        return self._stub

    def close(self) -> None:
        if self._channel is not None:
            try:
                self._channel.close()
            except Exception:
                pass
        self._channel = None
        self._stub = None

    # -- reads --------------------------------------------------------------

    def _auth(self, tenant: str):
        pb = self._pb
        # The dedicated reader role, not an admin role: reading this chain across
        # tenants reconstructs who did what to whom platform-wide, so least
        # privilege applies even among trusted callers.
        return pb.AuthenticationContext(
            user=self.config.core_identity,
            roles=[self.config.core_reader_role],
            tenant=(tenant if tenant != "*global*" else "default"),
            source_addr="")

    def fetch(self, tenant: str, newer_than_ts_micros: int, limit: int):
        """Return ``(records, has_more, head_seq)`` for one page.

        Records come back in ``ts`` order, which under the core's chain lock is
        also ``seq`` order. ``head_seq`` is the core's committed head at read
        time, which is what lets a caller tell "nothing new" apart from "I am
        reading state that has not caught up".
        """
        stub = self._connect()
        pb = self._pb
        request = pb.ListAccountabilityRecordsRequest(
            tenant=tenant,
            newer_than_ts_micros=newer_than_ts_micros,
            limit=limit,
            auth=self._auth(tenant))
        response = stub.ListAccountabilityRecords(
            request, timeout=self.config.core_grpc_timeout_s)
        if not response.success:
            raise RuntimeError(f"core refused the accountability read for "
                               f"tenant {tenant!r}: {response.error}")
        records = [
            CoreRecord(
                seq=r.seq,
                ts_micros=r.ts_micros,
                ts=micros_to_datetime(r.ts_micros),
                actor=r.actor,
                actor_roles=list(r.actor_roles),
                source_iface=r.source_iface,
                source_addr=r.source_addr,
                category=r.category,
                action=r.action,
                target_uid=r.target_uid,
                target_type=r.target_type,
                principal=r.principal,
                # Verbatim. Re-serializing would change the bytes the core
                # hashed and break every verification.
                detail=r.detail,
                prev_hash=bytes(r.prev_hash) or None,
                hash=bytes(r.hash),
                global_tenant=r.global_tenant,
            )
            for r in response.records
        ]
        return records, response.has_more, response.head_seq
