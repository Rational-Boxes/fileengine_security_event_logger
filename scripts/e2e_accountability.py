#!/usr/bin/env python3
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

"""End-to-end: a real core, a real database, and this service's pull path.

Acceptance 3, 4 and 6 of PROPOSAL_accountability_record.md §8 — the ones that
cannot be demonstrated by either repo alone, because the claim is about what
survives when the *pieces between them* fail:

  * **Not bypassable by configuration.** With auditing disabled entirely at the
    core, every in-scope operation still produces a record.
  * **Not bypassable by queue state.** With Redis unreachable for the whole run,
    every operation still succeeds AND still produces a record — and this service
    still receives every one of them, because the pull path does not involve
    Redis at all.
  * **Replay.** A consumer restarted with a reset cursor reproduces the full core
    history in seq order.
  * **Queryable from the core alone**, with no audit_service and no Redis.
  * **The gate is real.** A caller without the dedicated reader role is refused,
    and cannot reach another tenant's chain by asking for it.

Run against the dev stack (Postgres on :5434 by default):

    python3 scripts/e2e_accountability.py

It starts its own core process with auditing and events switched OFF, which is
the point: with both disabled the ONLY path a record can take is the one under
test. Exits 0 on success, 1 on failure, 77 (skip) when the infrastructure or the
core binary is missing.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
WORKSPACE = os.path.abspath(os.path.join(REPO, ".."))
CORE = os.path.join(WORKSPACE, "file_engine_core")

sys.path.insert(0, os.path.join(REPO, "src"))
sys.path.insert(0, os.path.join(WORKSPACE, "python_interface"))

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if condition:
        print(f"  ok   {message}")
    else:
        print(f"  FAIL {message}")
        failures.append(message)


def skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(77)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.25)
    return False


def main():
    server = shutil.which("fileengine_server") or os.path.join(
        CORE, "build", "core", "fileengine_server")
    if not os.path.isfile(server):
        skip(f"no core binary at {server} — build the core first")

    try:
        import grpc  # noqa: F401
        from fileengine import fileservice_pb2 as pb
        from fileengine import fileservice_pb2_grpc as pb_grpc
    except ImportError as e:
        skip(f"gRPC/SDK unavailable: {e}")

    from audit_service.accountability import IntegrityBreak, verify_batch
    from audit_service.config import Config, load_dotenv
    from audit_service.core_client import CoreAccountabilityClient
    from audit_service.cursors import CursorStore
    from audit_service.puller import AccountabilityPuller
    from audit_service import db as audit_db

    load_dotenv(os.path.join(REPO, ".env"))
    config = Config()

    try:
        conn = audit_db.connect(config)
    except Exception as e:
        skip(f"Postgres not reachable: {e}")

    port = free_port()
    tenant = f"e2e_acct_{uuid.uuid4().hex[:8]}"
    storage = tempfile.mkdtemp(prefix="e2e-acct-")
    log_path = os.path.join(storage, "core.log")
    env = dict(os.environ)
    env.update({
        "FILEENGINE_GRPC_HOST": "127.0.0.1",
        "FILEENGINE_GRPC_PORT": str(port),
        "FILEENGINE_STORAGE_PATH": storage,
        # The two switches this test exists to defeat. Auditing off means the
        # audit sink is a NullAuditSink that "pretends every entry is durable";
        # events off means no Redis at all, so there is no queue hint either.
        # If a record still exists after this run, it did not come from either.
        "FILEENGINE_AUDIT_ENABLED": "false",
        "FILEENGINE_EVENTS_ENABLED": "false",
        # Point Redis at a closed port for good measure, so any code path that
        # tried to reach it would fail loudly rather than quietly succeed.
        "FILEENGINE_REDIS_PORT": str(free_port()),
        "FILEENGINE_LOG_TO_CONSOLE": "false",
        # Level FATAL and a real log file: the SECURITY channel has to reach that
        # file anyway, and no name may reach it at all.
        "FILEENGINE_LOG_LEVEL": "FATAL",
        "FILEENGINE_LOG_TO_FILE": "true",
        "FILEENGINE_LOG_FILE_PATH": log_path,
    })

    print(f"starting core on :{port} (audit OFF, events OFF, redis unreachable)")
    proc = subprocess.Popen([server], cwd=CORE, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_for_port(port):
            skip("core did not start listening")

        channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        stub = pb_grpc.FileServiceStub(channel)

        def auth(user, roles, tenant_id=tenant):
            return pb.AuthenticationContext(user=user, roles=list(roles),
                                            tenant=tenant_id, source_addr="10.0.0.9")

        # ── drive real operations through the real RPC surface ──────────────
        admin = auth("root", ["system_admin"])
        resource = "e2e-doc-" + uuid.uuid4().hex[:8]

        # Provision the tenant first. The core creates a tenant's schema lazily,
        # on the first call that goes through TenantManager — GrantPermission
        # reaches AclManager directly and does not, so on a brand-new tenant it
        # would fail on a missing table. A deployed system always has the tenant
        # provisioned by the time a bridge grants anything; this test creates it
        # the same way, rather than papering over the ordering.
        provisioned = stub.GetAllRoles(pb.GetAllRolesRequest(auth=admin))
        check(provisioned.success, "tenant provisioned")

        grant = stub.GrantPermission(pb.GrantPermissionRequest(
            resource_uid=resource, principal="bob",
            permission=pb.Permission.READ, auth=admin))
        check(grant.success, f"GrantPermission succeeded with Redis down ({grant.error})")

        revoke = stub.RevokePermission(pb.RevokePermissionRequest(
            resource_uid=resource, principal="bob",
            permission=pb.Permission.READ, auth=admin))
        check(revoke.success, f"RevokePermission succeeded ({revoke.error})")

        created = stub.CreateRole(pb.CreateRoleRequest(role="e2e_editors", auth=admin))
        check(created.success, "CreateRole succeeded")
        assigned = stub.AssignUserToRole(pb.AssignUserToRoleRequest(
            user="bob", role="e2e_editors", auth=admin))
        check(assigned.success, "AssignUserToRole succeeded")

        # ── acceptance 3 + 4: the record exists anyway ──────────────────────
        listed = stub.ListAccountabilityRecords(pb.ListAccountabilityRecordsRequest(
            tenant=tenant, newer_than_ts_micros=0, limit=100,
            auth=auth("audit_service", ["accountability_reader"])))
        check(listed.success, f"the reader role can pull records ({listed.error})")
        actions = [r.action for r in listed.records]
        check(actions == ["acl.grant", "acl.revoke", "role.create", "role.assign"],
              f"every in-scope operation was recorded with auditing and Redis both "
              f"unavailable (got {actions})")
        check(all(r.actor == "root" for r in listed.records),
              "each record names the acting identity the bridge presented")
        check(listed.head_seq == len(listed.records),
              "the response carries the committed head, for staleness checking")

        # ── acceptance 8: verification, consumer-side ───────────────────────
        client = CoreAccountabilityClient(config)
        client.config.core_grpc_host = "127.0.0.1"
        client.config.core_grpc_port = port
        records, has_more, head = client.fetch(tenant, 0, 100)
        try:
            verify_batch(tenant, records, last_seq=None, last_hash=None,
                         last_ts_micros=None)
            check(True, "the chain verifies end to end on the consumer side")
        except IntegrityBreak as e:
            check(False, f"chain verification failed: {e}")

        # ── the gate is real (§4.3.1) ───────────────────────────────────────
        denied = stub.ListAccountabilityRecords(pb.ListAccountabilityRecordsRequest(
            tenant=tenant, newer_than_ts_micros=0, limit=10,
            auth=auth("bob", ["editors"])))
        check(not denied.success and not denied.records,
              "a caller without the reader role is refused the security log")

        # The reader role covers the global chain too — audit_service has to
        # drain it to see tenant deletions. Restricting it to system_admin bought
        # nothing (the role already permits asking for any tenant by name) and
        # broke the only consumer the endpoint exists for.
        global_by_reader = stub.ListAccountabilityRecords(
            pb.ListAccountabilityRecordsRequest(
                tenant="*global*", newer_than_ts_micros=0, limit=10,
                auth=auth("audit_service", ["accountability_reader"])))
        check(global_by_reader.success,
              f"the reader role can drain the global chain ({global_by_reader.error})")

        global_allowed = stub.ListAccountabilityRecords(
            pb.ListAccountabilityRecordsRequest(
                tenant="*global*", newer_than_ts_micros=0, limit=10,
                auth=auth("root", ["system_admin"])))
        check(global_allowed.success, "system_admin can read the global chain")

        global_denied = stub.ListAccountabilityRecords(
            pb.ListAccountabilityRecordsRequest(
                tenant="*global*", newer_than_ts_micros=0, limit=10,
                auth=auth("bob", ["editors"])))
        check(not global_denied.success,
              "and a caller with neither role still cannot")

        # ── acceptance 15: the destroy-data bits are gated ──────────────────
        tenant_admin = auth("carol", ["tenant_admin"])
        cull = stub.PurgeOldVersions(pb.PurgeOldVersionsRequest(
            uid=resource, keep_count=1, auth=tenant_admin))
        check(not cull.success and "CULL_VERSIONS" in cull.error,
              "a tenant_admin cannot cull without an explicit grant")

        # ── acceptance 4: the pull delivers what push could not ─────────────
        cursors = CursorStore()
        cursors.ensure_schema(conn)
        conn.commit()
        puller = AccountabilityPuller(client.config, client, cursors)
        drained = puller.drain(conn, tenant, {})
        conn.commit()
        check(drained == 4,
              f"audit_service received every record with Redis down throughout "
              f"(drained {drained})")

        second = puller.drain(conn, tenant, {})
        conn.commit()
        check(second == 0, "a caught-up consumer sees nothing new")

        # ── replay from zero ────────────────────────────────────────────────
        cursors.reset(conn, tenant)
        conn.commit()
        replayed = puller.drain(conn, tenant, {})
        conn.commit()
        check(replayed == 4,
              "a consumer with a reset cursor reproduces the full core history")

        schema = "tenant_" + tenant
        with conn.cursor() as cur:
            cur.execute(f'SELECT count(*) FROM "{schema}".audit_log')
            written = cur.fetchone()[0]
        check(written == 4, f"and the replay did not duplicate a row (have {written})")

        # ── acceptance 6: queryable from the core alone ─────────────────────
        with conn.cursor() as cur:
            cur.execute(
                f'SELECT action FROM "{schema}".accountability_record '
                "WHERE principal = 'bob' ORDER BY seq")
            about_bob = [r[0] for r in cur.fetchall()]
        check(about_bob == ["acl.grant", "acl.revoke", "role.assign"],
              "'every authorization change affecting bob' is answerable from the "
              "core alone, with no audit_service and no Redis")

        # ── the operational log carries the mechanisms too ──────────────────
        # A denied read of the security log is a security event. The core was
        # started at level FATAL, which suppresses everything up to and including
        # ERROR — so if this line is present, no configuration silences it.
        core_log = ""
        if os.path.isfile(log_path):
            with open(log_path, errors="replace") as f:
                core_log = f.read()
        check("[SECURITY]" in core_log,
              "a SECURITY entry reached the log at level FATAL, where ERROR did not")
        check("Accountability read DENIED" in core_log,
              "and it is the denied read of the security log")
        check("[ERROR]" not in core_log,
              "while ordinary ERROR lines really were filtered — so the SECURITY "
              "entry is not just surviving a level that lets everything through")

        # Drive a create through the real RPC surface with a name that would be
        # unmistakable if it leaked, then prove it did not.
        party_data = "Acme_Corp_Contract_J_Smith_e2e.pdf"
        stub.MakeDirectory(pb.MakeDirectoryRequest(
            parent_uid="", name=party_data, auth=admin, permissions=0o755))
        with open(log_path, errors="replace") as f:
            core_log = f.read()
        check(party_data not in core_log and "Acme_Corp" not in core_log,
              "no filename reached the operational log in clear")
        # The tag that replaces it is NOT asserted here, and the reason is worth
        # writing down: the lines that carry a name are DEBUG/INFO, and this core
        # runs at FATAL precisely so the SECURITY assertions above mean something.
        # The two properties cannot be proven by the same run. That the tag is
        # stable, non-reversible and actually written is covered by
        # file_engine_core/tests/logger_tests.cpp.


        with conn.cursor() as cur:
            cur.execute(f'SELECT count(*) FROM "{schema}".accountability_record '
                        "WHERE detail::text ILIKE '%.pdf%' OR detail::text ILIKE '%name%'")
            leaked = cur.fetchone()[0]
        check(leaked == 0, "no filename or name-shaped field reached the chain")

        # And the audit log's own detail, which used to carry {"name": ...} on
        # every create and {"new_name": ...} on every rename.
        with conn.cursor() as cur:
            cur.execute(f'SELECT count(*) FROM "{schema}".audit_log '
                        "WHERE detail::text ILIKE %s OR target_name IS NOT NULL",
                        (f"%{party_data}%",))
            audit_leaked = cur.fetchone()[0]
        check(audit_leaked == 0,
              "and none reached the audit log's detail or target_name either")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
        try:
            with conn.cursor() as cur:
                cur.execute(f'DROP SCHEMA IF EXISTS "tenant_{tenant}" CASCADE')
                cur.execute("DELETE FROM tenants WHERE tenant_id = %s", (tenant,))
                cur.execute("DELETE FROM accountability_cursor WHERE tenant = %s",
                            (tenant,))
            conn.commit()
            conn.close()
        except Exception:
            pass
        shutil.rmtree(storage, ignore_errors=True)

    print(f"\n=== {checks - len(failures)}/{checks} checks passed ===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
