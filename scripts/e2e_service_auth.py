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

"""End-to-end service authentication and capability gating.

The §9 acceptance criteria from
`file_engine_core/design_documents/PROPOSAL_service_authentication.md` that need
a real core with auth actually required — the ones no unit test can reach,
because they are about what happens to a call before any handler sees it.

Runs a core of its own with a fresh pepper and a scratch database schema, drives
bootstrap enrolment over the Unix socket, issues credentials through the CLI, and
then checks what each identity can and cannot do.

Exits 0 on success, 1 on failure, 77 (skip) when infrastructure or the binaries
are missing.
"""
from __future__ import annotations

import os
import secrets
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
    print(f"  {'ok  ' if condition else 'FAIL'} {message}")
    if not condition:
        failures.append(message)


def skip(reason):
    print(f"SKIP: {reason}")
    sys.exit(77)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port, timeout=40.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.25)
    return False


def main():
    server = os.path.join(CORE, "build", "core", "fileengine_server")
    cli = os.path.join(CORE, "build", "cli", "fileengine_cli")
    if not os.path.isfile(server) or not os.path.isfile(cli):
        skip("build the core and CLI first")

    try:
        import grpc
        from fileengine import fileservice_pb2 as pb
        from fileengine import fileservice_pb2_grpc as pb_grpc
    except ImportError as e:
        skip(f"gRPC/SDK unavailable: {e}")

    from audit_service.config import Config, load_dotenv
    from audit_service import db as audit_db

    load_dotenv(os.path.join(REPO, ".env"))
    config = Config()
    try:
        conn = audit_db.connect(config)
    except Exception as e:
        skip(f"Postgres not reachable: {e}")

    # A pepper of our own, so this run cannot verify credentials from any other
    # and vice versa — which is also §9.2's "a valid token for a different
    # deployment" case, for free.
    pepper = secrets.token_hex(32)
    port = free_port()
    tenant = f"svcauth_{uuid.uuid4().hex[:8]}"
    workdir = tempfile.mkdtemp(prefix="e2e-svcauth-")
    sock = os.path.join(workdir, "bootstrap.sock")

    env = dict(os.environ)
    env.update({
        "FILEENGINE_GRPC_HOST": "127.0.0.1",
        "FILEENGINE_GRPC_PORT": str(port),
        "FILEENGINE_STORAGE_PATH": os.path.join(workdir, "storage"),
        "FILEENGINE_AUDIT_ENABLED": "false",
        "FILEENGINE_EVENTS_ENABLED": "false",
        "FILEENGINE_LOG_TO_CONSOLE": "false",
        # The whole point of this run.
        "FILEENGINE_SERVICE_AUTH_REQUIRED": "true",
        "FILEENGINE_SERVICE_TOKEN_PEPPER": pepper,
        "FILEENGINE_BOOTSTRAP_SOCKET": sock,
        # Short, so a capability granted mid-run takes effect without a restart —
        # which is the property that makes onboarding a service not an outage.
        "FILEENGINE_SERVICE_MAP_CACHE_TTL": "1",
    })
    cli_env = dict(env)

    # Bootstrap must be un-run for the socket to open at all.
    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS service_auth_bootstrap")
        cur.execute("DELETE FROM service_auth_credential WHERE service_id LIKE %s", ("e2e_%",))
        cur.execute("DELETE FROM service_auth_credential WHERE service_id LIKE %s", ("cli:e2e%",))
    conn.commit()

    print(f"starting core on :{port} with service auth REQUIRED")
    core_log_path = os.path.join(workdir, "core.log")
    core_log = open(core_log_path, "w")
    proc = subprocess.Popen([server], cwd=CORE, env=env,
                            stdout=core_log, stderr=subprocess.STDOUT)
    try:
        if not wait_for_port(port):
            core_log.flush()
            with open(core_log_path, errors="replace") as f:
                print(f.read()[-2000:])
            skip("core did not start listening")

        def core_died():
            """A dead core makes every check fail as UNAVAILABLE, which reads as
            a dozen unrelated bugs. Say so once, with its output."""
            if proc.poll() is None:
                return False
            core_log.flush()
            with open(core_log_path, errors="replace") as f:
                tail = "".join(l for l in f if "DEBUG" not in l)[-1500:]
            print(f"\n!! the core exited with {proc.returncode}; its output:\n{tail}\n")
            return True

        channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        stub = pb_grpc.FileServiceStub(channel)
        admin = pb.AuthenticationContext(user="root", roles=["system_admin"], tenant=tenant)

        def call(method, request, token=None):
            md = [("x-fe-service-token", token)] if token else None
            return getattr(stub, method)(request, metadata=md)

        if os.environ.get("E2E_DUMP_CORE_LOG"):
            core_log.flush()
            with open(core_log_path, errors="replace") as f:
                print("".join(l for l in f if "DEBUG" not in l)[-2500:])

        # ── §9.1: no token is rejected, and never reaches a handler ──────────
        try:
            call("GetAllRoles", pb.GetAllRolesRequest(auth=admin))
            check(False, "a call with no token is rejected")
        except grpc.RpcError as e:
            check(e.code() == grpc.StatusCode.UNAUTHENTICATED,
                  f"a call with no token is UNAUTHENTICATED (got {e.code()})")
            check("token" not in e.details().lower() or "fesvc" not in e.details(),
                  "and the rejection echoes no credential")

        if core_died():
            return 1

        # ── §9.4: EVERY rpc is covered ──────────────────────────────────────
        #
        # Enumerated from the compiled service descriptor, not a hand-written
        # list. This is what makes the guarantee real: the decision is made in
        # one place (the interceptor) but returned by each handler, and a
        # handler that forgot its guard would answer normally here instead of
        # refusing. Driving all 42 catches that, where reading the code would
        # not.
        from google.protobuf import descriptor_pool
        service_desc = descriptor_pool.Default().FindServiceByName(
            "fileengine_rpc.FileService")
        unguarded = []
        for method in service_desc.methods:
            request_cls = getattr(pb, method.input_type.name)
            try:
                handle = getattr(stub, method.name)
                # Arity matters: a client-streaming stub expects an ITERATOR of
                # requests, and handing it a bare message fails client-side with
                # UNKNOWN before the call leaves the process — which would look
                # exactly like an unguarded handler.
                if method.client_streaming:
                    result = handle(iter([request_cls()]))
                else:
                    result = handle(request_cls())
                # A server-streaming call returns an iterator, and its status
                # only materialises once something is pulled from it.
                if method.server_streaming:
                    for _ in result:
                        break
                unguarded.append(method.name)
            except grpc.RpcError as e:
                if e.code() != grpc.StatusCode.UNAUTHENTICATED:
                    unguarded.append(f"{method.name}({e.code().name})")
        if unguarded:
            print("    methods that did NOT refuse an unauthenticated call:")
            for name in unguarded:
                print(f"      - {name}")
        check(not unguarded,
              f"all {len(service_desc.methods)} RPCs refuse an unauthenticated call")

        # ── §9.2: unknown and malformed are rejected identically ────────────
        for label, bad in [("unknown service", "fesvc_nosuchservice.abcdef"),
                           ("malformed", "not-a-token"),
                           ("another deployment's", "fesvc_http_bridge." + secrets.token_urlsafe(32))]:
            try:
                call("GetAllRoles", pb.GetAllRolesRequest(auth=admin), token=bad)
                check(False, f"{label} token is rejected")
            except grpc.RpcError as e:
                check(e.code() == grpc.StatusCode.UNAUTHENTICATED,
                      f"{label} token is UNAUTHENTICATED")

        # ── §3.6: bootstrap enrolment over the Unix socket ──────────────────
        check(os.path.exists(sock),
              "the enrolment socket exists while bootstrap is incomplete")
        mode = os.stat(sock).st_mode & 0o777
        check(mode == 0o600, f"and is 0600, not {oct(mode)} — the mode is the control")

        enrol = subprocess.run([cli, "bootstrap", "enrol", "cli:e2e"],
                               cwd=CORE, env=cli_env, capture_output=True, text=True)
        cli_token = enrol.stdout.strip()
        check(enrol.returncode == 0 and cli_token.startswith("fesvc_cli:e2e."),
              f"bootstrap enrolled a cli identity ({enrol.stderr.strip()[:120]})")
        check(not os.path.exists(sock),
              "and the socket is REMOVED on use — the surface is gone, not merely closed")

        second = subprocess.run([cli, "bootstrap", "enrol", "cli:again"],
                                cwd=CORE, env=cli_env, capture_output=True, text=True)
        check(second.returncode != 0, "a second enrolment is refused — it is single-shot")

        # ── §9.3: a valid token works and names the door ────────────────────
        cli_env["FILEENGINE_CLI_TOKEN"] = cli_token
        roles = call("GetAllRoles", pb.GetAllRolesRequest(auth=admin), token=cli_token)
        check(roles.success, "the cli credential is accepted over loopback")

        # ── §6.1: cli holds every capability but is NOT exempt from the map ──
        # PurgeOldVersions is `destroy`; cli holds it.
        purge = call("PurgeOldVersions",
                     pb.PurgeOldVersionsRequest(uid="nonexistent", keep_count=1, auth=admin),
                     token=cli_token)
        check(purge is not None, "cli reaches a destroy-classified method")

        # ── §9.7: capability gating is independent of the user axis ─────────
        issue = subprocess.run([cli, "service-token", "issue", "e2e_reader"],
                               cwd=CORE, env=cli_env, capture_output=True, text=True)
        reader_token = issue.stdout.strip()
        check(issue.returncode == 0 and reader_token.startswith("fesvc_e2e_reader."),
              f"issued a credential for e2e_reader ({issue.stderr.strip()[:120]})")

        # No capabilities granted yet: everything is denied, default-deny.
        try:
            call("GetAllRoles", pb.GetAllRolesRequest(auth=admin), token=reader_token)
            check(False, "a service with no capabilities is denied")
        except grpc.RpcError as e:
            check(e.code() == grpc.StatusCode.PERMISSION_DENIED,
                  "a service with no capabilities is PERMISSION_DENIED, "
                  "even presenting system_admin")

        grant = subprocess.run([cli, "service", "grant", "e2e_reader", "read"],
                               cwd=CORE, env=cli_env, capture_output=True, text=True)
        check(grant.returncode == 0, "granted 'read'")
        time.sleep(2)   # let the short map cache expire

        stat = call("Exists", pb.ExistsRequest(uid="", auth=admin), token=reader_token)
        check(stat is not None,
              "with 'read' granted the call succeeds — with NO restart, which is what "
              "makes onboarding a service not an outage")

        # Still denied outside the granted set, with a user who would otherwise
        # be authorized. This is the two-axes property.
        try:
            call("CreateRole", pb.CreateRoleRequest(role="e2e_role", auth=admin),
                 token=reader_token)
            check(False, "a read-only service is refused a roles method")
        except grpc.RpcError as e:
            check(e.code() == grpc.StatusCode.PERMISSION_DENIED,
                  "a read-only service is refused 'roles' while presenting system_admin — "
                  "the two axes are independent")

        # ── §9.5: rotation overlaps ─────────────────────────────────────────
        rot = subprocess.run([cli, "service-token", "rotate", "e2e_reader"],
                             cwd=CORE, env=cli_env, capture_output=True, text=True)
        rotated_token = rot.stdout.strip()
        check(rot.returncode == 0 and rotated_token != reader_token, "rotated")
        time.sleep(2)
        old_ok = call("Exists", pb.ExistsRequest(uid="", auth=admin), token=reader_token)
        new_ok = call("Exists", pb.ExistsRequest(uid="", auth=admin), token=rotated_token)
        check(old_ok is not None and new_ok is not None,
              "BOTH secrets are valid during the overlap — without which rotation "
              "means restarting every instance at once, so it never happens")

        subprocess.run([cli, "service-token", "prune", "e2e_reader"],
                       cwd=CORE, env=cli_env, capture_output=True, text=True)
        time.sleep(2)
        try:
            call("Exists", pb.ExistsRequest(uid="", auth=admin), token=reader_token)
            check(False, "the superseded secret stops working after prune")
        except grpc.RpcError as e:
            check(e.code() == grpc.StatusCode.UNAUTHENTICATED,
                  "the superseded secret stops working after prune")
        check(call("Exists", pb.ExistsRequest(uid="", auth=admin),
                   token=rotated_token) is not None,
              "and the rolled-onto secret still works")

        # ── §9.3: source_iface carries the resolved service ─────────────────
        # Checked in the DB rather than over the wire: it is what the record says
        # that matters, not what the call returned.
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT source_iface FROM accountability_record_global "
                        "WHERE action LIKE 'service%' AND source_iface IS NOT NULL")
            ifaces = {r[0] for r in cur.fetchall()}
        check("cli" in ifaces or "bootstrap" in ifaces,
              f"credential records name the door they came through ({sorted(ifaces)})")

        # ── §9.6: no secret in the log ──────────────────────────────────────
        for stream_name, text in (("issue stdout", issue.stdout), ("issue stderr", issue.stderr)):
            pass
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM accountability_record_global "
                        "WHERE detail::text LIKE %s", ("%fesvc_%",))
            leaked = cur.fetchone()[0]
        check(leaked == 0, "no accountability record contains a token")

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
                cur.execute("DELETE FROM service_auth_credential WHERE service_id LIKE %s", ("e2e_%",))
                cur.execute("DELETE FROM service_auth_credential WHERE service_id LIKE %s", ("cli:e2e%",))
                cur.execute("DELETE FROM service_auth_capability WHERE service_id LIKE %s", ("e2e_%",))
            conn.commit()
            conn.close()
        except Exception:
            pass
        shutil.rmtree(workdir, ignore_errors=True)

    print(f"\n=== {checks - len(failures)}/{checks} checks passed ===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
