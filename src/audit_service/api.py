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

"""Audit query/export/verify HTTP API (§9), gated by AUDIT_READ (§8).

The audit_service owns the audit data + the hash chain, so it also serves the
read side. Every read is itself audited (audit_read / audit_export — "audit the
auditors", §8). No MCP surface (§13). The Phase-9 console (in ldap_manager)
consumes these endpoints.
"""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse

import dataclasses

from . import auth, db, queries, security
from .config import Config, load_dotenv
from .engine import RulesEngine
from .publisher import AuditPublisher
from .rules import Rule
from .verify import verify_chain


class _Noop:
    """No-op store/notifier/enforcer for validate-against-history replays."""
    def record(self, *_a): ...
    def alert(self, *_a): ...
    def notify_admins_mandatory(self, *_a): ...
    def disable(self, *_a): ...

log = logging.getLogger("audit_service.api")

_VERSION = "0.1.0"


def _check_db(config) -> bool:
    """Readiness probe: the audit query API serves from Postgres, so it is ready
    iff a connection + trivial query succeeds. Blocking (psycopg) — run off the
    event loop."""
    try:
        conn = db.connect(config)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        finally:
            conn.close()
        return True
    except Exception as e:  # noqa: BLE001 — readiness must never raise
        log.warning("readyz db check failed: %s", e)
        return False


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config()
    app = FastAPI(title="FileEngine Audit Query API", version="0.1.0")
    app.state.config = config

    # Route-scoped IP allowlist for the unauthenticated monitoring endpoints
    # (security review L2). Endpoints already bind loopback; when
    # FILEENGINE_MONITORING_ALLOW_IPS is set (comma-separated client IPs), a
    # monitoring request from a non-listed address is refused with 403.
    import os as _os
    from fastapi.responses import JSONResponse as _JSONResponse
    _monitor_allow = {ip.strip() for ip in
                      _os.environ.get("FILEENGINE_MONITORING_ALLOW_IPS", "").split(",") if ip.strip()}

    @app.middleware("http")
    async def _guard_monitoring(request, call_next):
        if _monitor_allow and request.url.path in {"/healthz", "/readyz", "/poolz", "/metrics"}:
            client = request.client.host if request.client else ""
            if client not in _monitor_allow:
                return _JSONResponse({"error": "forbidden"}, status_code=403)
        return await call_next(request)
    app.state.publisher = None

    # ------------------------------- health --------------------------------
    # Same telemetry surface as the sibling services so the cloud monitor can
    # scrape every component uniformly. /healthz = liveness; /readyz gates on the
    # Postgres backing store the query API serves from.
    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "service": "audit-api", "version": _VERSION}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        checks = {"db": await run_in_threadpool(_check_db, config)}
        ready = all(checks.values())
        return JSONResponse(status_code=200 if ready else 503,
                            content={"ready": ready, "checks": checks})

    def identity(authorization: str | None = Header(default=None)) -> auth.Identity:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        try:
            return auth.verify_jwt(authorization.split(" ", 1)[1].strip(), config.jwt_secret)
        except auth.AuthError as e:
            raise HTTPException(status_code=401, detail=str(e))

    def require_read(tenant: str | None, ident: auth.Identity) -> None:
        if not auth.has_audit_read(ident, tenant, admin_role=config.admin_role,
                                   system_admin_role=config.system_admin_role):
            raise HTTPException(status_code=403, detail="AUDIT_READ required")

    def audit_the_auditors(action: str, ident: auth.Identity, tenant: str | None, detail: dict) -> None:
        try:
            if app.state.publisher is None:
                app.state.publisher = AuditPublisher.from_env()
            app.state.publisher.publish(
                category="admin", action=action, outcome="ok", actor=ident.user or "unknown",
                scope=("global" if tenant is None else "tenant"), tenant=tenant,
                source_iface="rest", detail=detail)
        except Exception:
            log.warning("failed to audit an audit read", exc_info=True)

    def _filters(actor, target_uid, category, action, outcome, from_ts, to_ts) -> dict:
        return {"actor": actor, "target_uid": target_uid, "category": category,
                "action": action, "outcome": outcome, "from_ts": from_ts, "to_ts": to_ts}

    @app.get("/v1/audit/query")
    def query_audit(tenant: str | None = Query(default=None), actor: str | None = None,
                    target_uid: str | None = None, category: str | None = None,
                    action: str | None = None, outcome: str | None = None,
                    from_ts: str | None = Query(default=None, alias="from"),
                    to_ts: str | None = Query(default=None, alias="to"),
                    page: int = 0, page_size: int = 100,
                    ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        page_size = max(1, min(page_size, config.query_max_page))
        filters = _filters(actor, target_uid, category, action, outcome, from_ts, to_ts)
        conn = db.connect(config)
        try:
            rows = queries.query(conn, tenant, filters, page=page, page_size=page_size)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        finally:
            conn.close()
        audit_the_auditors("audit_read", ident, tenant, {k: v for k, v in filters.items() if v})
        return {"rows": rows, "page": page, "page_size": page_size, "count": len(rows)}

    @app.get("/v1/audit/export")
    def export_audit(tenant: str | None = Query(default=None), actor: str | None = None,
                     target_uid: str | None = None, category: str | None = None,
                     action: str | None = None, outcome: str | None = None,
                     from_ts: str | None = Query(default=None, alias="from"),
                     to_ts: str | None = Query(default=None, alias="to"),
                     ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        filters = _filters(actor, target_uid, category, action, outcome, from_ts, to_ts)

        def stream():
            conn = db.connect(config)
            try:
                yield from queries.export_ndjson(conn, tenant, filters)
            finally:
                conn.close()

        audit_the_auditors("audit_export", ident, tenant, {k: v for k, v in filters.items() if v})
        return StreamingResponse(stream(), media_type="application/x-ndjson")

    @app.get("/v1/audit/verify")
    def verify_audit(tenant: str | None = Query(default=None),
                     ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        conn = db.connect(config)
        try:
            res = verify_chain(conn, tenant)
        finally:
            conn.close()
        return {"ok": res.ok, "checked": res.checked,
                "first_broken_seq": res.first_broken_seq, "reason": res.reason}

    # ---- security: incidents (§11) ----
    @app.get("/v1/security/incidents")
    def get_incidents(tenant: str | None = Query(default=None), status: str | None = None,
                      limit: int = 100, ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        conn = db.connect(config)
        try:
            security.ensure_tables(conn)
            rows = security.list_incidents(conn, tenant, status=status, limit=max(1, min(limit, 500)))
        finally:
            conn.close()
        return {"incidents": rows}

    @app.post("/v1/security/incidents/{incident_id}/status")
    def set_incident(incident_id: int, body: dict, tenant: str | None = Query(default=None),
                     ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        new_status = str(body.get("status", "acknowledged"))
        conn = db.connect(config)
        try:
            security.ensure_tables(conn)
            ok = security.set_incident_status(conn, incident_id, new_status)
        finally:
            conn.close()
        if not ok:
            raise HTTPException(status_code=404, detail="incident not found")
        audit_the_auditors("incident_status", ident, tenant, {"id": incident_id, "status": new_status})
        return {"ok": True}

    # ---- security: rules (the rule builder's backend, §11) ----
    @app.get("/v1/security/rules")
    def get_rules(tenant: str | None = Query(default=None), ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        store = security.RulesStore(lambda: db.connect(config))
        try:
            store.seed_defaults()  # ensure the global default pack exists
            effective = [dataclasses.asdict(r) for r in store.rules_for(tenant)]
            defaults = store.list_rules(security.GLOBAL)
            overrides = store.list_rules(tenant) if tenant else []
        finally:
            store.close()
        return {"effective": effective, "defaults": defaults, "overrides": overrides}

    @app.put("/v1/security/rules")
    def put_rule(body: dict, tenant: str | None = Query(default=None),
                 ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        try:
            Rule.from_dict(body)  # validate the DSL
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid rule: {e}")
        store = security.RulesStore(lambda: db.connect(config))
        try:
            store.upsert_rule(tenant or security.GLOBAL, body)
        finally:
            store.close()
        audit_the_auditors("rule_edit", ident, tenant, {"rule_id": body.get("id")})
        return {"ok": True}

    @app.delete("/v1/security/rules/{rule_id}")
    def delete_rule(rule_id: str, tenant: str | None = Query(default=None),
                    ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        store = security.RulesStore(lambda: db.connect(config))
        try:
            deleted = store.delete_rule(tenant or security.GLOBAL, rule_id)
        finally:
            store.close()
        if not deleted:
            raise HTTPException(status_code=404, detail="rule not found")
        audit_the_auditors("rule_delete", ident, tenant, {"rule_id": rule_id})
        return {"ok": True}

    @app.post("/v1/security/rules/validate")
    def validate_rule(body: dict, tenant: str | None = Query(default=None),
                      ident: auth.Identity = Depends(identity)):
        require_read(tenant, ident)
        try:
            rule = Rule.from_dict(body)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"invalid rule: {e}")
        filters = {"category": rule.category, "action": rule.action, "outcome": rule.outcome}
        conn = db.connect(config)
        try:
            events = queries.query_ascending(conn, tenant, filters, limit=5000)
        finally:
            conn.close()
        noop = _Noop()
        eng = RulesEngine([rule], store=noop, notifier=noop, enforcer=noop)
        fired = sum(len(eng.feed({**ev, "tenant": tenant})) for ev in events)
        return {"would_fire": fired, "events_examined": len(events)}

    # Prometheus scrape endpoint, guarded by the same allowlist as the other
    # monitoring routes. Reports process and per-thread state so a stuck or
    # leaking service is visible to the same scraper that watches the core.
    from . import metrics as _fe_metrics
    _fe_metrics.install(app, "audit_service", [], {"version": str("0.1.0")})

    return app


def main() -> None:  # pragma: no cover
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    config = Config()
    uvicorn.run(create_app(config), host=config.api_host, port=config.api_port)


if __name__ == "__main__":
    main()
