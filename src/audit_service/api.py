"""Audit query/export/verify HTTP API (§9), gated by AUDIT_READ (§8).

The audit_service owns the audit data + the hash chain, so it also serves the
read side. Every read is itself audited (audit_read / audit_export — "audit the
auditors", §8). No MCP surface (§13). The Phase-9 console (in ldap_manager)
consumes these endpoints.
"""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import StreamingResponse

from . import auth, db, queries
from .config import Config, load_dotenv
from .publisher import AuditPublisher
from .verify import verify_chain

log = logging.getLogger("audit_service.api")


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config()
    app = FastAPI(title="FileEngine Audit Query API", version="0.1.0")
    app.state.config = config
    app.state.publisher = None

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

    return app


def main() -> None:  # pragma: no cover
    import uvicorn

    logging.basicConfig(level=logging.INFO)
    load_dotenv()
    config = Config()
    uvicorn.run(create_app(config), host=config.api_host, port=config.api_port)
