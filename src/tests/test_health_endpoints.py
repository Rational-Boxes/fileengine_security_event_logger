"""audit-api telemetry endpoints (/healthz, /readyz).

The cloud monitor scrapes every component uniformly, so audit-api exposes the
same surface as the sibling services: /healthz is always-200 liveness; /readyz
gates on the Postgres backing store and must return a well-formed 200/503
(never raise) regardless of DB reachability. The L2 monitoring allowlist also
applies to these routes.
"""
import os

from fastapi.testclient import TestClient

from audit_service.api import create_app


def test_healthz_ok():
    c = TestClient(create_app())
    r = c.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "audit-api"


def test_readyz_is_well_formed():
    # PG may or may not be reachable in the test env; readyz must still answer
    # with a 200/503 and a db check, never raise.
    c = TestClient(create_app())
    r = c.get("/readyz")
    assert r.status_code in (200, 503)
    assert "db" in r.json()["checks"]


def test_monitoring_allowlist_guards_health_routes():
    os.environ["FILEENGINE_MONITORING_ALLOW_IPS"] = "10.9.9.9"  # testclient not listed
    try:
        c = TestClient(create_app())
        assert c.get("/healthz").status_code == 403
        assert c.get("/readyz").status_code == 403
    finally:
        os.environ.pop("FILEENGINE_MONITORING_ALLOW_IPS", None)
