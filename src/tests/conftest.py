"""Shared fixtures. Live fixtures skip (never fail) when Redis/Postgres are not
reachable, so the pure unit tests always run and the integration tests light up
only where the brokers exist — matching the repo's "configurable to the
environment" test policy. Point them with the standard FILEENGINE_* env vars.
"""
from __future__ import annotations

import os

import pytest

from audit_service.config import Config, load_dotenv
from audit_service.naming import schema_for_tenant

# The per-tenant audit_log DDL, kept identical to
# file_engine_core/core/src/database.cpp::create_tenant_schema so the writer is
# tested against the real production table shape.
AUDIT_LOG_DDL = """
CREATE TABLE IF NOT EXISTS "{schema}".audit_log (
    seq          BIGSERIAL,
    event_id     UUID         NOT NULL,
    ts           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    category     SMALLINT     NOT NULL,
    action       VARCHAR(32)  NOT NULL,
    outcome      SMALLINT     NOT NULL,
    actor        VARCHAR(255) NOT NULL,
    actor_roles  TEXT,
    target_uid   VARCHAR(64),
    target_name  VARCHAR(1024),
    target_type  SMALLINT,
    detail       JSONB,
    source_iface VARCHAR(16),
    source_addr  VARCHAR(64),
    request_id   VARCHAR(64),
    prev_hash    BYTEA,
    row_hash     BYTEA,
    PRIMARY KEY (seq, ts),
    UNIQUE (event_id, ts)
) PARTITION BY RANGE (ts);
"""


@pytest.fixture(scope="session", autouse=True)
def _dotenv():
    load_dotenv()


@pytest.fixture()
def config():
    return Config()


@pytest.fixture()
def pg_conn(config):
    from audit_service import db
    try:
        conn = db.connect(config)
    except Exception as e:  # psycopg.OperationalError etc.
        pytest.skip(f"Postgres not reachable: {e}")
    yield conn
    try:
        conn.close()
    except Exception:
        pass


@pytest.fixture()
def audit_schema(pg_conn):
    """Create a throwaway tenant schema with a real audit_log, yield the tenant
    id, and drop the schema afterward."""
    tenant = f"audit_it_{os.getpid()}"
    schema = schema_for_tenant(tenant)
    with pg_conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        cur.execute(f'CREATE SCHEMA "{schema}"')
        cur.execute(AUDIT_LOG_DDL.format(schema=schema))
    pg_conn.commit()
    yield tenant
    with pg_conn.cursor() as cur:
        cur.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    pg_conn.commit()


@pytest.fixture()
def redis_client(config):
    import redis
    try:
        r = redis.Redis(host=config.redis_host, port=config.redis_port,
                        password=config.redis_password or None, db=config.redis_db,
                        socket_connect_timeout=3)
        r.ping()
    except Exception as e:
        pytest.skip(f"Redis not reachable: {e}")
    return r
