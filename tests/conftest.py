"""Shared test fixtures: stack-up check, DB connection helper."""
import os
import subprocess
import time

import psycopg
import pytest
import requests

CONTROL_PLANE = os.environ.get("CP_URL", "http://localhost:18080")
WEB_APP = os.environ.get("WEB_URL", "http://localhost:13000")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "54321"))
DB_NAME = os.environ.get("DB_NAME", "identity")
APP_DB_PASSWORD = os.environ.get("APP_DB_PASSWORD", "app_session_pw")

WEB_APP_CLIENT_SECRET = os.environ.get("WEB_APP_CLIENT_SECRET", "web_app_client_secret_change_me")
ETL_AGENT_SECRET = os.environ.get("ETL_AGENT_SECRET", "agent_etl_secret_change_me")


def get_db_conn():
    return psycopg.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user="app_session", password=APP_DB_PASSWORD,
    )


def get_cp_admin_conn():
    return psycopg.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user="control_plane_admin", password=os.environ.get("CONTROL_PLANE_DB_PASSWORD", "cp_admin_pw"),
    )


@pytest.fixture(scope="session", autouse=True)
def wait_for_stack():
    """Wait for all services to be healthy before any test runs."""
    for name, url in [("control-plane", f"{CONTROL_PLANE}/health"), ("web-app", f"{WEB_APP}/health")]:
        for attempt in range(30):
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    break
            except requests.RequestException:
                pass
            time.sleep(1)
        else:
            pytest.fail(f"{name} did not become healthy at {url}")


@pytest.fixture
def db():
    """Fresh DB connection per test, rolled back at the end."""
    conn = get_db_conn()
    yield conn
    conn.close()


@pytest.fixture
def cp_admin_db():
    conn = get_cp_admin_conn()
    yield conn
    conn.close()
