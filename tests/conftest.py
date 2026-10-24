import os
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "data" / "seed"
sys.path.insert(0, str(ROOT / "scripts"))


def admin_url():
    return os.environ.get("TEST_DATABASE_ADMIN_URL")


def run_script(name, url, *args):
    env = {**os.environ, "DATABASE_URL": url}
    return subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / name), *args], env=env, cwd=ROOT, check=True, capture_output=True, text=True)


@pytest.fixture(scope="session")
def seed_database_url():
    admin = admin_url()
    if not admin:
        pytest.skip("set TEST_DATABASE_ADMIN_URL to a PostgreSQL 17 server to run database tests")
    name = f"mcp_sentinel_test_{uuid.uuid4().hex[:8]}"
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    url = make_conninfo(**{**conninfo_to_dict(admin), "dbname": name})
    try:
        run_script("import_registry.py", url, "--bundle", str(SEED))
        run_script("import_enrichment.py", url, "--bundle", str(SEED))
        yield url
    finally:
        with psycopg.connect(admin, autocommit=True) as conn:
            conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture()
def db(seed_database_url):
    with psycopg.connect(seed_database_url) as conn:
        yield conn
