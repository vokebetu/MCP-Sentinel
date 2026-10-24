import os

from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


def database_url():
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    return make_conninfo(
        host=os.environ.get("POSTGRES_HOST", "db"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        dbname=os.environ.get("POSTGRES_DB", "mcp_sentinel"),
        user=os.environ.get("POSTGRES_USER", "sentinel"),
        password=os.environ.get("POSTGRES_PASSWORD", ""),
        application_name="mcp-sentinel-backend",
    )


pool = ConnectionPool(
    database_url(),
    min_size=1,
    max_size=int(os.environ.get("DB_POOL_SIZE", "5")),
    open=False,
    kwargs={"row_factory": dict_row, "autocommit": True, "options": "-c default_transaction_read_only=on -c statement_timeout=15000"},
)


def fetch_all(sql, params=None):
    with pool.connection(timeout=5) as conn:
        return conn.execute(sql, params or {}).fetchall()


def fetch_one(sql, params=None):
    with pool.connection(timeout=5) as conn:
        return conn.execute(sql, params or {}).fetchone()
