"""Postgres connection pool."""
from psycopg_pool import ConnectionPool

from .config import config

# Lazy: pool is created on first use, so config validation happens at app start
_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(config.db_dsn, min_size=1, max_size=10, open=True)
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None
