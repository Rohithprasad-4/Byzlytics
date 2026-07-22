"""PostgreSQL connection pool and query execution helpers."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Generator, Iterable

import psycopg2
import psycopg2.extras
from psycopg2 import pool
from psycopg2.extensions import connection as PgConnection
from psycopg2.extensions import cursor as PgCursor

from backend.config import DatabaseConfig
from backend.exceptions import DatabaseError

logger = logging.getLogger(__name__)

_connection_pool: pool.ThreadedConnectionPool | None = None


def init_db_pool(db_config: DatabaseConfig) -> None:
    """Initialize the global threaded connection pool."""
    global _connection_pool
    if _connection_pool is not None:
        return

    try:
        _connection_pool = pool.ThreadedConnectionPool(
            minconn=db_config.min_connections,
            maxconn=db_config.max_connections,
            host=db_config.host,
            port=db_config.port,
            user=db_config.user,
            password=db_config.password,
            dbname=db_config.name,
        )
        logger.info("Database connection pool initialized.")
    except psycopg2.Error as exc:
        logger.exception("Failed to initialize database pool.")
        raise DatabaseError(f"Unable to connect to database: {exc}") from exc


def close_db_pool() -> None:
    """Close all pooled connections on application shutdown."""
    global _connection_pool
    if _connection_pool is not None:
        _connection_pool.closeall()
        _connection_pool = None
        logger.info("Database connection pool closed.")


@contextmanager
def get_connection() -> Generator[PgConnection, None, None]:
    """Borrow a connection from the pool and return it when done."""
    if _connection_pool is None:
        raise DatabaseError("Database pool is not initialized.")

    conn = None
    try:
        conn = _connection_pool.getconn()
        yield conn
    except psycopg2.Error as exc:
        if conn is not None:
            conn.rollback()
        logger.exception("Database connection error.")
        raise DatabaseError(str(exc)) from exc
    finally:
        if conn is not None:
            _connection_pool.putconn(conn)


@contextmanager
def get_cursor(*, dict_cursor: bool = True) -> Generator[PgCursor, None, None]:
    """Yield a cursor within a managed transaction (auto-commit on success)."""
    cursor_factory = psycopg2.extras.RealDictCursor if dict_cursor else None

    with get_connection() as conn:
        try:
            with conn.cursor(cursor_factory=cursor_factory) as cur:
                yield cur
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def fetch_one(query: str, params: Iterable[Any] | None = None) -> dict[str, Any] | None:
    """Execute a parameterized query and return a single row."""
    with get_cursor() as cur:
        cur.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None


def fetch_all(query: str, params: Iterable[Any] | None = None) -> list[dict[str, Any]]:
    """Execute a parameterized query and return all rows."""
    with get_cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(row) for row in rows]


def execute(query: str, params: Iterable[Any] | None = None) -> int:
    """Execute a write query and return affected row count."""
    with get_cursor() as cur:
        cur.execute(query, params)
        return cur.rowcount


def execute_returning(
    query: str, params: Iterable[Any] | None = None
) -> dict[str, Any] | None:
    """Execute INSERT/UPDATE ... RETURNING and return the row."""
    with get_cursor() as cur:
        cur.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None


def check_health() -> dict[str, Any]:
    """Verify database connectivity for the /health endpoint."""
    try:
        row = fetch_one("SELECT NOW() AS server_time, current_database() AS database_name")
        return {
            "database": "connected",
            "database_name": row["database_name"] if row else None,
            "server_time": row["server_time"].isoformat() if row else None,
        }
    except DatabaseError:
        return {"database": "disconnected"}
