"""
SecureGate AI — Database seed and initialization utilities.

Creates the network_security database, applies schema/indexes, and optionally
loads development sample data for local testing.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

DATABASE_DIR = Path(__file__).resolve().parent
SCHEMA_FILE = DATABASE_DIR / "schema.sql"
INDEXES_FILE = DATABASE_DIR / "indexes.sql"


def get_connection_params() -> dict:
    """Load database connection parameters from environment with safe defaults."""
    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "user": os.getenv("DB_USER", "postgres"),
        "password": os.getenv("DB_PASSWORD", "postgres"),
        "dbname": os.getenv("DB_NAME", "network_security"),
    }


def connect(dbname: str | None = None, autocommit: bool = False):
    """Create a psycopg2 connection using parameterized config."""
    params = get_connection_params()
    if dbname is not None:
        params["dbname"] = dbname
    conn = psycopg2.connect(**params)
    if autocommit:
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    return conn


def database_exists(cursor, db_name: str) -> bool:
    """Check whether the target database already exists."""
    cursor.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s",
        (db_name,),
    )
    return cursor.fetchone() is not None


def create_database_if_missing(db_name: str) -> None:
    """Create PostgreSQL database if it does not exist."""
    conn = connect(dbname="postgres", autocommit=True)
    try:
        with conn.cursor() as cur:
            if database_exists(cur, db_name):
                logger.info("Database '%s' already exists.", db_name)
                return
            cur.execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db_name))
            )
            logger.info("Created database '%s'.", db_name)
    finally:
        conn.close()


def execute_sql_file(conn, file_path: Path) -> None:
    """Execute a SQL file against the connected database."""
    if not file_path.exists():
        raise FileNotFoundError(f"SQL file not found: {file_path}")

    sql_text = file_path.read_text(encoding="utf-8")
    with conn.cursor() as cur:
        cur.execute(sql_text)
    conn.commit()
    logger.info("Executed %s", file_path.name)


def seed_development_data(conn) -> None:
    """
    Insert minimal development seed data for dashboard and API testing.
    Safe to run multiple times — uses ON CONFLICT guards.
    """
    seed_sql = """
    INSERT INTO devices (ip_address, mac_address, device_type, is_trusted, hostname)
    VALUES
        ('192.168.1.10'::inet, '00:1A:2B:3C:4D:5E'::macaddr, 'workstation', TRUE, 'dev-workstation'),
        ('192.168.1.20'::inet, 'AA:BB:CC:DD:EE:FF'::macaddr, 'iot', FALSE, 'smart-sensor'),
        ('192.168.1.50'::inet, NULL, 'unknown', FALSE, NULL)
    ON CONFLICT (ip_address) DO NOTHING;

    INSERT INTO daily_summary (
        summary_date, total_devices, active_devices, total_events,
        dns_events, tcp_events, icmp_events,
        low_risk_count, medium_risk_count, high_risk_count,
        blocked_devices, blocked_requests, suspicious_devices, avg_risk_score,
        peak_hour, top_risky_ips, hourly_distribution, protocol_distribution
    )
    VALUES (
        CURRENT_DATE,
        3, 2, 0,
        0, 0, 0,
        0, 0, 0,
        0, 0, 0, 0.00,
        14,
        '[]'::jsonb,
        '{}'::jsonb,
        '{"DNS": 0, "TCP": 0, "ICMP": 0}'::jsonb
    )
    ON CONFLICT (summary_date) DO NOTHING;
    """
    with conn.cursor() as cur:
        cur.execute(seed_sql)
    conn.commit()
    logger.info("Development seed data applied.")


def initialize_schema(include_seed: bool = False) -> None:
    """Full database bootstrap: create DB, schema, indexes, optional seed."""
    params = get_connection_params()
    db_name = params["dbname"]

    create_database_if_missing(db_name)

    conn = connect(dbname=db_name)
    try:
        execute_sql_file(conn, SCHEMA_FILE)
        execute_sql_file(conn, INDEXES_FILE)
        if include_seed:
            seed_development_data(conn)
        logger.info("Database initialization complete.")
    except Exception:
        conn.rollback()
        logger.exception("Database initialization failed.")
        raise
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize SecureGate AI database.")
    parser.add_argument(
        "--seed",
        action="store_true",
        help="Load development seed data after schema creation.",
    )
    args = parser.parse_args()

    try:
        initialize_schema(include_seed=args.seed)
    except psycopg2.OperationalError as exc:
        logger.error(
            "Could not connect to PostgreSQL. Ensure the server is running and "
            ".env credentials are correct. Details: %s",
            exc,
        )
        return 1
    except Exception:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
