"""Migration 301: Public SSH KRL version counter.

Adds ``krl_version`` to ``ssh_cas``, incremented on every SSH certificate
revocation so pull-based KRL sync clients can cheaply detect a fresh KRL via
ETag / If-None-Match on ``/ssh/krl/<refid>``.
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

TABLE = 'ssh_cas'
COLUMN = 'krl_version'


def _upgrade_sqlite(conn):
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (TABLE,)).fetchone() is None:
        return
    present = {row[1] for row in conn.execute(f"PRAGMA table_info({TABLE})")}
    if COLUMN not in present:
        conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN {COLUMN} INTEGER NOT NULL DEFAULT 0")
        conn.commit()
    logger.info("[301] ssh_cas.krl_version (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    if TABLE not in set(inspector.get_table_names()):
        return
    present = {c['name'] for c in inspector.get_columns(TABLE)}
    if COLUMN not in present:
        conn.execute(text(f"ALTER TABLE {TABLE} ADD COLUMN {COLUMN} INTEGER NOT NULL DEFAULT 0"))
    logger.info("[301] ssh_cas.krl_version (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    pass
