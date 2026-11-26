"""Migration 302: SSH managed hosts (SPEC_SSH_HOSTS_AND_KRL_AUTOMATION).

Creates ``ssh_managed_hosts`` — the pull-model registry of servers that run
``ucm-ssh-agent``: their host-certificate CA, their user-CA for KRL rollout,
the hashed host token and bootstrap token, the fixed principals and the
lifecycle status (pending/active/revoked).

Extends ``ssh_cas`` with host-certificate lifecycle fields used only by host
CAs (``host_cert_ttl`` default 30 days — isolated from the day-short user
``default_ttl`` — and ``renew_threshold_percent``) plus ``krl_version``, a
counter bumped on every SSH revocation so agents can cheaply detect a fresh
KRL (the ETag source of the pull-only ``/ssh/krl/<refid>`` endpoint).
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

TABLE = 'ssh_managed_hosts'

HOSTS_SQLITE = f"""
CREATE TABLE {TABLE} (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname VARCHAR(255) NOT NULL UNIQUE,
    host_ca_id INTEGER REFERENCES ssh_cas(id),
    user_ca_id INTEGER REFERENCES ssh_cas(id),
    token_hash VARCHAR(64) UNIQUE,
    token_prefix VARCHAR(16),
    bootstrap_hash VARCHAR(64),
    bootstrap_expires DATETIME,
    public_key TEXT,
    principals TEXT,
    current_cert_id INTEGER REFERENCES ssh_certificates(id),
    auto_renew BOOLEAN NOT NULL DEFAULT 1,
    status VARCHAR(10) NOT NULL DEFAULT 'pending',
    host_cert_ttl INTEGER,
    renew_threshold_percent INTEGER,
    config_synced BOOLEAN NOT NULL DEFAULT 1,
    last_seen_at DATETIME,
    last_krl_sync_at DATETIME,
    last_renew_at DATETIME,
    last_ip VARCHAR(45),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)
"""

CA_COLS = [
    ('host_cert_ttl', 'INTEGER NOT NULL DEFAULT 2592000'),
    ('renew_threshold_percent', 'INTEGER NOT NULL DEFAULT 30'),
]


def _upgrade_sqlite(conn):
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (TABLE,)).fetchone() is None:
        conn.execute(HOSTS_SQLITE)
    else:
        hcols = {row[1] for row in conn.execute(f"PRAGMA table_info({TABLE})")}
        for col, decl in [
            ('host_cert_ttl', 'INTEGER'),
            ('renew_threshold_percent', 'INTEGER'),
            ('config_synced', 'BOOLEAN NOT NULL DEFAULT 1'),
        ]:
            if col not in hcols:
                conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN {col} {decl}")
    conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_bootstrap_hash ON {TABLE}(bootstrap_hash)")
    present = {row[1] for row in conn.execute("PRAGMA table_info(ssh_cas)")}
    for col, decl in CA_COLS:
        if col not in present:
            conn.execute(f"ALTER TABLE ssh_cas ADD COLUMN {col} {decl}")
    conn.commit()
    logger.info("[138] ssh_managed_hosts + ssh_cas host-cert fields (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text

    inspector = inspect(conn)
    tables = set(inspector.get_table_names())
    if TABLE not in tables:
        conn.execute(text(f"""
            CREATE TABLE {TABLE} (
                id SERIAL PRIMARY KEY,
                hostname VARCHAR(255) NOT NULL UNIQUE,
                host_ca_id INTEGER REFERENCES ssh_cas(id),
                user_ca_id INTEGER REFERENCES ssh_cas(id),
                token_hash VARCHAR(64) UNIQUE,
                token_prefix VARCHAR(16),
                bootstrap_hash VARCHAR(64),
                bootstrap_expires TIMESTAMP,
                public_key TEXT,
                principals TEXT,
                current_cert_id INTEGER REFERENCES ssh_certificates(id),
                auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
                status VARCHAR(10) NOT NULL DEFAULT 'pending',
                host_cert_ttl INTEGER,
                renew_threshold_percent INTEGER,
                config_synced BOOLEAN NOT NULL DEFAULT TRUE,
                last_seen_at TIMESTAMP,
                last_krl_sync_at TIMESTAMP,
                last_renew_at TIMESTAMP,
                last_ip VARCHAR(45),
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """))
    else:
        hcols = {c['name'] for c in inspector.get_columns(TABLE)}
        for col, decl in [
            ('host_cert_ttl', 'INTEGER'),
            ('renew_threshold_percent', 'INTEGER'),
            ('config_synced', 'BOOLEAN NOT NULL DEFAULT TRUE'),
        ]:
            if col not in hcols:
                conn.execute(text(f"ALTER TABLE {TABLE} ADD COLUMN {col} {decl}"))
    conn.execute(text(f"CREATE INDEX IF NOT EXISTS idx_{TABLE}_bootstrap_hash ON {TABLE}(bootstrap_hash)"))
    present = {c['name'] for c in inspector.get_columns('ssh_cas')}
    for col, decl in CA_COLS:
        if col not in present:
            conn.execute(text(f"ALTER TABLE ssh_cas ADD COLUMN {col} "
                              f"{decl.replace('2592000', '2592000')}"))
    logger.info("[138] ssh_managed_hosts + ssh_cas host-cert fields (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    """No downgrade: dropping the registry would erase host enrollment state."""
    pass
