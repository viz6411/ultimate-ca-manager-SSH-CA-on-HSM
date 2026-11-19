"""Migration 301: SSH CA deployment bindings, and a certificate's deploy target.

``ssh_ca_deploy_bindings`` says what UCM writes on one deploy target for one SSH CA
(its public key, the KRL, the host certificate signed for that target) and with what
parameters. ``ssh_certificates.deploy_target_id`` records which target a host
certificate was issued for: the link a later release needs to reissue it there.

Adds only: a table, a nullable column, indexes. Nothing 3.0 reads or writes is
touched, so an HA cluster keeps running node by node (CONTRIBUTING.md,
"Migrations and rolling updates"). Idempotent on both backends: SQLite commits as
it goes, so a start after an interruption runs it again and lands in the same state.
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

TABLE = 'ssh_ca_deploy_bindings'
TABLE_DDL = (
    f"CREATE TABLE IF NOT EXISTS {TABLE} ("
    "id {serial} PRIMARY KEY, target_id INTEGER NOT NULL, ssh_ca_id INTEGER NOT NULL, "
    "ca_pub_path VARCHAR(512), krl_path VARCHAR(512), host_cert_path VARCHAR(512), "
    "validity INTEGER, principals TEXT, key_id_template VARCHAR(512), host_public_key TEXT, "
    "reload_command VARCHAR(512), enabled BOOLEAN NOT NULL, "
    "created_at {timestamp}, created_by VARCHAR(80), "
    "CONSTRAINT uq_ssh_ca_deploy_binding UNIQUE (target_id, ssh_ca_id), "
    "CONSTRAINT fk_ssh_ca_deploy_binding_target FOREIGN KEY (target_id) REFERENCES deploy_targets (id), "
    "CONSTRAINT fk_ssh_ca_deploy_binding_ca FOREIGN KEY (ssh_ca_id) REFERENCES ssh_cas (id))"
)
INDEXES = (
    f"CREATE INDEX IF NOT EXISTS ix_{TABLE}_target_id ON {TABLE} (target_id)",
    f"CREATE INDEX IF NOT EXISTS ix_{TABLE}_ssh_ca_id ON {TABLE} (ssh_ca_id)",
)
CERT_TABLE = 'ssh_certificates'
CERT_COLUMN = 'deploy_target_id'
CERT_DDL = (f"ALTER TABLE {CERT_TABLE} ADD COLUMN {CERT_COLUMN} INTEGER "
            f"REFERENCES deploy_targets (id)")
CERT_INDEX = f"CREATE INDEX IF NOT EXISTS ix_{CERT_TABLE}_{CERT_COLUMN} ON {CERT_TABLE} ({CERT_COLUMN})"


def _columns(conn):
    """Column names of ``ssh_certificates``, as the backend sees them."""
    if isinstance(conn, sqlite3.Connection):
        return {row[1] for row in conn.execute(f"PRAGMA table_info({CERT_TABLE})")}
    from sqlalchemy import inspect
    return {c['name'] for c in inspect(conn).get_columns(CERT_TABLE)}


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        conn.execute(TABLE_DDL.format(serial='INTEGER', timestamp='DATETIME'))
        for statement in INDEXES:
            conn.execute(statement)
        if CERT_TABLE not in {row[0] for row in
                              conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}:
            conn.commit()
            logger.info("[301] a database without ssh_certificates: nothing to add the link to")
            return
        if CERT_COLUMN not in _columns(conn):
            conn.execute(CERT_DDL)
        conn.execute(CERT_INDEX)
        conn.commit()
        logger.info("[301] ssh_ca_deploy_bindings and ssh_certificates.deploy_target_id (SQLite)")
        return

    from sqlalchemy import inspect, text
    if CERT_TABLE not in inspect(conn).get_table_names():
        logger.info("[301] a database without ssh_certificates: nothing to add the link to")
        return
    # SERIAL, not INTEGER: on PostgreSQL only SERIAL lands the sequence and its nextval
    # default that create_all gives a fresh install, and a binding INSERT needs it
    conn.execute(text(TABLE_DDL.format(serial='SERIAL', timestamp='TIMESTAMP WITHOUT TIME ZONE')))
    for statement in INDEXES:
        conn.execute(text(statement))
    if CERT_COLUMN not in _columns(conn):
        conn.execute(text(CERT_DDL))
    conn.execute(text(CERT_INDEX))
    logger.info("[301] ssh_ca_deploy_bindings and ssh_certificates.deploy_target_id (PostgreSQL)")


def downgrade(conn):
    """No downgrade: an unused table and an unused nullable column are harmless to 3.0."""
    pass
