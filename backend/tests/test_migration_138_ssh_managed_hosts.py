"""Migration 138: ssh_managed_hosts registry + ssh_cas host-cert fields.

The migration must be idempotent (an install that already ran 138 re-runs on
every boot), must fill the three new ssh_cas columns on pre-existing rows
with the SPEC defaults, and must never drop the registry on downgrade.
"""
import importlib
import os
import sqlite3

import pytest

PG_URL = os.getenv('UCM_TEST_PG_URL')
TABLE = 'ssh_managed_hosts'


def _migration():
    return importlib.import_module('migrations.138_ssh_managed_hosts')


@pytest.fixture
def old_sqlite_db():
    """A database as it looked before 138: ssh_cas without the new columns."""
    conn = sqlite3.connect(':memory:')
    conn.execute("CREATE TABLE ssh_cas (id INTEGER PRIMARY KEY, descr TEXT, "
                 "ca_type TEXT, default_ttl INTEGER)")
    conn.execute("CREATE TABLE ssh_certificates (id INTEGER PRIMARY KEY, "
                 "ssh_ca_id INTEGER)")
    conn.execute("INSERT INTO ssh_cas VALUES (1, 'Old host CA', 'host', 86400)")
    conn.execute("INSERT INTO ssh_certificates VALUES (7, 1)")
    yield conn
    conn.close()


def _tables(conn):
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}


def _columns(conn, table):
    return {r[1]: r for r in conn.execute(f"PRAGMA table_info({table})")}


def test_creates_the_registry_and_widens_the_ca_table(old_sqlite_db):
    conn = old_sqlite_db
    _migration().upgrade(conn)
    assert TABLE in _tables(conn)
    cols = _columns(conn, 'ssh_cas')
    assert {'host_cert_ttl', 'renew_threshold_percent', 'krl_version'} <= set(cols)
    # pre-existing CA rows carry the SPEC defaults, not NULL
    row = conn.execute("SELECT host_cert_ttl, renew_threshold_percent, krl_version "
                       "FROM ssh_cas WHERE id = 1").fetchone()
    assert row == (2592000, 30, 0)


def test_runs_twice_without_damage(old_sqlite_db):
    conn = old_sqlite_db
    _migration().upgrade(conn)
    conn.execute(f"INSERT INTO {TABLE} (hostname, host_ca_id, status) "
                 "VALUES ('keepme.test', 1, 'active')")
    conn.commit()
    _migration().upgrade(conn)  # second boot: no table rebuild, no data loss
    assert conn.execute(f"SELECT hostname FROM {TABLE}").fetchall() == [('keepme.test',)]
    assert conn.execute("SELECT COUNT(*) FROM ssh_cas").fetchone() == (1,)


def test_registry_shape_matches_the_model(old_sqlite_db):
    conn = old_sqlite_db
    _migration().upgrade(conn)
    cols = set(_columns(conn, TABLE))
    model_required = {
        'hostname', 'host_ca_id', 'user_ca_id', 'token_hash', 'token_prefix',
        'bootstrap_hash', 'bootstrap_expires', 'public_key', 'principals',
        'current_cert_id', 'auto_renew', 'status',
        'last_seen_at', 'last_krl_sync_at', 'last_renew_at', 'last_ip', 'created_at',
    }
    assert model_required <= cols
    # host tokens are unique so a hash can never resolve to two hosts
    conn.execute(f"INSERT INTO {TABLE} (hostname, host_ca_id, token_hash) "
                 "VALUES ('a.test', 1, 'hash-a')")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(f"INSERT INTO {TABLE} (hostname, host_ca_id, token_hash) "
                     "VALUES ('b.test', 1, 'hash-a')")
    # hostname is unique too
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(f"INSERT INTO {TABLE} (hostname, host_ca_id) VALUES ('a.test', 1)")


def test_defaults_on_a_fresh_insert(old_sqlite_db):
    conn = old_sqlite_db
    _migration().upgrade(conn)
    conn.execute(f"INSERT INTO {TABLE} (hostname, host_ca_id) VALUES ('fresh.test', 1)")
    auto_renew, status, created = conn.execute(
        f"SELECT auto_renew, status, created_at FROM {TABLE}").fetchone()
    assert auto_renew == 1 and status == 'pending' and created  # spec: auto_renew on, pending


def test_fresh_install_schema_re_applies_cleanly(old_sqlite_db):
    """A brand-new install already has every column (create_all builds the
    current model); the migration still runs after it and must be a no-op."""
    conn = old_sqlite_db
    conn.execute("CREATE TABLE ssh_managed_hosts (id INTEGER PRIMARY KEY)")
    conn.execute("DROP TABLE ssh_cas")
    conn.execute("CREATE TABLE ssh_cas (id INTEGER PRIMARY KEY, descr TEXT, "
                 "ca_type TEXT, default_ttl INTEGER, host_cert_ttl INTEGER "
                 "NOT NULL DEFAULT 2592000, renew_threshold_percent INTEGER "
                 "NOT NULL DEFAULT 30, krl_version INTEGER NOT NULL DEFAULT 0)")
    _migration().upgrade(conn)  # must neither raise nor double-add anything
    assert TABLE in _tables(conn)
    cols = _columns(conn, 'ssh_cas')
    assert {'host_cert_ttl', 'renew_threshold_percent', 'krl_version'} <= set(cols)
    assert conn.execute("SELECT COUNT(*) FROM ssh_cas").fetchone() == (0,)


def test_downgrade_never_eats_enrollment_state(old_sqlite_db):
    conn = old_sqlite_db
    _migration().upgrade(conn)
    conn.execute(f"INSERT INTO {TABLE} (hostname, host_ca_id, status) "
                 "VALUES ('eaten.test', 1, 'active')")
    conn.commit()
    _migration().downgrade(conn)
    assert conn.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone() == (1,)


@pytest.mark.postgres
@pytest.mark.skipif(not PG_URL, reason='UCM_TEST_PG_URL not set')
def test_postgres_creates_and_widens_and_runs_twice():
    from sqlalchemy import create_engine, inspect, text

    schema = f"migtest_138_{os.getenv('PYTEST_XDIST_WORKER', 'main')}"
    engine = create_engine(PG_URL)
    conn = engine.connect()
    # A run interrupted before the final DROP leaves the scratch schema behind
    # and the CREATE TABLE below then dies with "relation ssh_cas already exists".
    conn.execute(text(f"DROP SCHEMA IF EXISTS {schema} CASCADE"))
    conn.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
    conn.execute(text(f"SET search_path TO {schema}"))
    conn.execute(text("CREATE TABLE ssh_cas (id SERIAL PRIMARY KEY, descr TEXT, "
                      "ca_type TEXT, default_ttl INTEGER)"))
    conn.execute(text("CREATE TABLE ssh_certificates (id SERIAL PRIMARY KEY, "
                      "ssh_ca_id INTEGER)"))
    conn.execute(text("INSERT INTO ssh_cas (descr, ca_type, default_ttl) "
                      "VALUES ('Old host CA', 'host', 86400) RETURNING id"))
    conn.commit()

    _migration().upgrade(conn)
    _migration().upgrade(conn)

    insp = inspect(conn)
    assert TABLE in insp.get_table_names()
    cols = {c['name'] for c in insp.get_columns('ssh_cas')}
    assert {'host_cert_ttl', 'renew_threshold_percent', 'krl_version'} <= cols
    row = conn.execute(text("SELECT host_cert_ttl, renew_threshold_percent, "
                            "krl_version FROM ssh_cas")).fetchone()
    assert tuple(row) == (2592000, 30, 0)
    conn.execute(text(f"DROP SCHEMA {schema} CASCADE"))
    conn.close()
