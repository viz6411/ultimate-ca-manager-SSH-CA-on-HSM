"""Migration 138 as an installed install gets it (checklist §1): the pull-model schema.

`db.create_all` builds `ssh_managed_hosts` from the model; a real install that
already has databases gets it from this migration instead. The two have to agree,
because every query the feature writes is written against the model. Run against a
scratch database the way an upgrade runs it: `upgrade(conn)` on tables that are
already there, twice, then look at what the database actually ended up with.

Uses no application fixtures on purpose — this is about the DDL.
"""
import importlib
import os
import sqlite3
import tempfile

import pytest

migration = importlib.import_module('migrations.138_ssh_managed_hosts')


@pytest.fixture
def installed_db():
    """A database as an existing install has it: the SSH tables, no host registry."""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("""CREATE TABLE ssh_cas (
        id INTEGER PRIMARY KEY AUTOINCREMENT, descr VARCHAR(255) NOT NULL)""")
    conn.execute("""CREATE TABLE ssh_certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ssh_ca_id INTEGER NOT NULL)""")
    conn.executemany("INSERT INTO ssh_cas (id, descr) VALUES (?, ?)",
                     [(1, 'host CA'), (2, 'other CA'), (7, 'deleting CA')])
    conn.execute("INSERT INTO ssh_certificates (id, ssh_ca_id) VALUES (9, 1)")
    conn.commit()
    yield conn
    conn.close()
    os.unlink(path)


def _tables(conn):
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _indexes(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA index_list({table})")}


def _indexed_columns(conn, table):
    """Every column any index on this table covers."""
    covered = set()
    for name in _indexes(conn, table):
        covered |= {r[2] for r in conn.execute(f"PRAGMA index_info({name})")}
    return covered


def _columns(conn, table):
    return {r[1]: (r[2], r[3], r[4]) for r in conn.execute(f"PRAGMA table_info({table})")}


class TestTheMigrationRunsOnAnExistingInstall:
    def test_it_creates_the_registry_and_extends_the_cas(self, installed_db):
        migration.upgrade(installed_db)
        assert 'ssh_managed_hosts' in _tables(installed_db)
        ca = _columns(installed_db, 'ssh_cas')
        for column, default in (('host_cert_ttl', '2592000'),      # 30 days, host CAs only
                                ('renew_threshold_percent', '30'),  # agent asks early at 30 %
                                ('krl_version', '0')):              # ETag source, bumped per revocation
            assert column in ca, column
            assert ca[column][2] == default, (column, ca[column])

    def test_running_it_twice_changes_nothing(self, installed_db):
        migration.upgrade(installed_db)
        before = (_columns(installed_db, 'ssh_managed_hosts'),
                  _columns(installed_db, 'ssh_cas'), _indexes(installed_db, 'ssh_managed_hosts'))
        migration.upgrade(installed_db)
        assert before == (_columns(installed_db, 'ssh_managed_hosts'),
                          _columns(installed_db, 'ssh_cas'),
                          _indexes(installed_db, 'ssh_managed_hosts'))

    def test_a_downgrade_never_loses_enrolled_hosts(self, installed_db):
        """The migration states it: no downgrade. Dropping the registry would
        erase the enrollment state and every host token with it."""
        migration.upgrade(installed_db)
        installed_db.execute("INSERT INTO ssh_managed_hosts (hostname, host_ca_id) "
                            "VALUES ('host-a.example.com', 1)")
        installed_db.commit()
        migration.downgrade(installed_db)
        assert 'host-a.example.com' in {r[0] for r in installed_db.execute(
            "SELECT hostname FROM ssh_managed_hosts")}


class TestTheSchemaTheFeatureReliesOn:
    def test_hostname_is_unique_and_a_pending_host_needs_no_token(self, installed_db):
        migration.upgrade(installed_db)
        installed_db.execute("INSERT INTO ssh_managed_hosts (hostname, host_ca_id) "
                            "VALUES ('dup.example.com', 1)")
        with pytest.raises(sqlite3.IntegrityError):
            installed_db.execute("INSERT INTO ssh_managed_hosts (hostname, host_ca_id) "
                                "VALUES ('dup.example.com', 2)")
        # Several pending hosts share token_hash NULL before their first enroll;
        # UNIQUE must not treat NULL as one value or registration would stall.
        installed_db.executemany("INSERT INTO ssh_managed_hosts (hostname, host_ca_id) "
                                 "VALUES (?, 1)", [('p1.example.com',), ('p2.example.com',)])
        installed_db.commit()
        rows = installed_db.execute("SELECT status, auto_renew FROM ssh_managed_hosts "
                                    "WHERE hostname LIKE 'p%'").fetchall()
        assert rows == [('pending', 1), ('pending', 1)]

    def test_two_hosts_cannot_share_one_host_token(self, installed_db):
        migration.upgrade(installed_db)
        installed_db.execute("INSERT INTO ssh_managed_hosts (hostname, host_ca_id, token_hash) "
                            "VALUES ('one.example.com', 1, 'x' || 'a'*63)")
        with pytest.raises(sqlite3.IntegrityError):
            installed_db.execute("INSERT INTO ssh_managed_hosts (hostname, host_ca_id, token_hash) "
                                 "VALUES ('two.example.com', 1, 'x' || 'a'*63)")

    def test_the_registry_cannot_outlive_its_ca_or_its_certificate(self, installed_db):
        migration.upgrade(installed_db)
        installed_db.execute("INSERT INTO ssh_managed_hosts (hostname, host_ca_id, current_cert_id) "
                            "VALUES ('orphan.example.com', 7, 9)")
        installed_db.commit()
        assert sorted(f[2] for f in installed_db.execute(
            "PRAGMA foreign_key_list(ssh_managed_hosts)")) == ['ssh_cas', 'ssh_cas',
                                                               'ssh_certificates']
        with pytest.raises(sqlite3.IntegrityError):
            installed_db.execute("DELETE FROM ssh_cas WHERE id = 7")
        with pytest.raises(sqlite3.IntegrityError):
            installed_db.execute("DELETE FROM ssh_certificates WHERE id = 9")

    def test_no_migration_index_backs_the_columns_the_feature_filters_on(self, installed_db):
        """Drift found while testing §1 (see the report): the model declares
        `index=True` on host_ca_id, user_ca_id and status — the CA delete guard
        filters by both CA columns and the UI list by status — but the migration
        DDL carries only the two UNIQUE constraints. A fresh install (built from
        the models) has those indexes, an upgraded install does not. Migrations
        130/132/134 name their indexes for exactly this reason; 138 does not.
        Fixing the migration means flipping this test, not deleting it."""
        migration.upgrade(installed_db)
        indexed = _indexed_columns(installed_db, 'ssh_managed_hosts')
        assert {'hostname', 'token_hash'} <= indexed
        assert not ({'host_ca_id', 'user_ca_id', 'status'} & indexed), indexed
