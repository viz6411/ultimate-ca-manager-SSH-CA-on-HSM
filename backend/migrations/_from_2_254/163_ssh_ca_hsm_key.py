"""Upgrade step 163: an HSM key backs one X.509 CA and one SSH CA at most; an SSH CA can keep its key on an HSM token.

``ssh_cas.key_source`` ('software' on every existing row) and ``ssh_cas.hsm_key_id`` (NULL),
a foreign key to ``hsm_keys.id``; the unique index ``uq_ssh_cas_hsm_key_id`` binds a key to
one SSH CA at most (NULLs stay distinct on both backends). A stock 2.254 has no HSM SSH CA: no row
moves; a 2.254 build that added the columns itself can already hold SSH CAs on keys.

``uq_ca_hsm_key_id`` does the same for X.509 CAs. 2.x created it (partial) only on the databases its
migration 035 upgraded: it is created, or replaced by the definition of a fresh install, on every one.
Two CAs on one key — two X.509, two SSH, or an X.509 CA and an SSH CA — refuse the upgrade before
migration 300 writes anything (``refusal``), naming them. The cross pair is not caught by any index:
2.254 builds without the 3.0 rule let one key sign an X.509 CA and an SSH CA.
Idempotent, dual-backend (SQLite + PostgreSQL).
"""
import logging
import sqlite3

logger = logging.getLogger(__name__)
pg_compatible = True

TABLE = 'ssh_cas'
INDEX = ('CREATE UNIQUE INDEX IF NOT EXISTS uq_ssh_cas_hsm_key_id '
         'ON ssh_cas (hsm_key_id)')
_COLUMNS = (
    ('key_source', "VARCHAR(20) NOT NULL DEFAULT 'software'"),
    ('hsm_key_id', 'INTEGER REFERENCES hsm_keys (id)'),
)

X509 = 'certificate_authorities'
X509_INDEX = 'uq_ca_hsm_key_id'
_X509_DDL = (f'DROP INDEX IF EXISTS {X509_INDEX}', f'CREATE UNIQUE INDEX {X509_INDEX} ON {X509} (hsm_key_id)')
_SHARED = (f"SELECT c.hsm_key_id, k.label, c.id, c.descr FROM {X509} c "
           f"LEFT JOIN hsm_keys k ON k.id = c.hsm_key_id "
           f"WHERE c.hsm_key_id IN (SELECT hsm_key_id FROM {X509} WHERE hsm_key_id IS NOT NULL "
           f"GROUP BY hsm_key_id HAVING COUNT(*) > 1) ORDER BY c.hsm_key_id, c.id")


# The same for ssh_cas, which 2.254 already has when a 2.254 build patched the columns in
# (an older UCM added them without the index): creating the index on such data would fail in the
# middle of the step. No join here: the CA names identify the pair, and ssh_cas is checked on
# databases whose hsm_keys shape is not known yet.
_SSH_SHARED = (f"SELECT c.hsm_key_id, NULL, c.id, c.descr FROM {TABLE} c "
               f"WHERE c.hsm_key_id IN (SELECT hsm_key_id FROM {TABLE} WHERE hsm_key_id IS NOT NULL "
               f"GROUP BY hsm_key_id HAVING COUNT(*) > 1) ORDER BY c.hsm_key_id, c.id")

# And the pair no unique index can see, because the two rows live in different tables: one key
# backing an X.509 CA and an SSH CA at once. 2.254 builds without the 3.0 rule offered exactly
# that ('a key already signing an X.509 CA can sign SSH certificates too'), and a restore refuses
# the same shape, so the upgrade has to name it too.
_CROSS = (f"SELECT c.hsm_key_id, k.label, c.descr, c.id, s.descr, s.id FROM {X509} c "
          f"JOIN {TABLE} s ON s.hsm_key_id = c.hsm_key_id "
          f"LEFT JOIN hsm_keys k ON k.id = c.hsm_key_id WHERE c.hsm_key_id IS NOT NULL "
          f"ORDER BY c.hsm_key_id, c.id, s.id")


def _key_name(key_id, label):
    return f"HSM key '{label}' (#{key_id})" if label else f"HSM key #{key_id}"


def _named(rows, kind):
    """One sentence per key: which CAs share it. 'SSH CAs' / 'X.509 CAs' is the kind being named."""
    keys = {}
    for key_id, label, ca_id, descr in rows:
        keys.setdefault((key_id, label), []).append(f"'{descr}' (#{ca_id})")
    return [f"{_key_name(key_id, label)} backs {len(cas)} {kind}: {', '.join(cas)}"
            for (key_id, label), cas in keys.items()]


def _named_cross(rows):
    """One sentence per key that backs an X.509 CA and an SSH CA at once."""
    return [f"{_key_name(key_id, label)} backs the X.509 CA '{x509}' (#{x509_id}) and the SSH CA "
            f"'{ssh}' (#{ssh_id})" for key_id, label, x509, x509_id, ssh, ssh_id in rows]


def _refusal(named):
    return (f"Upgrade refused: {named}. An HSM key backs one CA only: start 2.254 again, keep one CA on "
            f"each key and delete the others, then upgrade. Nothing was changed: 2.254 still starts on "
            f"this database.")


def _tables(conn):
    if isinstance(conn, sqlite3.Connection):
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    from sqlalchemy import inspect
    return set(inspect(conn).get_table_names())


def _columns(conn, table):
    if isinstance(conn, sqlite3.Connection):
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    from sqlalchemy import inspect
    return {c['name'] for c in inspect(conn).get_columns(table)}


def _rows(conn, sql):
    if isinstance(conn, sqlite3.Connection):
        return conn.execute(sql).fetchall()
    from sqlalchemy import text
    return [tuple(r) for r in conn.execute(text(sql))]


def refusal(conn):
    """The message that stops the upgrade when one HSM key backs two CAs, else None. Reads only.

    Three shapes are checked: two X.509 CAs on one key; two SSH CAs on one key, which matters when
    its hsm_key_id column is already there (2.254 builds that patched the columns in left it without
    the index, and creating the index on such data would fail in the middle of the step); and one
    X.509 CA and one SSH CA on the same key, which no unique index covers."""
    tables = _tables(conn)
    if 'hsm_keys' not in tables:
        return None
    named = []
    ssh_bound = TABLE in tables and 'hsm_key_id' in _columns(conn, TABLE)
    if X509 in tables:
        named += _named(_rows(conn, _SHARED), 'X.509 CAs')
    if ssh_bound:
        named += _named(_rows(conn, _SSH_SHARED), 'SSH CAs')
    if X509 in tables and ssh_bound:
        named += _named_cross(_rows(conn, _CROSS))
    return _refusal('; '.join(named)) if named else None


def _upgrade_sqlite(conn):
    tables = _tables(conn)
    if TABLE not in tables and X509 not in tables:
        logger.info("163: no ssh_cas table, nothing to do (SQLite)")
        return
    message = refusal(conn)
    if message:
        raise RuntimeError(message)
    if TABLE in tables:
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({TABLE})")}
        for name, ddl in _COLUMNS:
            if name not in columns:
                conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN {name} {ddl}")
        conn.execute(INDEX)
    if X509 in tables:
        for ddl in _X509_DDL:
            conn.execute(ddl)
    conn.commit()
    logger.info("163: one CA per HSM key, ssh_cas can name one (SQLite)")


def _upgrade_pg(conn):
    from sqlalchemy import inspect, text
    tables = _tables(conn)
    if TABLE not in tables and X509 not in tables:
        logger.info("163: no ssh_cas table, nothing to do (PostgreSQL)")
        return
    message = refusal(conn)
    if message:
        raise RuntimeError(message)
    if TABLE in tables:
        columns = {c['name'] for c in inspect(conn).get_columns(TABLE)}
        for name, ddl in _COLUMNS:
            if name not in columns:
                conn.execute(text(f"ALTER TABLE {TABLE} ADD COLUMN {name} {ddl}"))
        conn.execute(text(INDEX))
    if X509 in tables:
        for ddl in _X509_DDL:
            conn.execute(text(ddl))
    logger.info("163: one CA per HSM key, ssh_cas can name one (PostgreSQL)")


def upgrade(conn):
    if isinstance(conn, sqlite3.Connection):
        _upgrade_sqlite(conn)
    else:
        _upgrade_pg(conn)


def downgrade(conn):
    """No downgrade: 2.254 never reads the two columns, and keeps the index of its migration 035."""
    pass
