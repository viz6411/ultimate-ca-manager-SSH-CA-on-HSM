"""Defect D6 — the SSH certificate validity window is stored as naive UTC.

`ssh_certificates.valid_from/valid_to` are `timestamp without time zone`. While
they were written as timezone-**aware** datetimes, PostgreSQL received them as
`timestamptz` and converted them into the server's TimeZone, so on a UTC+4 host
every signed and every imported host certificate read its window four hours
late — which moves `cert_status`, the renewal threshold, the delete guard and
the KRL's expiry rule. Both write sites now store naive UTC.

These tests pin the fix from the outside: the stored values must equal the
window the certificate itself carries (`valid_after`/`valid_before`), on SQLite
and on PostgreSQL, including on a session that is deliberately sitting in a
+04 timezone. The PostgreSQL half runs in the CI job that puts the application
on PostgreSQL (`scripts/ci/pg-app-tests.txt` lists this file through
`tests/test_ssh*.py`).

Uses the shared conftest fixtures: app, client, auth_client.
"""
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from models import db
from models.ssh import SSHCertificate, SSHManagedHost
from services.ssh_ca_service import SSHCAService
from services.ssh_cert import SSHCertificateService
from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json
from tests import pg_app_harness

UTC_PLUS_4 = 'Asia/Tbilisi'   # the D6 host: a +04 PostgreSQL re-read every window


def _uniq(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10]}.test.example.com"


def _naive_utc(epoch_seconds):
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).replace(tzinfo=None)


def _instant(value):
    """Parse an API timestamp to naive UTC. Accepts the 'Z' the admin API emits
    and the bare local-clock string the agent-facing enroll/renew responses
    emit (they use `cert.valid_to.isoformat()` — see the report, MINOR)."""
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed


def _window_of(cert_pem):
    """The validity window the signed certificate itself declares."""
    from cryptography.hazmat.primitives.serialization import load_ssh_public_identity
    signed = load_ssh_public_identity(cert_pem.encode())
    return signed.valid_after, signed.valid_before


def _reload(app, cert_id):
    """Read the row back from the database, not from the identity map."""
    with app.app_context():
        db.session.expire_all()
        return db.session.get(SSHCertificate, cert_id)


def _raw_columns(app, cert_id):
    """The stored wall clock, read as text: no driver or session timezone can
    change what `CAST(... AS TEXT)` prints for a timestamp-without-time-zone."""
    from sqlalchemy import text
    with app.app_context():
        row = db.session.execute(
            text("SELECT CAST(valid_from AS TEXT), CAST(valid_to AS TEXT) "
                 "FROM ssh_certificates WHERE id = :id"), {'id': cert_id}).first()
    return tuple(datetime.fromisoformat(v) for v in row)


# ── the property, on whatever backend this run uses ─────────────────────────

class TestStoredWindowMatchesTheCertificate:
    def test_a_signed_certificate_round_trips_to_its_own_window(self, app, auth_client):
        ca = _create_ssh_ca(auth_client, ca_type='host', descr='D6 host CA',
                            allow_any_principal=True)
        with app.app_context():
            cert = SSHCertificateService.sign_certificate(
                ca_id=ca['id'], public_key_data=_generate_test_ssh_key(),
                cert_type='host', principals=[_uniq('d6')], validity_seconds=86400,
                source='web', username='tester')
            cert_id, pem = cert.id, cert.certificate

        valid_after, valid_before = _window_of(pem)
        stored = _reload(app, cert_id)
        assert stored.valid_from == _naive_utc(valid_after)
        assert stored.valid_to == _naive_utc(valid_before)
        assert stored.valid_from.tzinfo is None and stored.valid_to.tzinfo is None
        assert _raw_columns(app, cert_id) == (stored.valid_from, stored.valid_to)

    def test_an_imported_certificate_is_stored_the_same_way(self, app, auth_client):
        """Export → delete → re-import (the path the import endpoint exists for).
        The serial guard means the original row has to be gone first, and a
        certificate is only deletable after its window has passed."""
        ca = _create_ssh_ca(auth_client, ca_type='user', descr='D6 import CA',
                            allow_any_principal=True)
        with app.app_context():
            signed = SSHCertificateService.sign_certificate(
                ca_id=ca['id'], public_key_data=_generate_test_ssh_key(),
                cert_type='user', principals=['import-me'], validity_seconds=3600,
                source='web', username='tester')
            pem, cert_id = signed.certificate, signed.id
            signed.valid_to = signed.valid_to - timedelta(days=2)   # now deletable
            db.session.commit()

        assert auth_client.delete(f'/api/v2/ssh/certificates/{cert_id}').status_code == 204

        with app.app_context():
            imported = SSHCertificateService.import_certificate(
                pem, descr='Re-imported', ssh_ca_id=ca['id'], username='tester')
            imported_id, imported_pem = imported.id, imported.certificate

        valid_after, valid_before = _window_of(imported_pem)
        stored = _reload(app, imported_id)
        assert stored.valid_from == _naive_utc(valid_after)
        assert stored.valid_to == _naive_utc(valid_before)
        assert stored.valid_from.tzinfo is None and stored.valid_to.tzinfo is None

    def test_the_api_reports_the_stored_window_as_utc(self, auth_client, client):
        ca = _create_ssh_ca(auth_client, ca_type='host', descr='D6 API host CA',
                            allow_any_principal=True)
        r = post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': ca['id'], 'public_key': _generate_test_ssh_key(), 'cert_type': 'host',
            'principals': [_uniq('d6api')], 'validity_seconds': 600})
        assert r.status_code == 201, r.data
        body = r.get_json()['data']
        valid_after, valid_before = _window_of(body['certificate'])
        assert body['valid_from'] == _naive_utc(valid_after).isoformat() + 'Z'
        assert body['valid_to'] == _naive_utc(valid_before).isoformat() + 'Z'
        got = auth_client.get(f"/api/v2/ssh/certificates/{body['id']}").get_json()['data']
        assert got['valid_from'] == body['valid_from'] and got['valid_to'] == body['valid_to']

    def test_the_managed_host_flow_stores_the_window_it_signed(self, app, auth_client,
                                                                client):
        ca = _create_ssh_ca(auth_client, ca_type='host', descr='D6 managed host CA',
                            allow_any_principal=True)
        name = _uniq('d6managed')
        r = post_json(auth_client, '/api/v2/ssh/hosts',
                      {'host_ca_id': ca['id'], 'hostname': name})
        bootstrap = r.get_json()['data']['bootstrap_token']
        r = client.post('/api/v2/ssh/hosts/enroll', data=json.dumps({
            'bootstrap_token': bootstrap, 'hostname': name,
            'public_key': _generate_test_ssh_key()}), content_type='application/json')
        assert r.status_code == 201, r.data
        pem = r.get_json()['data']['certificate']
        valid_after, valid_before = _window_of(pem)

        with app.app_context():
            db.session.expire_all()
            host = SSHManagedHost.query.filter_by(hostname=name).first()
            cert = host.current_cert
            assert cert.valid_from == _naive_utc(valid_after)
            assert cert.valid_to == _naive_utc(valid_before)
        row = next(h for h in auth_client.get(
                       f'/api/v2/ssh/hosts?search={name}&per_page=100').get_json()['data']
                   if h['hostname'] == name)
        assert row['cert_valid_to'] == _naive_utc(valid_before).isoformat() + 'Z'

    def test_the_renewed_certificate_carries_a_utc_window_too(self, app, auth_client, client):
        """Renewal goes through the same signing code, so it must not reintroduce
        an aware value."""
        ca = _create_ssh_ca(auth_client, ca_type='host', descr='D6 renew host CA',
                            allow_any_principal=True)
        name = _uniq('d6renew')
        bootstrap = post_json(auth_client, '/api/v2/ssh/hosts',
                              {'host_ca_id': ca['id'], 'hostname': name}
                              ).get_json()['data']['bootstrap_token']
        data = client.post('/api/v2/ssh/hosts/enroll', data=json.dumps({
            'bootstrap_token': bootstrap, 'hostname': name,
            'public_key': _generate_test_ssh_key()}), content_type='application/json'
        ).get_json()['data']
        r = client.post('/api/v2/ssh/hosts/renew', headers={'X-Host-Token': data['host_token']})
        assert r.status_code == 200, r.data
        renewed = r.get_json()['data']
        valid_after, valid_before = _window_of(renewed['certificate'])

        with app.app_context():
            db.session.expire_all()
            host = SSHManagedHost.query.filter_by(hostname=name).first()
            assert host.current_cert.valid_from == _naive_utc(valid_after)
            assert host.current_cert.valid_to == _naive_utc(valid_before)
        assert _instant(renewed['valid_to']) == _naive_utc(valid_before)


# ── the mechanism, on the backend where it actually bit ─────────────────────

@pytest.mark.skipif(not pg_app_harness.ENABLED,
                    reason='needs the application on PostgreSQL (UCM_TEST_APP_PG_URL)')
class TestPostgresTimeZoneCannotMoveTheWindow:
    def test_a_utc_four_session_stores_the_same_utc_window(self, app):
        from sqlalchemy import text

        with app.app_context():
            db.session.execute(text(f"SET SESSION TIME ZONE '{UTC_PLUS_4}'"))
            try:
                server_zone = db.session.execute(text("SHOW TIME ZONE")).scalar()
                assert 'Tbilisi' in server_zone or server_zone.endswith('+04')

                ca = SSHCAService.create_ca(descr='D6 +04 CA', ca_type='host',
                                            key_type='ed25519', username='tester',
                                            allow_any_principal=True)
                before = int(time.time())
                cert = SSHCertificateService.sign_certificate(
                    ca_id=ca.id, public_key_data=_generate_test_ssh_key(),
                    cert_type='host', principals=['plus-four.test'],
                    validity_seconds=2592000, source='agent', username='agent')
                cert_id, pem = cert.id, cert.certificate
                valid_after, valid_before = _window_of(pem)

                db.session.expire_all()
                stored = db.session.get(SSHCertificate, cert_id)
                assert stored.valid_from == _naive_utc(valid_after), (
                    stored.valid_from, _naive_utc(valid_after))
                assert stored.valid_to == _naive_utc(valid_before), (
                    stored.valid_to, _naive_utc(valid_before))
                # four hours late would be the old defect
                assert stored.valid_from != _naive_utc(valid_after) + timedelta(hours=4)
                # sanity: the window really starts at 'now', in naive UTC (a +04
                # write would land four hours ahead of the wall clock here)
                assert -5 <= (_naive_utc(before) - stored.valid_from).total_seconds() <= 400
            finally:
                db.session.execute(text("RESET TIME ZONE"))
                db.session.commit()

    def test_an_aware_value_would_have_landed_in_the_session_timezone(self, app):
        """Proof the guard tests something real: an aware datetime handed to a
        `timestamp without time zone` column is coerced through the *session*
        timezone. Set the session to a zone the cluster does not use (UTC+5) and
        the value lands five hours late — which is exactly what the fix stopped.
        (UTC+4 is the reported host; UTC+5 proves the shift follows the session.)"""
        from sqlalchemy import text

        aware = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        with app.app_context():
            db.session.execute(text("SET SESSION TIME ZONE 'Etc/GMT-5'"))
            try:
                assert db.session.execute(text("SHOW TIME ZONE")).scalar() == 'Etc/GMT-5'
                db.session.execute(text("CREATE TEMP TABLE d6_probe (ts TIMESTAMP)"))
                db.session.execute(text("INSERT INTO d6_probe VALUES (:v)"), {'v': aware})
                stored = db.session.execute(text("SELECT ts FROM d6_probe")).scalar()
                db.session.execute(text("DROP TABLE d6_probe"))
                db.session.commit()
            finally:
                db.session.execute(text("RESET TIME ZONE"))
                db.session.commit()

        assert stored == aware.replace(tzinfo=None) + timedelta(hours=5)
        assert stored != aware.replace(tzinfo=None)

    def test_the_managed_host_row_and_the_raw_column_agree_under_plus_four(self, app):
        from sqlalchemy import text

        with app.app_context():
            db.session.execute(text(f"SET SESSION TIME ZONE '{UTC_PLUS_4}'"))
            try:
                ca = SSHCAService.create_ca(descr='D6 +04 host CA', ca_type='host',
                                            key_type='ed25519', username='tester',
                                            allow_any_principal=True)
                cert = SSHCertificateService.sign_certificate(
                    ca_id=ca.id, public_key_data=_generate_test_ssh_key(),
                    cert_type='host', principals=['raw-column.test'],
                    validity_seconds=3600, source='agent', username='agent')
                cert_id = cert.id
                valid_after, valid_before = _window_of(cert.certificate)
                db.session.expire_all()
                stored = db.session.get(SSHCertificate, cert_id)
                stored_from, stored_to = stored.valid_from, stored.valid_to
                raw = tuple(db.session.execute(
                    text("SELECT CAST(valid_from AS TEXT), CAST(valid_to AS TEXT) "
                         "FROM ssh_certificates WHERE id = :i"), {'i': cert_id}).first())
            finally:
                db.session.execute(text("RESET TIME ZONE"))
                db.session.commit()

        assert stored_from == _naive_utc(valid_after)
        assert stored_to == _naive_utc(valid_before)
        assert tuple(datetime.fromisoformat(v) for v in raw) == (stored_from, stored_to)
