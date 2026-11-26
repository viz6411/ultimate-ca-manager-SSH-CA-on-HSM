"""Round-7 pins (reviewer round 5 close-out) for the SSH managed-host code.

1. `_revoke_host_certs` selects in SQL again: `public_key == <key material>`
   OR `public_key LIKE "<key material> %"`.
   - case B here: a certificate ROW that kept the .pub comment is still
     revoked (the LIKE half). case A (bare row, commented host key) is already
     pinned by `TestRevokeWithRealPubKeyFile` in tests/test_ssh_managed_hosts.py.
   - case C here: a host whose stored key is empty revokes NOTHING — neither
     its own certificates nor those of the other hosts of the same Host CA —
     on both the revoke path and the re-enroll/rotate path.
2. `POST /api/v2/ssh/hosts/enroll` refuses a public_key that is not a plain
   OpenSSH key line before anything is stored: host stays `pending`, no key,
   zero certificates, and the bootstrap token still works for a good enroll.
3. Same key material + different comment: no revocation cascade, `krl_version`
   unmoved, published KRL bytes identical. Genuine rotation (same comment,
   different base64): the old certificate IS revoked.
"""
import json
import uuid

import pytest

from models import db
from models.ssh import SSHCertificate, SSHManagedHost
from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json
from tests.test_ssh_managed_hosts import (
    SSH_EVENTS, _deliveries, _enroll, _host_row, _register, _uniq,
)


@pytest.fixture
def host_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='host', descr='v7 host CA',
                          allow_any_principal=True)


@pytest.fixture
def user_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='user', descr='v7 user CA',
                          allow_any_principal=True)


@pytest.fixture
def ssh_sink(app):
    """Endpoint subscribed to the six SSH events, so the revoke events of THIS
    test (and only them) can be counted."""
    from models import WebhookDelivery
    from services.webhook_service import WebhookEndpoint
    with app.app_context():
        ep = WebhookEndpoint(name=f'ssh-v7-sink-{uuid.uuid4().hex[:8]}',
                             url='https://example.invalid/hook',
                             events=json.dumps(SSH_EVENTS),
                             enabled=True)
        db.session.add(ep)
        db.session.commit()
        ep_id = ep.id
    yield ep_id
    with app.app_context():
        WebhookDelivery.query.filter_by(endpoint_id=ep_id).delete()
        endpoint = db.session.get(WebhookEndpoint, ep_id)
        if endpoint:
            db.session.delete(endpoint)
        db.session.commit()


def _certs(app, ca_id, revoked=None):
    with app.app_context():
        db.session.expire_all()
        q = SSHCertificate.query.filter_by(ssh_ca_id=ca_id, cert_type='host')
        if revoked is not None:
            q = q.filter_by(revoked=revoked)
        return q.all()


def _ca(auth_client, ca_id):
    return auth_client.get(f'/api/v2/ssh/cas/{ca_id}').get_json()['data']


class TestStoredCertificateShapes:
    """case B: the stored row carries the comment → the LIKE half must match."""

    def test_a_certificate_row_that_kept_the_pub_comment_is_still_revoked(
            self, app, auth_client, client, host_ca, user_ca):
        hostname = _uniq('storedcomment')
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=hostname)
        assert _enroll(auth_client, bootstrap, hostname=hostname,
                       public_key=f'{_generate_test_ssh_key()} root@{hostname}').status_code == 201
        cert_id = _host_row(auth_client, hostname)['cert_id']

        with app.app_context():
            cert = db.session.get(SSHCertificate, cert_id)
            stored = cert.public_key
            # the normal shape (case A): the row holds the key alone
            assert stored == ' '.join(stored.split()[:2]), f'unexpected stored shape: {stored!r}'
            # the shape under test: a row that kept the comment of the .pub line
            cert.public_key = f'{stored} old@host'
            db.session.commit()

        krl_before = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_before.status_code == 200
        krl_version_before = _ca(auth_client, host_ca['id']).get('krl_version') or 0

        r = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/revoke-cert",
                      {'reason': 'key compromise', 'revoke_certificate': True})
        assert r.status_code == 200, r.data
        assert r.get_json()['data']['status'] == 'revoked'

        moved = _certs(app, host_ca['id'], revoked=True)
        assert [c.id for c in moved] == [cert_id], \
            'the commented certificate row was not selected for revocation'
        assert moved[0].revoked_at is not None and moved[0].revoke_reason == 'key compromise'
        ca_after = _ca(auth_client, host_ca['id'])
        assert ca_after['krl_version'] == krl_version_before + 1, 'krl_version did not move'
        krl_after = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_after.status_code == 200
        assert krl_after.data != krl_before.data, 'the published KRL bytes never changed'


class TestEmptyHostKeyRevokesNothing:
    """case C: no key material on the host → no certificates of ANY host of the
    same Host CA may be revoked."""

    def test_revoke_and_rotate_of_a_host_without_a_public_key_touch_no_certificates(
            self, app, auth_client, client, host_ca, user_ca, ssh_sink):
        # three hosts under the same Host CA
        hosts, keys = {}, {}
        for tag in ('victim', 'other', 'blanked'):
            hostname = _uniq(f'nokey-{tag}')
            host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=hostname)
            assert _enroll(auth_client, bootstrap, hostname=hostname).status_code == 201
            hosts[tag] = (host['id'], hostname)
            keys[tag] = _host_row(auth_client, hostname)['cert_id']

        live_before = len(_certs(app, host_ca['id'], revoked=False))
        assert live_before == 3, live_before
        krl_before = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_before.status_code == 200
        krl_version_before = _ca(auth_client, host_ca['id']).get('krl_version') or 0

        with app.app_context():
            db.session.expire_all()
            db.session.get(SSHManagedHost, hosts['blanked'][0]).public_key = None
            db.session.commit()

        # the emergency revoke path
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{hosts['blanked'][0]}/revoke-cert",
                      {'reason': 'key compromise'})
        assert r.status_code == 200, r.data
        assert _certs(app, host_ca['id'], revoked=True) == [], \
            'a host with an empty public_key dragged certificates into the KRL'
        assert len(_certs(app, host_ca['id'], revoked=False)) == live_before
        assert _ca(auth_client, host_ca['id']).get('krl_version') == krl_version_before
        krl_after = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_after.data == krl_before.data, 'the KRL moved without any revoked certificate'
        events, _ = _deliveries(app, ssh_sink)
        assert 'ssh_certificate.revoked' not in events and 'ssh_ca.krl_updated' not in events, events
        assert 'ssh_host.revoked' in events

        # the re-enroll / rotate path of the same host
        with app.app_context():
            db.session.expire_all()
            host = db.session.get(SSHManagedHost, hosts['blanked'][0])
            host.status = SSHManagedHost.STATUS_ACTIVE
            db.session.commit()
        bootstrap = post_json(auth_client, f"/api/v2/ssh/hosts/{hosts['blanked'][0]}/bootstrap",
                              {}).get_json()['data']['bootstrap_token']
        assert _enroll(auth_client, bootstrap, hostname=hosts['blanked'][1]).status_code == 201
        assert _certs(app, host_ca['id'], revoked=True) == [], \
            're-enrolling a host with an empty stored key revoked someone else certificate'
        assert len(_certs(app, host_ca['id'], revoked=False)) == live_before + 1
        assert _ca(auth_client, host_ca['id']).get('krl_version') == krl_version_before


class TestEnrollRefusesUnusablePublicKey:
    def test_a_key_line_the_parser_cannot_use_is_refused_before_anything_is_stored(
            self, app, auth_client, host_ca, user_ca):
        hostname = _uniq('badkey')
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=hostname)
        bare = _generate_test_ssh_key()
        for bad in (f'from="10.0.0.1" {bare}', 'not-a-key-at-all'):
            r = _enroll(auth_client, bootstrap, hostname=hostname, public_key=bad)
            assert r.status_code >= 400, (bad, r.status_code, r.data)
            assert 'certificate' not in (r.get_json() or {}).get('data', {})

        row = _host_row(auth_client, hostname)
        assert row['status'] == 'pending', row
        with app.app_context():
            db.session.expire_all()
            host_row = db.session.get(SSHManagedHost, host['id'])
            assert not host_row.public_key, 'a rejected key was left on the host row'
            assert host_row.current_cert_id is None
            assert SSHCertificate.query.filter_by(
                ssh_ca_id=host_ca['id'], cert_type='host').count() == 0, \
                'a rejected enroll signed a certificate'

        good = _enroll(auth_client, bootstrap, hostname=hostname, public_key=bare)
        assert good.status_code == 201, good.data
        assert _host_row(auth_client, hostname)['status'] == 'active'


class TestSameKeyMaterialIsNotARotation:
    def test_the_same_key_with_another_comment_revokes_nothing(
            self, app, auth_client, client, host_ca, user_ca):
        hostname = _uniq('samekey')
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=hostname)
        key = _generate_test_ssh_key()
        assert _enroll(auth_client, bootstrap, hostname=hostname,
                       public_key=f'{key} root@{hostname}').status_code == 201
        first_cert = _host_row(auth_client, hostname)['cert_id']
        krl_before = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_before.status_code == 200
        krl_version_before = _ca(auth_client, host_ca['id']).get('krl_version') or 0

        bootstrap2 = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/bootstrap",
                               {}).get_json()['data']['bootstrap_token']
        assert _enroll(auth_client, bootstrap2, hostname=hostname,
                       public_key=f'{key} admin@otherhost.example').status_code == 201

        with app.app_context():
            db.session.expire_all()
            old = db.session.get(SSHCertificate, first_cert)
            assert old.revoked is False, \
                'a changed comment alone revoked a working host certificate'
            assert old.revoked_at is None
        assert _certs(app, host_ca['id'], revoked=True) == [], 'revocation cascade'
        assert len(_certs(app, host_ca['id'], revoked=False)) == 2
        assert _ca(auth_client, host_ca['id']).get('krl_version') == krl_version_before
        krl_after = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_after.data == krl_before.data, 'the KRL bytes moved without any revocation'

    def test_a_genuine_rotation_under_the_same_comment_revokes_the_old_cert(
            self, app, auth_client, client, host_ca, user_ca):
        hostname = _uniq('rotcomment')
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=hostname)
        comment = f'root@{hostname}'
        old_key = f'{_generate_test_ssh_key()} {comment}'
        assert _enroll(auth_client, bootstrap, hostname=hostname,
                       public_key=old_key).status_code == 201
        old_cert = _host_row(auth_client, hostname)['cert_id']
        krl_version_before = _ca(auth_client, host_ca['id']).get('krl_version') or 0

        bootstrap2 = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/bootstrap",
                               {}).get_json()['data']['bootstrap_token']
        new_key = f'{_generate_test_ssh_key()} {comment}'
        assert new_key.split()[1] != old_key.split()[1], 'the two keys must really differ'
        assert _enroll(auth_client, bootstrap2, hostname=hostname,
                       public_key=new_key).status_code == 201

        with app.app_context():
            db.session.expire_all()
            old = db.session.get(SSHCertificate, old_cert)
            assert old.revoked is True and old.revoked_at is not None, \
                'the certificate of the key the host threw away is still usable'
        live = _certs(app, host_ca['id'], revoked=False)
        assert len(live) == 1 and new_key.split()[1] in live[0].public_key, live
        assert _ca(auth_client, host_ca['id']).get('krl_version') == krl_version_before + 1
