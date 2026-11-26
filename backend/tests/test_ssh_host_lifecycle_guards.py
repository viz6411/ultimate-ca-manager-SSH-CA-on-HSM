"""Managed-host lifecycle guards and the renewal cadence (issue #451).

Independent coverage of what the pre-release checklist claims (§6, §5, §10) and
does not prove anywhere in the suite:

- §6 "Host CA without principal policy": a CA **policy** refusal rolls the whole
  enroll back — host stays pending, the bootstrap token survives, no serial is
  burned — and where that rollback stops working (a re-enroll whose cascade
  already committed the revocations);
- an operational signing failure keeps the host enrolled so check-in → renew can
  recover, and which failure does not behave that way;
- §6 "Revoke certificate": the cascade covers every unexpired certificate of the
  host key, not just the current one, and a host that rotated its key loses the
  certificates signed for the key it threw away;
- §6 delete guard, rotate-token guard, deleting a CA that live hosts point at,
  deleting the host's current certificate;
- §10 the renewal cadence is the agent's: the server has no idempotency
  threshold, only the per-route limits — and UCM's default LAN trust exempts
  exactly the network the managed hosts live on.

Uses the shared conftest fixtures: app, client, auth_client.
"""
import json
import uuid
from datetime import timedelta

import pytest

from models import db
from models.ssh import SSHCertificate, SSHManagedHost
from services.ssh_ca_service import SSHCAService
from services.ssh_cert.utils import SSHCertificateUtilsMixin
from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json
from utils.datetime_utils import utc_now


def _uniq(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10]}.test.example.com"


def _register(auth_client, host_ca_id, user_ca_id=None, hostname=None):
    r = post_json(auth_client, '/api/v2/ssh/hosts', {
        'host_ca_id': host_ca_id, 'user_ca_id': user_ca_id, 'hostname': hostname})
    assert r.status_code == 201, r.data
    data = r.get_json()['data']
    return data['host'], data['bootstrap_token']


def _enroll(client, bootstrap, hostname, public_key=None, principals=None):
    body = {'bootstrap_token': bootstrap, 'hostname': hostname,
            'public_key': public_key or _generate_test_ssh_key()}
    if principals is not None:
        body['principals'] = principals
    return client.post('/api/v2/ssh/hosts/enroll', data=json.dumps(body),
                       content_type='application/json')


def _renew(client, token):
    return client.post('/api/v2/ssh/hosts/renew', headers={'X-Host-Token': token})


def _check_in(client, token, krl_etag='0'):
    return client.post('/api/v2/ssh/hosts/check-in', data=json.dumps({'krl_etag': krl_etag}),
                       content_type='application/json', headers={'X-Host-Token': token})


def _row(auth_client, hostname):
    # The list is paginated (25 per page) and the DB is shared across the test
    # session, so ask the API for this host by name instead of scanning page 1.
    body = auth_client.get(f'/api/v2/ssh/hosts?search={hostname}&per_page=100').get_json()
    return next(h for h in body['data'] if h['hostname'] == hostname)


def _host_certs(app, host_ca_id, public_key=None):
    with app.app_context():
        query = SSHCertificate.query.filter_by(ssh_ca_id=host_ca_id, cert_type='host')
        if public_key:
            query = query.filter_by(public_key=public_key)
        return [(c.id, c.serial, c.revoked, c.valid_to > utc_now()) for c in query.all()]


def enrolled_host(auth_client, client, host_ca):
    """Module helper: register + enroll one host, return (hostname, host_token)."""
    host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('e'))
    r = _enroll(client, bootstrap, host['hostname'])
    assert r.status_code == 201, r.data
    return host['hostname'], r.get_json()['data']['host_token']


def _shift_cert(app, cert_id, days):
    """Move a certificate's whole window by `days` (negative = in the past)."""
    with app.app_context():
        cert = db.session.get(SSHCertificate, cert_id)
        window = cert.valid_to - cert.valid_from
        cert.valid_from = cert.valid_from + timedelta(days=days)
        cert.valid_to = cert.valid_from + window
        db.session.commit()


@pytest.fixture
def host_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='host', descr='Guard host CA',
                          allow_any_principal=True)


@pytest.fixture
def user_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='user', descr='Guard user CA',
                          allow_any_principal=True)


@pytest.fixture
def enrolled(auth_client, client, host_ca, user_ca):
    """(host_dict, host_token) of a fully enrolled active host."""
    host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                hostname=_uniq('guard'))
    r = _enroll(client, bootstrap, host['hostname'])
    assert r.status_code == 201, r.data
    return host['hostname'], r.get_json()['data']['host_token']


# ── §6: what a CA policy refusal does, and where the rollback stops ─────────

class TestEnrollPolicyRefusal:
    def test_the_whole_enroll_is_reverted_and_the_token_survives(self, app, auth_client,
                                                                  client):
        strict = _create_ssh_ca(auth_client, ca_type='host', descr='Strict guard CA',
                                allow_any_principal=False)
        serial_before = auth_client.get(f"/api/v2/ssh/cas/{strict['id']}"
                                        ).get_json()['data']['serial_counter']
        host, bootstrap = _register(auth_client, strict['id'], hostname=_uniq('refused'))
        r = _enroll(client, bootstrap, host['hostname'])
        assert r.status_code == 403, r.data
        assert 'allowed principals' in r.get_json()['message']

        with app.app_context():
            db.session.expire_all()
            row = db.session.get(SSHManagedHost, host['id'])
            assert row.status == SSHManagedHost.STATUS_PENDING
            assert row.public_key is None            # the key was not taken
            assert row.principals is None            # principals were not fixed
            assert row.token_hash is None            # no host token was issued
            assert row.current_cert_id is None
            assert row.bootstrap_hash                # the bootstrap token survived
            assert row.bootstrap_expires > utc_now()
        assert _host_certs(app, strict['id']) == []  # nothing was signed
        assert auth_client.get(f"/api/v2/ssh/cas/{strict['id']}"
                               ).get_json()['data']['serial_counter'] == serial_before

        # ...and the same bootstrap token still works once the CA policy allows it
        auth_client.put(f"/api/v2/ssh/cas/{strict['id']}",
                        data=json.dumps({'allow_any_principal': True}),
                        content_type='application/json')
        assert _enroll(client, bootstrap, host['hostname']).status_code == 201

    def test_a_refused_reenroll_after_a_host_key_change_has_already_revoked_the_old_certs(
            self, app, auth_client, client, host_ca):
        """The rollback covers the host row, not the cascade it triggered:
        `revoke_certificate` commits, so a re-enroll whose signing is refused by
        the CA policy leaves the previously issued certificates revoked — with
        the host still active and no replacement certificate. Pinned behaviour:
        the old key's certificates were unusable anyway (the host rotated its
        key), and the enrollment is still retryable."""
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('rekey2'))
        first = _enroll(client, bootstrap, host['hostname'])
        assert first.status_code == 201, first.data
        old_token = first.get_json()['data']['host_token']
        old_key = auth_client.get(f"/api/v2/ssh/hosts/{host['id']}"
                                  ).get_json()['data']['public_key']
        auth_client.put(f"/api/v2/ssh/cas/{host_ca['id']}", data=json.dumps({
            'allowed_principals': ['nothing-matches-*'], 'allow_any_principal': False}),
            content_type='application/json')

        bootstrap2 = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/bootstrap",
                               {}).get_json()['data']['bootstrap_token']
        r = _enroll(client, bootstrap2, host['hostname'], public_key=_generate_test_ssh_key())
        assert r.status_code == 403, r.data

        certs = _host_certs(app, host_ca['id'])
        assert certs and all(revoked for (_id, _s, revoked, _live) in certs), certs
        with app.app_context():
            db.session.expire_all()
            row = db.session.get(SSHManagedHost, host['id'])
            assert row.bootstrap_hash                      # a retry stays possible
            assert row.public_key.strip() == old_key.strip()   # the new key was refused
        # the host is not silently re-armed: its old token still resolves, and
        # the refusal is what the agent sees on every later tick — as a 400
        # 'Invalid parameter value', the generic ValueError answer, where enroll
        # answers 403 with the CA policy text (see the report).
        refused = _renew(client, old_token)
        assert refused.status_code == 400, refused.data
        assert 'Invalid parameter value' in refused.get_json()['message']


# ── operational signing failure: the documented recovery path ──────────────

class TestOperationalSigningFailure:
    def test_the_host_stays_enrolled_and_check_in_retries_the_certificate(
            self, app, auth_client, client, host_ca, user_ca, monkeypatch):
        """The CA cannot sign right now (offline key, HSM error): the enrollment
        itself must stand, and the agent must recover through check-in → renew."""
        def offline(ca_id):
            raise RuntimeError('CA private key unavailable (HSM offline)')
        monkeypatch.setattr(SSHCAService, 'get_private_key_object', staticmethod(offline))

        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                    hostname=_uniq('signfail'))
        r = _enroll(client, bootstrap, host['hostname'])
        assert r.status_code == 201, r.data
        data = r.get_json()['data']
        assert 'certificate' not in data
        assert 'signing failed' in r.get_json()['message']
        token = data['host_token']

        row = _row(auth_client, host['hostname'])
        assert row['status'] == 'active' and row['cert_id'] is None

        check = _check_in(client, token).get_json()['data']
        assert check['renew_required'] is True and check['valid_to'] is None

        monkeypatch.undo()
        r = _renew(client, token)
        assert r.status_code == 200, r.data
        after = _row(auth_client, host['hostname'])
        assert after['cert_status'] == 'valid' and after['cert_serial']

    def test_a_failure_while_storing_the_certificate_behaves_the_same_way(
            self, app, auth_client, client, host_ca, user_ca, monkeypatch):
        """A failure at the INSERT is not a different story: `get_next_serial`
        already committed the session, so the host keeps its enrollment and its
        token, and check-in → renew completes the certificate. The CA does lose
        the serial it handed out (pre-existing signing behaviour)."""
        monkeypatch.setattr(SSHCertificateUtilsMixin, '_compute_fingerprint',
                            staticmethod(lambda key: None))      # NOT NULL violation
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                    hostname=_uniq('storefail'))
        serial_before = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}"
                                        ).get_json()['data']['serial_counter']
        r = _enroll(client, bootstrap, host['hostname'])
        assert r.status_code == 201, r.data
        token = r.get_json()['data']['host_token']
        assert 'will retry' in r.get_json()['message']

        hostname = host['hostname']
        row = _row(auth_client, hostname)
        assert row['status'] == 'active' and row['cert_id'] is None
        check = _check_in(client, token).get_json()['data']
        assert check['renew_required'] is True

        monkeypatch.undo()
        assert _renew(client, token).status_code == 200
        assert _row(auth_client, hostname)['cert_status'] == 'valid'
        serial_after = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}"
                                       ).get_json()['data']['serial_counter']
        assert serial_after > serial_before        # the burned serial is never reused


# ── §6: the certificate cascade of one host key ─────────────────────────────

class TestCertificateCascade:
    def test_revoke_takes_every_unexpired_certificate_of_the_host_key(
            self, app, auth_client, client, host_ca, enrolled):
        hostname, token = enrolled
        for _ in range(2):                       # three live certificates, one key
            assert _renew(client, token).status_code == 200
        row = _row(auth_client, hostname)
        before = _host_certs(app, host_ca['id'])
        assert len(before) == 3 and all(live for (_i, _s, _r, live) in before)

        r = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                      {'reason': 'key compromise', 'revoke_certificate': True})
        assert r.status_code == 200, r.data
        after = _host_certs(app, host_ca['id'])
        assert len(after) == 3
        assert all(revoked for (_i, _s, revoked, _live) in after), after
        assert _renew(client, token).status_code == 401

        # every serial moved into the host CA's public KRL, in one version bump
        ca = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']
        assert ca['krl_version'] == 3
        krl = client.get(f"/ssh/krl/{ca['refid']}")
        assert krl.status_code == 200 and krl.headers['ETag'] == '"3"'

    def test_revoke_leaves_an_already_expired_certificate_out_of_the_krl(
            self, app, auth_client, client, host_ca, enrolled):
        hostname, token = enrolled
        assert _renew(client, token).status_code == 200
        row = _row(auth_client, hostname)
        stale_id = [c[0] for c in _host_certs(app, host_ca['id'])][-1]
        _shift_cert(app, stale_id, -40)        # an old renewal, long expired

        assert post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                         {'revoke_certificate': True}).status_code == 200
        certs = _host_certs(app, host_ca['id'])
        expired = [c for c in certs if not c[3]]
        live = [c for c in certs if c[3]]
        assert expired and all(not revoked for (_i, _s, revoked, _l) in expired)
        assert live and all(revoked for (_i, _s, revoked, _l) in live)

    def test_reenroll_with_a_rotated_host_key_retires_the_old_certificates(
            self, app, auth_client, client, host_ca, enrolled):
        """§6: a host that regenerated its ssh host key must not keep working
        certificates signed for the key it threw away."""
        hostname, _token = enrolled
        row = _row(auth_client, hostname)
        old_certs = _host_certs(app, host_ca['id'])

        bootstrap = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/bootstrap",
                              {}).get_json()['data']['bootstrap_token']
        new_key = _generate_test_ssh_key()
        r = _enroll(client, bootstrap, hostname, public_key=new_key)
        assert r.status_code == 201, r.data

        certs = _host_certs(app, host_ca['id'])
        old = [c for c in certs if c[0] in [x[0] for x in old_certs]]
        assert old and all(revoked for (_i, _s, revoked, _l) in old), certs
        assert len(certs) == len(old) + 1
        assert any(not revoked and live for (_i, _s, revoked, live) in certs)
        with app.app_context():
            db.session.expire_all()
            host = db.session.get(SSHManagedHost, row['id'])
            assert host.public_key.strip() == new_key.strip()
            assert host.current_cert is not None

    def test_the_fixed_principals_are_kept_across_a_reenroll(self, auth_client, client,
                                                             host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('principals'))
        assert _enroll(client, bootstrap, host['hostname'],
                       principals=['malicious-alias.internal']).status_code == 201
        bootstrap2 = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/bootstrap",
                               {}).get_json()['data']['bootstrap_token']
        r = _enroll(client, bootstrap2, host['hostname'], principals=['whoever'])
        assert r.status_code == 201
        # S1: caller-supplied principals are ignored; principals are bound to [hostname]
        assert r.get_json()['data']['principals'] == [host['hostname']]


# ── §6: the delete and rotate guards ────────────────────────────────────────

class TestGuards:
    def test_one_host_token_never_reaches_another_host(self, auth_client, client, host_ca):
        """§6 cross-host isolation: the token resolves to exactly one host row, so
        host A renewing cannot move host B's certificate — even though both share
        the same host CA."""
        name_a, token_a = enrolled_host(auth_client, client, host_ca)
        name_b, token_b = enrolled_host(auth_client, client, host_ca)
        before_b = _row(auth_client, name_b)

        assert _renew(client, token_a).status_code == 200
        after_a, after_b = _row(auth_client, name_a), _row(auth_client, name_b)
        assert after_a['cert_serial'] != before_b['cert_serial']
        assert after_b['cert_serial'] == before_b['cert_serial']
        assert after_b['cert_id'] == before_b['cert_id']
        assert after_b['last_ip'] == before_b['last_ip']

        # And the token is not a general credential: it opens no admin route.
        assert auth_client.get('/api/v2/ssh/hosts',
                               headers={'X-API-Key': token_a}).status_code == 401
        assert client.get(f"/api/v2/ssh/hosts/{_row(auth_client, name_b)['id']}",
                          headers={'X-Host-Token': token_a}).status_code in (401, 404)
        assert _renew(client, token_b).status_code == 200

    def test_rotate_token_is_refused_for_hosts_without_a_token(self, auth_client, client,
                                                               host_ca):
        host, _bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('nopending'))
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/rotate-token", {})
        assert r.status_code == 400 and 'active' in r.get_json()['message']
        assert auth_client.get(f"/api/v2/ssh/hosts/{host['id']}"
                               ).get_json()['data']['has_token'] is False

        hostname, _token = enrolled_host(auth_client, client, host_ca)
        row = _row(auth_client, hostname)
        assert post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                         {'revoke_certificate': True}).status_code == 200
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/rotate-token", {})
        assert r.status_code == 400 and 'revoked' in r.get_json()['message']

    def test_delete_is_allowed_once_the_current_certificate_cannot_authenticate(
            self, app, auth_client, client, host_ca):
        """The guard protects a *valid* certificate; an expired one is not a
        reason to keep the host registered."""
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('expired'))
        token = _enroll(client, bootstrap, host['hostname']).get_json()['data']['host_token']
        row = _row(auth_client, host['hostname'])
        _shift_cert(app, row['cert_id'], -40)
        assert _row(auth_client, host['hostname'])['cert_status'] == 'expired'
        assert _row(auth_client, host['hostname'])['auto_renew'] is True
        assert auth_client.delete(f"/api/v2/ssh/hosts/{row['id']}").status_code == 204
        assert _renew(client, token).status_code == 401

    def test_deleting_a_ca_that_live_hosts_point_at_is_refused(self, auth_client, host_ca,
                                                               user_ca):
        host, _bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                     hostname=_uniq('capointer'))
        for ca_id, label in ((host_ca['id'], 'host CA'), (user_ca['id'], 'user CA')):
            r = auth_client.delete(f"/api/v2/ssh/cas/{ca_id}")
            assert r.status_code == 409, f'{label}: {r.data}'
            assert 'managed host' in r.get_json()['message']
        assert auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").status_code == 200

        assert auth_client.delete(f"/api/v2/ssh/hosts/{host['id']}").status_code == 204
        for ca_id in (host_ca['id'], user_ca['id']):
            assert auth_client.delete(f"/api/v2/ssh/cas/{ca_id}").status_code == 204

    def test_deleting_the_current_certificate_nulls_the_pointer_not_the_host(
            self, app, auth_client, client, host_ca):
        """§6: the FK would otherwise block the delete; the host must survive and
        re-sign on the next check-in."""
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('certdel'))
        token = _enroll(client, bootstrap, host['hostname']).get_json()['data']['host_token']
        row = _row(auth_client, host['hostname'])
        cert_id = row['cert_id']
        _shift_cert(app, cert_id, -40)                 # deletable: past its window

        assert auth_client.delete(f"/api/v2/ssh/certificates/{cert_id}").status_code == 204
        after = _row(auth_client, host['hostname'])
        assert after['status'] == 'active' and after['cert_id'] is None
        with app.app_context():
            db.session.expire_all()
            assert db.session.get(SSHManagedHost, host['id']).current_cert_id is None
            assert db.session.get(SSHCertificate, cert_id) is None

        assert _check_in(client, token).get_json()['data']['renew_required'] is True
        assert _renew(client, token).status_code == 200
        assert _row(auth_client, host['hostname'])['cert_status'] == 'valid'


# ── §10: the renewal cadence is the agent's ─────────────────────────────────

class TestRenewCadence:
    def test_check_in_asks_for_renewal_at_the_threshold_not_before(
            self, app, auth_client, client, host_ca, enrolled):
        hostname, token = enrolled
        assert _check_in(client, token).get_json()['data']['renew_required'] is False

        row = _row(auth_client, hostname)
        _shift_cert(app, row['cert_id'], -25)     # 30-day cert, 5 days left = 17%
        assert _row(auth_client, hostname)['cert_status'] == 'expiring'
        assert _check_in(client, token).get_json()['data']['renew_required'] is True

        hostname2, token2 = enrolled_host(auth_client, client, host_ca)
        auth_client.patch(f"/api/v2/ssh/hosts/{_row(auth_client, hostname2)['id']}",
                          data=json.dumps({'auto_renew': False}), content_type='application/json')
        row2 = _row(auth_client, hostname2)
        _shift_cert(app, row2['cert_id'], -40)    # expired, but the pause wins
        assert _check_in(client, token2).get_json()['data']['renew_required'] is False
        assert _renew(client, token2).status_code == 403

    def test_check_in_reports_the_threshold_the_host_ca_defines(self, app, auth_client,
                                                                client, host_ca, enrolled):
        hostname, _token = enrolled
        row = _row(auth_client, hostname)
        _shift_cert(app, row['cert_id'], -20)     # 10 days left of 30 = 33%
        assert _row(auth_client, hostname)['cert_status'] == 'valid'
        auth_client.put(f"/api/v2/ssh/cas/{host_ca['id']}",
                        data=json.dumps({'renew_threshold_percent': 40}),
                        content_type='application/json')
        assert _row(auth_client, hostname)['cert_status'] == 'expiring'

    def test_the_server_has_no_idempotency_threshold_at_all(self, app, auth_client,
                                                            client, host_ca, enrolled):
        """§10: cadence is the agent's. Consequence pinned here — a
        caller holding one host token can mint one new certificate per call,
        each burning a CA serial, with the server signing every single one."""
        hostname, token = enrolled
        serial_before = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}"
                                        ).get_json()['data']['serial_counter']
        serials = set()
        for _ in range(12):
            r = _renew(client, token)
            assert r.status_code == 200, r.data
            serials.add(r.get_json()['data']['serial'])
        assert len(serials) == 12
        serial_after = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}"
                                       ).get_json()['data']['serial_counter']
        assert serial_after - serial_before == 12
        certs = _host_certs(app, host_ca['id'])
        assert len(certs) == 13                       # the enroll cert + 12 renewals
        assert sum(1 for c in certs if not c[2]) == 13

    def test_the_default_lan_deployment_exempts_the_agent_routes(self, auth_client, client,
                                                                 host_ca, enrolled):
        """The only backstop the pull model names is the per-route limit — and
        UCM's documented default (RATE_LIMIT_TRUST_LAN, plus the 127.0.0.1
        whitelist) exempts LAN clients from every limiter. On a managed-host
        network that is exactly where the agents are."""
        hostname, token = enrolled
        statuses = [_renew(client, token).status_code for _ in range(25)]
        assert statuses == [200] * 25, statuses

    def test_per_route_limits_apply_when_lan_trust_is_off(self, app, auth_client, client,
                                                          host_ca, enrolled, monkeypatch):
        """enroll 10/min, renew 10/min, check-in 60/min, each its own bucket."""
        from app import limiter
        hostname, token = enrolled
        monkeypatch.setenv('RATE_LIMIT_TRUST_LAN', 'false')
        limiter.reset()
        try:
            statuses = [_renew(client, token).status_code for _ in range(11)]
            assert statuses[:10] == [200] * 10, statuses
            assert statuses[10] == 429, statuses

            # the check-in bucket is separate and 6× larger: 12 more calls pass
            checkins = [_check_in(client, token).status_code for _ in range(12)]
            assert checkins == [200] * 12, checkins
        finally:
            limiter.reset()
