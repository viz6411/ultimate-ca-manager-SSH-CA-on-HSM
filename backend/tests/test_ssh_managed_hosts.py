"""SSH managed hosts — pull-model registry (/api/v2/ssh/hosts, migration 138).

Covers the SPEC_SSH_HOSTS_AND_KRL_AUTOMATION contracts that matter for rollout:
- enroll: bootstrap token is one-time, hostname-bound, host-unique, and obeys
  the host CA's principal policy;
- renew: host token only reaches its own host; guard rails on auto_renew and
  status; rotation kills the old token;
- revoke: certificate → KRL (krl_version bump), tokens NULL, renewals off;
- delete: blocked while auto_renew is on and the certificate is valid;
- check-in: KRL-version delta and renewal wake-up flag;
- webhook events for every lifecycle step.

Pull-only per issue #451: UCM never reaches out to servers, so there is no
wake-up POST and no long-poll stream — the timer-driven agent polls.

Uses the shared conftest fixtures: app, client, auth_client.
"""
import json
import uuid
from datetime import timedelta

import pytest

from models import db
from models.ssh import SSHCertificate, SSHManagedHost
from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json
from utils.datetime_utils import utc_now


def _uniq(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10]}.test.example.com"


def _register(auth_client, host_ca_id, user_ca_id=None, hostname=None, **extra):
    """Register a managed host; returns (host_dict, bootstrap_token)."""
    r = post_json(auth_client, '/api/v2/ssh/hosts', {
        'host_ca_id': host_ca_id, 'user_ca_id': user_ca_id,
        'hostname': hostname, **extra})
    assert r.status_code == 201, r.data
    data = r.get_json()['data']
    return data['host'], data['bootstrap_token']


def _enroll(auth_client, bootstrap, hostname=None, public_key=None, **extra):
    return post_json(auth_client, '/api/v2/ssh/hosts/enroll', {
        'bootstrap_token': bootstrap,
        'hostname': hostname or _uniq('host'),
        'public_key': public_key or _generate_test_ssh_key(),
        **extra})


def _host_row(auth_client, hostname):
    """The registry row of one host, asked for by name.

    The list is paginated (25 per page, sorted by hostname) and the database is
    shared for the whole test session — across files on PostgreSQL — so scanning
    page 1 is the harness root cause of the "flake": the fixture host lands on
    page 2 and `next(...)` raises StopIteration. Asking the API for the name is
    deterministic, the same rule tests/test_ssh_host_lifecycle_guards.py::_row
    already follows. No assertion changed: it is the same row, found by filter.
    """
    body = auth_client.get(f'/api/v2/ssh/hosts?search={hostname}&per_page=100').get_json()
    return next(h for h in body['data'] if h['hostname'] == hostname)


def _agent_renew(client, token):
    return client.post('/api/v2/ssh/hosts/renew', headers={'X-Host-Token': token})


def _agent_check_in(client, token, krl_etag=None):
    return client.post('/api/v2/ssh/hosts/check-in',
                       data=json.dumps({'krl_etag': krl_etag}),
                       content_type='application/json',
                       headers={'X-Host-Token': token})


def _expire_current_cert(app, host_id):
    with app.app_context():
        host = db.session.get(SSHManagedHost, host_id)
        cert = db.session.get(SSHCertificate, host.current_cert_id)
        cert.valid_to = utc_now() - timedelta(days=1)
        db.session.commit()
        return cert.serial


@pytest.fixture
def host_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='host', descr='Managed host CA',
                          allow_any_principal=True)


@pytest.fixture
def user_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='user', descr='Managed user CA',
                          allow_any_principal=True)


@pytest.fixture
def enrolled_host(auth_client, host_ca, user_ca):
    """A fully enrolled active host: returns (host_dict, host_token)."""
    host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                hostname=_uniq('enrolled'))
    r = _enroll(auth_client, bootstrap, hostname=host['hostname'])
    assert r.status_code == 201, r.data
    return r.get_json()['data']['hostname'], r.get_json()['data']['host_token']


# ── admin CRUD + bootstrap ──────────────────────────────────────────────────

class TestRegister:
    def test_returns_bootstrap_and_install_command(self, auth_client, host_ca, user_ca):
        r = post_json(auth_client, '/api/v2/ssh/hosts', {
            'host_ca_id': host_ca['id'], 'user_ca_id': user_ca['id'],
            'hostname': _uniq('reg')})
        assert r.status_code == 201, r.data
        data = r.get_json()['data']
        assert data['bootstrap_token'].startswith('ucm_boot_')
        assert data['host']['status'] == 'pending'
        assert data['host']['bootstrap_active'] is True
        assert f"/ssh/agent-setup?token={data['bootstrap_token']}" in data['install_command']

    def test_hostname_is_script_safe(self, auth_client, host_ca):
        r = post_json(auth_client, '/api/v2/ssh/hosts',
                      {'host_ca_id': host_ca['id'], 'hostname': 'x$(id)'})
        assert r.status_code == 400
        assert 'hostname' in r.get_json()['message']

    def test_duplicate_hostname_refused(self, auth_client, host_ca):
        name = _uniq('dupe')
        assert _register(auth_client, host_ca['id'], hostname=name)[0]['id']
        r = post_json(auth_client, '/api/v2/ssh/hosts',
                      {'host_ca_id': host_ca['id'], 'hostname': name})
        assert r.status_code == 400
        assert 'already exists' in r.get_json()['message']

    def test_host_ca_must_actually_be_a_host_ca(self, auth_client, user_ca):
        r = post_json(auth_client, '/api/v2/ssh/hosts', {'host_ca_id': user_ca['id']})
        assert r.status_code == 400
        assert 'not a host CA' in r.get_json()['message']

    def test_empty_hostname_is_allowed_and_named_pending(self, auth_client, host_ca):
        host, _ = _register(auth_client, host_ca['id'])
        assert host['hostname'].startswith('pending-')

    def test_user_ca_only_is_allowed_without_host_ca(self, auth_client, user_ca):
        r = post_json(auth_client, '/api/v2/ssh/hosts', {'user_ca_id': user_ca['id']})
        assert r.status_code == 201
        data = r.get_json()['data']
        assert data['host']['user_ca_id'] == user_ca['id']
        assert data['host']['host_ca_id'] is None

    def test_registration_without_any_ca_is_refused(self, auth_client):
        r = post_json(auth_client, '/api/v2/ssh/hosts', {})
        assert r.status_code == 400
        assert 'At least one CA' in r.get_json()['message']

    def test_registry_requires_read_ssh_cas(self, client, auth_client, host_ca):
        assert client.get('/api/v2/ssh/hosts').status_code == 401
        key = post_json(auth_client, '/api/v2/account/apikeys',
                        {'name': 'hosts-ro', 'permissions': ['read:ssh_cas']})
        api = key.get_json()['data']['key']
        r = client.get('/api/v2/ssh/hosts', headers={'X-API-Key': api})
        assert r.status_code == 200
        r = client.post('/api/v2/ssh/hosts', json={'host_ca_id': host_ca['id']},
                        headers={'X-API-Key': api})
        assert r.status_code == 403
        auth_client.delete(f"/api/v2/account/apikeys/{key.get_json()['data']['id']}")


class TestBootstrapReissue:
    def test_new_bootstrap_kills_the_old_one(self, auth_client, host_ca):
        host, old = _register(auth_client, host_ca['id'], hostname=_uniq('boot'))
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/bootstrap", {})
        assert r.status_code == 200
        new = r.get_json()['data']['bootstrap_token']
        assert new != old
        assert _enroll(auth_client, old, hostname=host['hostname']).status_code == 403

    def test_revoked_host_cannot_be_reinstalled(self, auth_client, host_ca, enrolled_host):
        hostname, _ = enrolled_host
        host_id = _host_row(auth_client, hostname)['id']
        assert post_json(auth_client, f'/api/v2/ssh/hosts/{host_id}/revoke-cert',
                         {'reason': 'key compromise'}).status_code == 200
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{host_id}/bootstrap", {})
        assert r.status_code == 400
        assert 'revoked' in r.get_json()['message']


# ── enroll ───────────────────────────────────────────────────────────────────

class TestEnroll:
    def test_happy_path_issues_token_and_first_certificate(self, auth_client, host_ca,
                                                           user_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                    hostname=_uniq('happy'))
        r = _enroll(auth_client, bootstrap, hostname=host['hostname'])
        assert r.status_code == 201, r.data
        data = r.get_json()['data']
        assert data['host_token'].startswith('ucm_sh_')
        assert data['certificate'].startswith('ssh-ed25519-cert-v01@openssh.com ')
        assert data['principals'] == [host['hostname']]
        assert data['user_ca']['krl_path'] == f"/ssh/krl/{user_ca['refid']}"
        assert data['host_ca_public_key'] == host_ca['public_key']
        got = auth_client.get(f"/api/v2/ssh/hosts/{host['id']}").get_json()['data']
        assert got['status'] == 'active'
        assert got['cert_status'] == 'valid'
        assert got['bootstrap_active'] is False  # the one-time token is spent

    def test_bad_or_missing_bootstrap_token_refused(self, auth_client, host_ca):
        host, _ = _register(auth_client, host_ca['id'], hostname=_uniq('bad'))
        r = _enroll(auth_client, 'ucm_boot_not-a-real-token', hostname=host['hostname'])
        assert r.status_code == 403
        assert 'bootstrap token' in r.get_json()['message']

    def test_expired_bootstrap_refused(self, app, auth_client, host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('exp'))
        with app.app_context():
            row = db.session.get(SSHManagedHost, host['id'])
            row.bootstrap_expires = utc_now() - timedelta(minutes=1)
            db.session.commit()
        assert _enroll(auth_client, bootstrap, hostname=host['hostname']).status_code == 403

    def test_bootstrap_is_one_time(self, auth_client, host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('once'))
        assert _enroll(auth_client, bootstrap, hostname=host['hostname']).status_code == 201
        assert _enroll(auth_client, bootstrap, hostname=host['hostname']).status_code == 403

    def test_fixed_hostname_rules(self, auth_client, host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('fixed'))
        r = _enroll(auth_client, bootstrap, hostname=_uniq('other'))
        assert r.status_code == 403
        assert 'bound to hostname' in r.get_json()['message']

    def test_hostname_collision_with_another_host_refused(self, auth_client, host_ca):
        name = _uniq('collide')
        _register(auth_client, host_ca['id'], hostname=name)  # A owns the name
        b, bootstrap_b = _register(auth_client, host_ca['id'])  # B is pending
        r = _enroll(auth_client, bootstrap_b, hostname=name)
        assert r.status_code == 403
        assert 'already exists' in r.get_json()['message']
        assert b['hostname'].startswith('pending-')  # B untouched

    def test_ca_principal_policy_is_a_clear_refusal(self, auth_client):
        strict_ca = _create_ssh_ca(auth_client, ca_type='host',
                                   descr='Strict host CA', allow_any_principal=False)
        host, bootstrap = _register(auth_client, strict_ca['id'], hostname=_uniq('strict'))
        r = _enroll(auth_client, bootstrap, hostname=host['hostname'])
        assert r.status_code == 403
        assert 'allowed principals' in r.get_json()['message']

    def test_shell_metacharacters_in_hostname_refused(self, auth_client, host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'])
        r = _enroll(auth_client, bootstrap, hostname='x`reboot`')
        assert r.status_code == 400

    def test_public_key_required(self, auth_client, host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('nopub'))
        r = post_json(auth_client, '/api/v2/ssh/hosts/enroll', {
            'bootstrap_token': bootstrap, 'hostname': host['hostname'], 'public_key': ''})
        assert r.status_code == 400


# ── renew + guard rails ──────────────────────────────────────────────────────

class TestRenew:
    def test_agent_renew_signs_a_fresh_certificate(self, auth_client, enrolled_host,
                                                   host_ca):
        hostname, token = enrolled_host
        row = _host_row(auth_client, hostname)
        r = _agent_renew(auth_client, token)
        assert r.status_code == 200, r.data
        after = auth_client.get(f"/api/v2/ssh/hosts/{row['id']}").get_json()['data']
        assert after['cert_serial'] != row['cert_serial']
        assert after['cert_status'] == 'valid'
        # host certificates obey the CA's host_cert_ttl, not the daily user default
        ca = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']
        assert ca['host_cert_ttl'] == 2592000

    def test_missing_or_foreign_host_token_refused(self, client):
        assert _agent_renew(client, 'nope').status_code == 401
        assert _agent_renew(client, 'ucm_sh_0000000000000000000000000000').status_code == 401

    def test_auto_renew_off_blocks_the_agent(self, auth_client, enrolled_host):
        hostname, token = enrolled_host
        row = _host_row(auth_client, hostname)
        r = auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}", json={'auto_renew': False})
        assert r.status_code == 200
        assert r.get_json()['data']['auto_renew'] is False
        r = _agent_renew(auth_client, token)
        assert r.status_code == 403
        assert r.get_json()['message'] == 'Auto-renewal is paused'

    def test_patch_requires_auto_renew_boolean(self, auth_client, enrolled_host):
        hostname, _ = enrolled_host
        row = _host_row(auth_client, hostname)
        assert auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}",
                                 json={'autoRenew': True}).status_code == 400
        assert auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}",
                                 json={'auto_renew': 'yes'}).status_code == 400

    def test_ui_payload_round_trip_after_d1_fix(self, auth_client, enrolled_host):
        """The exact body ssh-hosts.service.js PATCHes since b6140155c:
        off → the agent's /renew obeys the pause; back on → it renews again."""
        hostname, token = enrolled_host
        row = _host_row(auth_client, hostname)
        r = auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}", data=json.dumps({'auto_renew': False}),
                              content_type='application/json')
        assert r.status_code == 200, r.data
        assert r.get_json()['data']['auto_renew'] is False
        assert _agent_renew(auth_client, token).status_code == 403
        r = auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}", data=json.dumps({'auto_renew': True}),
                              content_type='application/json')
        assert r.status_code == 200, r.data
        assert _agent_renew(auth_client, token).status_code == 200

    def test_renew_after_host_revocation_refused(self, auth_client, enrolled_host):
        hostname, token = enrolled_host
        row = _host_row(auth_client, hostname)
        assert post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                         {}).status_code == 200
        assert _agent_renew(auth_client, token).status_code == 401  # token is dead

    def test_force_renew_works_even_when_auto_renew_is_off(self, auth_client,
                                                            enrolled_host):
        hostname, _ = enrolled_host
        row = _host_row(auth_client, hostname)
        auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}", json={'auto_renew': False})
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/force-renew", {})
        assert r.status_code == 200, r.data
        assert r.get_json()['data']['cert_type'] == 'host'

    def test_force_renew_on_an_unenrolled_host_refused(self, auth_client, host_ca):
        host, _ = _register(auth_client, host_ca['id'], hostname=_uniq('nothing'))
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/force-renew", {})
        assert r.status_code == 400
        assert 'pending' in r.get_json()['message']


class TestTokenIsolation:
    def test_host_token_only_touches_its_own_host(self, auth_client, host_ca, user_ca):
        a, bootstrap_a = _register(auth_client, host_ca['id'], user_ca['id'],
                                   hostname=_uniq('a'))
        b, bootstrap_b = _register(auth_client, host_ca['id'], user_ca['id'],
                                   hostname=_uniq('b'))
        token_a = _enroll(auth_client, bootstrap_a, hostname=a['hostname']).get_json()['data']['host_token']
        token_b = _enroll(auth_client, bootstrap_b, hostname=b['hostname']).get_json()['data']['host_token']

        b_cert_before = auth_client.get(f"/api/v2/ssh/hosts/{b['id']}").get_json()['data']['cert_serial']
        assert _agent_renew(auth_client, token_a).status_code == 200
        assert auth_client.get(f"/api/v2/ssh/hosts/{b['id']}").get_json()['data']['cert_serial'] == b_cert_before

        # A's token cannot be used for B: the endpoints resolve the host from
        # the token, and A's spent bootstrap cannot enroll B's hostname.
        assert _agent_check_in(auth_client, token_b).status_code == 200
        assert _agent_check_in(auth_client, 'ucm_sh_wrong').status_code == 401
        # A host token is not a UCM API key: it authenticates nothing else
        assert auth_client.get('/api/v2/ssh/hosts',
                               headers={'X-API-Key': token_a}).status_code == 401
        assert auth_client.get('/api/v2/certificates',
                               headers={'X-API-Key': token_a}).status_code == 401

    def test_rotate_token_invalidates_the_old_one(self, auth_client, enrolled_host):
        hostname, old_token = enrolled_host
        row = _host_row(auth_client, hostname)
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/rotate-token", {})
        assert r.status_code == 200
        new_token = r.get_json()['data']['host_token']
        assert new_token != old_token
        assert r.get_json()['data']['host']['token_prefix'] == new_token[:12]
        assert _agent_renew(auth_client, old_token).status_code == 401
        assert _agent_renew(auth_client, new_token).status_code == 200

    def test_reenroll_keeps_the_fixed_principals(self, auth_client, host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('rekey'))
        _enroll(auth_client, bootstrap, hostname=host['hostname'],
                principals=['spoofed-principal.example.com'])
        bootstrap2 = post_json(auth_client,
                               f"/api/v2/ssh/hosts/{host['id']}/bootstrap",
                               {}).get_json()['data']['bootstrap_token']
        r = _enroll(auth_client, bootstrap2, hostname=host['hostname'],
                    principals=['somebody-else'])
        assert r.status_code == 201
        # S1: caller-supplied principals are ignored; principals are bound to [hostname]
        assert r.get_json()['data']['principals'] == [host['hostname']]


# ── revoke + delete guard rails ──────────────────────────────────────────────

class TestRevokeAndDelete:
    def _row(self, auth_client, hostname):
        return _host_row(auth_client, hostname)      # search, not page 1

    def test_revoke_puts_the_cert_in_the_krl_and_kills_the_tokens(self, app, auth_client,
                                                                  enrolled_host, host_ca,
                                                                  user_ca):
        hostname, token = enrolled_host
        row = self._row(auth_client, hostname)
        cert = auth_client.get(f"/api/v2/ssh/certificates/{row['cert_id']}").get_json()['data']
        assert cert['status'] == 'valid'

        r = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                      {'reason': 'key compromise', 'revoke_certificate': True})
        assert r.status_code == 200
        host = r.get_json()['data']
        assert host['status'] == 'revoked'
        assert host['auto_renew'] is False
        assert host['has_token'] is False  # token_hash NULLed
        assert host['bootstrap_active'] is False
        assert _agent_renew(auth_client, token).status_code == 401

        cert_after = auth_client.get(f"/api/v2/ssh/certificates/{row['cert_id']}").get_json()['data']
        assert cert_after['revoked'] is True
        assert cert_after['revoke_reason'] == 'key compromise'
        # the KRL wake-up counter moved — the public ETag will change
        ca = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']
        assert ca['krl_version'] == (host_ca.get('krl_version') or 0) + 1
        with app.app_context():
            assert db.session.get(SSHManagedHost, row['id']).token_hash is None

    def test_revoke_without_cert_revocation_keeps_cert_valid(self, app, auth_client,
                                                             enrolled_host, host_ca):
        hostname, token = enrolled_host
        row = self._row(auth_client, hostname)
        cert_before = auth_client.get(f"/api/v2/ssh/certificates/{row['cert_id']}").get_json()['data']
        assert cert_before['status'] == 'valid'
        ca_before = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']
        krl_version_before = ca_before.get('krl_version') or 0

        # Default revocation (revoke_certificate=False) does NOT revoke certificate
        r = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                      {'reason': 'agent decommission', 'revoke_certificate': False})
        assert r.status_code == 200
        host = r.get_json()['data']
        assert host['status'] == 'revoked'
        assert host['auto_renew'] is False
        assert host['has_token'] is False

        # Certificate remains valid and not in KRL
        cert_after = auth_client.get(f"/api/v2/ssh/certificates/{row['cert_id']}").get_json()['data']
        assert cert_after['revoked'] is False
        ca_after = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']
        assert (ca_after.get('krl_version') or 0) == krl_version_before

    def test_delete_blocked_while_auto_renew_and_cert_are_valid(self, auth_client,
                                                                 enrolled_host):
        hostname, _ = enrolled_host
        row = self._row(auth_client, hostname)
        r = auth_client.delete(f"/api/v2/ssh/hosts/{row['id']}")
        assert r.status_code == 400
        assert 'auto-renew is on' in r.get_json()['message']
        assert auth_client.get(f"/api/v2/ssh/hosts/{row['id']}").status_code == 200

    def test_delete_allowed_after_auto_renew_off(self, auth_client, enrolled_host):
        hostname, _ = enrolled_host
        row = self._row(auth_client, hostname)
        auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}", json={'auto_renew': False})
        assert auth_client.delete(f"/api/v2/ssh/hosts/{row['id']}").status_code == 204
        assert auth_client.get(f"/api/v2/ssh/hosts/{row['id']}").status_code == 404

    def test_delete_allowed_after_revoke(self, auth_client, enrolled_host):
        hostname, _ = enrolled_host
        row = self._row(auth_client, hostname)
        post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert", {})
        assert auth_client.delete(f"/api/v2/ssh/hosts/{row['id']}").status_code == 204

    def test_pending_host_can_be_dropped(self, auth_client, host_ca):
        host, _ = _register(auth_client, host_ca['id'], hostname=_uniq('drop'))
        assert auth_client.delete(f"/api/v2/ssh/hosts/{host['id']}").status_code == 204


# ── agent heartbeat: check-in ────────────────────────────────────────────────

class TestCheckIn:
    def test_check_in_reports_krl_delta_and_sets_sync_time(self, auth_client,
                                                            enrolled_host):
        hostname, token = enrolled_host
        r = _agent_check_in(auth_client, token, krl_etag='0')
        assert r.status_code == 200
        data = r.get_json()['data']
        assert data['krl_changed'] is False  # agent already at version 0
        assert data['krl_version'] == 0
        assert data['renew_required'] is False
        r = _agent_check_in(auth_client, token, krl_etag='stale-etag')
        assert r.get_json()['data']['krl_changed'] is True
        row = _host_row(auth_client, hostname)
        assert row['last_krl_sync_at']

    def test_check_in_asks_for_renewal_when_cert_is_expired(self, app, auth_client,
                                                             enrolled_host):
        hostname, token = enrolled_host
        row = _host_row(auth_client, hostname)
        _expire_current_cert(app, row['id'])
        r = _agent_check_in(auth_client, token, krl_etag='0')
        assert r.get_json()['data']['renew_required'] is True


# ── webhook events ─────────────────────────────────────────────────────────

SSH_EVENTS = ['ssh_certificate.issued', 'ssh_certificate.revoked', 'ssh_ca.krl_updated',
              'ssh_host.enrolled', 'ssh_host.renewed', 'ssh_host.revoked']


@pytest.fixture
def webhook_sink(app):
    """One endpoint subscribed to the six SSH events; removed afterwards."""
    from models import WebhookDelivery
    from services.webhook_service import WebhookEndpoint
    with app.app_context():
        ep = WebhookEndpoint(name='ssh-hosts-sink', url='https://example.invalid/hook',
                             events=json.dumps(SSH_EVENTS), enabled=True)
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


def _deliveries(app, ep_id):
    from models import WebhookDelivery
    with app.app_context():
        rows = WebhookDelivery.query.filter_by(endpoint_id=ep_id).all()
        return [r.event_type for r in rows], [r.status for r in rows]


class TestWebhookEvents:
    def test_enroll_queues_host_and_certificate_events(self, app, auth_client,
                                                        host_ca, user_ca, webhook_sink):
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                    hostname=_uniq('evenrol'))
        assert _enroll(auth_client, bootstrap, hostname=host['hostname']).status_code == 201
        events, statuses = _deliveries(app, webhook_sink)
        assert 'ssh_host.enrolled' in events
        assert 'ssh_certificate.issued' in events
        assert set(statuses) == {'pending'}  # durable queue, never a sync send

    def test_revoke_queues_host_cert_and_krl_events(self, app, auth_client,
                                                     enrolled_host, host_ca, webhook_sink):
        hostname, _ = enrolled_host
        row = _host_row(auth_client, hostname)
        assert post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                         {'reason': 'key compromise', 'revoke_certificate': True}).status_code == 200
        events, _ = _deliveries(app, webhook_sink)
        assert 'ssh_host.revoked' in events
        # Fixed 2026-11-21 (defect D2): the managed-host revoke route now emits
        # the certificate and KRL events too, so Host-CA webhook automations see
        # managed-host revocations, not just UI certificate revocations.
        assert 'ssh_certificate.revoked' in events
        assert 'ssh_ca.krl_updated' in events
        # the KRL itself moves with them:
        ca = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']
        assert ca['krl_version'] == 1

    def test_the_new_events_are_in_the_public_catalogue(self):
        from services.webhook_service import WebhookService
        for ev in SSH_EVENTS:
            assert ev in WebhookService.ALL_EVENTS

    def test_host_revoke_events_route_by_ca_filter(self, app, auth_client,
                                                    enrolled_host, host_ca, user_ca):
        """Independent proof of the D2 fix: the certificate and KRL events are
        tagged with the Host CA's refid (where the revoked host cert landed),
        while ssh_host.revoked stays tagged with the host's User CA refid.
        An endpoint filtered by each CA must see exactly its own events."""
        from models import WebhookDelivery
        from services.webhook_service import WebhookEndpoint
        with app.app_context():
            host_ep = WebhookEndpoint(name='ssh-hostca-filter', url='https://example.invalid/h',
                                      events=json.dumps(SSH_EVENTS),
                                      ca_filter=host_ca['refid'], enabled=True)
            user_ep = WebhookEndpoint(name='ssh-userca-filter', url='https://example.invalid/u',
                                      events=json.dumps(SSH_EVENTS),
                                      ca_filter=user_ca['refid'], enabled=True)
            db.session.add_all([host_ep, user_ep])
            db.session.commit()
            host_id, user_id = host_ep.id, user_ep.id
        try:
            row = _host_row(auth_client, enrolled_host[0])
            assert post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                             {'reason': 'key compromise', 'revoke_certificate': True}).status_code == 200
            host_events, _ = _deliveries(app, host_id)
            user_events, _ = _deliveries(app, user_id)
            assert 'ssh_certificate.revoked' in host_events
            assert 'ssh_ca.krl_updated' in host_events
            assert 'ssh_host.revoked' not in host_events  # that one names the User CA
            assert 'ssh_host.revoked' in user_events
            assert 'ssh_certificate.revoked' not in user_events
            with app.app_context():
                krl_event = next(r for r in WebhookDelivery.query.filter_by(
                    endpoint_id=host_id, event_type='ssh_ca.krl_updated').all())
                payload = json.loads(krl_event.payload)
            assert payload['krl_version'] == 1
            assert payload['krl_path'] == f"/ssh/krl/{host_ca['refid']}"
            assert payload['serial'] == row['cert_serial']
        finally:
            with app.app_context():
                for endpoint_id in (host_id, user_id):
                    WebhookDelivery.query.filter_by(endpoint_id=endpoint_id).delete()
                WebhookEndpoint.query.filter(
                    WebhookEndpoint.id.in_([host_id, user_id])).delete(synchronize_session=False)
                db.session.commit()

# ── D7 (live stand 2026-11-22): revoking a key that came from a real .pub file ─

class TestRevokeWithRealPubKeyFile:
    """A real agent posts the contents of /etc/ssh/ssh_host_ed25519_key.pub, i.e.
    `<type> <base64> <comment>`, while the certificate rows store the key without
    the comment. `_revoke_host_certs` used to compare the raw lines, so a managed
    host enrolled from a .pub file matched NOTHING: POST /hosts/<id>/revoke-cert
    answered 200, the host turned `revoked`, and the certificate stayed valid —
    `krl_version` unmoved, the public KRL byte-identical, `ssh-keygen -Q` still
    answering `ok`. That is what the live OpenSSH stand measured (defect D7); the
    automations missed it because the enroll helper sent a bare key.

    These tests enrol with a commented key on purpose. On the pre-fix code every
    assertion about the certificate row, the KRL version, the KRL bytes and the
    webhook events failed there: the assertions are not new, the key shape is.
    """

    def _pub_file_line(self, hostname):
        """Exactly what `cat /etc/ssh/ssh_host_ed25519_key.pub` hands to the agent."""
        return f'{_generate_test_ssh_key()} root@{hostname}'

    def test_revoking_a_host_enrolled_from_a_pub_file_moves_its_cert_into_the_krl(
            self, app, auth_client, client, host_ca, user_ca, webhook_sink):
        hostname = _uniq('pubkey')
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=hostname)
        r = _enroll(auth_client, bootstrap, hostname=hostname,
                    public_key=self._pub_file_line(hostname))
        assert r.status_code == 201, r.data
        assert r.get_json()['data']['certificate'].startswith('ssh-ed25519-cert-v01@openssh.com ')
        row = _host_row(auth_client, hostname)
        assert row['cert_status'] == 'valid'

        krl_before = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_before.status_code == 200
        ca_before = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']

        r = post_json(auth_client, f"/api/v2/ssh/hosts/{row['id']}/revoke-cert",
                      {'reason': 'key compromise', 'revoke_certificate': True})
        assert r.status_code == 200, r.data
        assert r.get_json()['data']['status'] == 'revoked'

        with app.app_context():
            certs = SSHCertificate.query.filter_by(ssh_ca_id=host_ca['id'],
                                                   cert_type='host').all()
            assert certs, 'nothing was signed for a commented key'
            for cert in certs:
                assert cert.revoked is True, f'certificate {cert.serial} stayed valid'
                assert cert.revoked_at is not None
                assert cert.revoke_reason == 'key compromise'
            moved = len(certs)

        ca_after = auth_client.get(f"/api/v2/ssh/cas/{host_ca['id']}").get_json()['data']
        # one krl_version per revoked certificate — not zero, and not more
        assert ca_after['krl_version'] == (ca_before.get('krl_version') or 0) + moved
        krl_after = client.get(f"/ssh/krl/{host_ca['refid']}")
        assert krl_after.status_code == 200
        assert krl_after.data, 'the public KRL is still empty'
        assert krl_after.data != krl_before.data, 'the published KRL bytes never changed'
        events, _ = _deliveries(app, webhook_sink)
        assert 'ssh_certificate.revoked' in events and 'ssh_ca.krl_updated' in events

    def test_rotating_to_another_commented_pub_key_revokes_the_certificates_of_the_old_key(
            self, app, auth_client, host_ca, user_ca):
        """The same filter serves the re-enroll-after-key-rotation path, so the
        commented shape has to work there too: pre-fix the old key's certificate
        survived the rotation unrevoked and absent from the KRL."""
        hostname = _uniq('rekeypub')
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=hostname)
        old_key = self._pub_file_line(hostname)
        assert _enroll(auth_client, bootstrap, hostname=hostname,
                       public_key=old_key).status_code == 201
        old_cert_id = _host_row(auth_client, hostname)['cert_id']

        bootstrap2 = post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/bootstrap",
                               {}).get_json()['data']['bootstrap_token']
        new_key = self._pub_file_line(hostname) + ' rotated'
        assert new_key.split()[1] != old_key.split()[1], 'the two keys must really differ'
        assert _enroll(auth_client, bootstrap2, hostname=hostname,
                       public_key=new_key).status_code == 201

        with app.app_context():
            db.session.expire_all()
            old = db.session.get(SSHCertificate, old_cert_id)
            assert old.revoked is True and old.revoked_at is not None, \
                'the certificate of the key the host threw away is still usable'
            host_row = db.session.get(SSHManagedHost, host['id'])
            assert host_row.public_key == new_key
            live = [c for c in SSHCertificate.query.filter_by(
                ssh_ca_id=host_ca['id'], cert_type='host').all() if not c.revoked]
        assert len(live) == 1, live
        assert new_key.split()[1] in live[0].public_key   # the certificate of the NEW key


class TestLiveCAReconfiguration:
    def test_change_user_and_host_ca_resets_sync_and_applies_on_checkin(
            self, auth_client, client, enrolled_host, host_ca, user_ca):
        hostname, token = enrolled_host
        row = _host_row(auth_client, hostname)
        assert row['config_synced'] is True

        new_user_ca = _create_ssh_ca(auth_client, ca_type='user', descr='Rotated User CA')
        new_host_ca = _create_ssh_ca(auth_client, ca_type='host', descr='Rotated Host CA',
                                     allow_any_principal=True)
        restricted_host_ca = _create_ssh_ca(auth_client, ca_type='host', descr='Restricted Host CA',
                                            allowed_principals=['*.only-prod.internal'])

        # Restricted CA rejects immediately on PATCH
        bad = auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}",
                                data=json.dumps({'host_ca_id': restricted_host_ca['id']}),
                                content_type='application/json')
        assert bad.status_code == 400
        assert 'not allowed' in bad.get_json()['message']

        # Clearing both CAs is refused
        none_ca = auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}",
                                    data=json.dumps({'host_ca_id': None, 'user_ca_id': None}),
                                    content_type='application/json')
        assert none_ca.status_code == 400

        # Valid update resets config_synced to False and stores overrides
        ok = auth_client.patch(f"/api/v2/ssh/hosts/{row['id']}",
                               data=json.dumps({
                                   'host_ca_id': new_host_ca['id'],
                                   'user_ca_id': new_user_ca['id'],
                                   'host_cert_ttl': 86400 * 14,
                                   'renew_threshold_percent': 25,
                               }),
                               content_type='application/json')
        assert ok.status_code == 200, ok.data
        updated = ok.get_json()['data']
        assert updated['config_synced'] is False
        assert updated['host_ca_id'] == new_host_ca['id']
        assert updated['user_ca_id'] == new_user_ca['id']
        assert updated['host_cert_ttl'] == 86400 * 14
        assert updated['renew_threshold_percent'] == 25

        # Next check-in delivers config_update and renew_required=True (CA mismatch)
        ci = client.post('/api/v2/ssh/hosts/check-in',
                         data=json.dumps({'krl_etag': '0'}),
                         content_type='application/json',
                         headers={'X-Host-Token': token})
        assert ci.status_code == 200
        ci_data = ci.get_json()['data']
        assert ci_data['config_changed'] is True
        assert ci_data['renew_required'] is True
        assert ci_data['config_update']['user_ca']['refid'] == new_user_ca['refid']
        assert ci_data['config_update']['has_host_ca'] is True

        # Agent renews under new Host CA
        ren = _agent_renew(client, token)
        assert ren.status_code == 200

        # Agent confirms config applied -> config_synced flips back to True
        ci2 = client.post('/api/v2/ssh/hosts/check-in',
                          data=json.dumps({'config_applied': True}),
                          content_type='application/json',
                          headers={'X-Host-Token': token})
        assert ci2.status_code == 200
        assert ci2.get_json()['data']['config_changed'] is False
        assert _host_row(auth_client, hostname)['config_synced'] is True

