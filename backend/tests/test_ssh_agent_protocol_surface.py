"""Issue #451 §10: the agent's pull paths are protocol paths, and their limits are real.

The 15-minute delivery guarantee only holds if three things stay true:

- `/ssh/krl/<refid>`, `/ssh/agent-setup` and `/ssh/agent-runner` are classified as
  PKI protocol paths, so the admin allowlist / safe-mode filter, the
  http→https canonical redirect and the admin-vs-ACME host-role check never get
  between an agent and its KRL;
- the classification is exact-match for the two agent routes: a sibling path must
  not inherit the exemption the way `/tsa-config` once did;
- the KRL pull has a rate bucket of its own: it answers 429 under abuse without
  spending the admin API's quota, and a whole fleet polling from one egress IP is
  not throttled by the shipped defaults.

Uses the shared conftest fixtures: app, client, auth_client.
"""
import json
import os
import uuid

import pytest

from security.rate_limiter import RateLimitConfig, get_rate_limiter
from models import db, SystemConfig
from utils import admin_allowlist
from utils.admin_allowlist import REFUSAL_MESSAGE
from utils.public_endpoints import (
    check_host_access, is_admin_ui_path, is_protocol_path, is_public_protocol_path,
)
from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json

AGENT_PATHS = ('/ssh/krl/host-ca-refid', '/ssh/agent-setup', '/ssh/agent-runner')
# The agent-facing API routes. They take X-Host-Token / a one-time bootstrap
# token, so they are machine clients like the KRL pull — not admin UI surface.
AGENT_API_PATHS = ('/api/v2/ssh/hosts/enroll', '/api/v2/ssh/hosts/check-in',
                   '/api/v2/ssh/hosts/renew')
# Paths that look like the agent routes but are not them.
LOOKALIKES = ('/ssh/krl', '/ssh/krl-x', '/ssh/agent-setup-x', '/ssh/agent-runner.sh',
              '/ssh/agent-setup/../hosts', '/ssh/hosts', '/ssh/cas')
API_LOOKALIKES = ('/api/v2/ssh/hosts', '/api/v2/ssh/hosts/3', '/api/v2/ssh/hosts/enroll-x',
                  '/api/v2/ssh/hosts/renew-all')


def _public_ip():
    """A source address no LAN exemption reaches. (TEST-NET ranges count as
    `is_private` in Python's ipaddress module, so 203.0.113.0/24 is LAN here.)"""
    return f'8.8.{uuid.uuid4().int % 200 + 20}.{uuid.uuid4().int % 200 + 20}'


@pytest.fixture
def user_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='user', descr='Surface user CA',
                          allow_any_principal=True)


# ── §10: classification, and only for the real routes ───────────────────────

class TestAgentPullsAreProtocolPaths:
    @pytest.mark.parametrize('path', AGENT_PATHS)
    def test_an_admin_allowlist_never_gets_between_an_agent_and_ucm(self, path):
        assert is_protocol_path(path), path
        assert is_public_protocol_path(path), path
        assert not is_admin_ui_path(path), path

    @pytest.mark.parametrize('path', AGENT_PATHS)
    def test_no_host_role_or_vhost_split_filters_them(self, path):
        for host in ('localhost', '10.0.0.5', 'ucm.example.com', 'acme.example.com', ''):
            assert check_host_access(path, host) is None, f'{path} on {host}'

    @pytest.mark.parametrize('path', LOOKALIKES)
    def test_a_lookalike_is_not_exempt(self, path):
        """`/tsa` is the protocol, `/tsa-config` was the page that leaked because
        a bare prefix matched its sibling. The agent routes are exact-match only."""
        assert not is_protocol_path(path), path

    def test_the_lookalikes_are_admin_surface(self, app, client):
        """They are not protocol paths, so they are normal admin routes: an
        anonymous request gets the admin answer (redirect/login/404), never a
        machine-client welcome."""
        for path in LOOKALIKES:
            r = client.get(path)
            assert r.status_code in (200, 302, 307, 401, 404), f'{path}: {r.status_code}'
            assert r.mimetype != 'application/octet-stream', path

    def test_the_real_krl_pull_needs_no_token_or_cookie(self, client, user_ca):
        r = client.get(f"/ssh/krl/{user_ca['refid']}")
        assert r.status_code == 200 and r.data.startswith(b'SSHKRL')
        assert 'ETag' in r.headers


# ── §10: the KRL bucket throttles abuse, not fleets ─────────────────────────

class TestTheKrlBucketIsRealAndSeparate:
    def test_abuse_on_the_krl_path_answers_429_and_leaves_the_admin_quota_alone(
            self, client, user_ca, monkeypatch):
        """The checklist asks for 429 under abuse on `/ssh/krl/`. It has to come
        from the KRL's own bucket: a throttled agent pull must not be able to
        lock the operator's browser out of the admin API (or the reverse)."""
        for name in [k for k in os.environ if k.startswith('RATE_LIMIT_')]:
            monkeypatch.delenv(name, raising=False)
        ip = _public_ip()
        RateLimitConfig._load_limits()
        RateLimitConfig.set_custom_limit('/ssh/krl/', 3, 3)
        try:
            krl_path = f"/ssh/krl/{user_ca['refid']}"
            pulls = [client.get(krl_path, environ_base={'REMOTE_ADDR': ip}).status_code
                     for _ in range(5)]
            assert pulls[:3] == [200] * 3, pulls
            assert pulls[3:] == [429, 429], pulls

            refused = client.get(krl_path, environ_base={'REMOTE_ADDR': ip})
            body = json.loads(refused.data)
            assert body['error'] == 'Rate limit exceeded'
            assert int(refused.headers['Retry-After']) >= 1
            assert refused.headers['X-RateLimit-Remaining'] == '0'
            assert refused.headers['X-RateLimit-Limit'] == '3'
            assert not refused.data.startswith(b'SSHKRL')   # no KRL bytes on a refusal

            # Same source address, different bucket: the agent installer route is
            # untouched, and no token was ever taken from the admin API's bucket.
            runner = client.get('/ssh/agent-runner', environ_base={'REMOTE_ADDR': ip})
            assert runner.status_code == 200
            limiter = get_rate_limiter()
            admin_key = limiter._get_key(ip, '/api/v2/ssh/hosts')
            assert admin_key not in limiter._buckets, 'the KRL abuse spent the admin bucket'
            assert limiter._get_key(ip, krl_path) != admin_key
        finally:
            RateLimitConfig.remove_custom_limit('/ssh/krl/')

    def test_the_agent_routes_and_the_admin_api_never_share_a_bucket(self):
        """Measured against one limit, counted in another: that was the bug
        `pattern_for` fixed. The agent surface must stay out of `_default`."""
        RateLimitConfig._load_limits()
        own = {path: RateLimitConfig.pattern_for(path) for path in AGENT_PATHS}
        assert own == {'/ssh/krl/host-ca-refid': '/ssh/krl/',
                       '/ssh/agent-setup': '/ssh/agent-setup',
                       '/ssh/agent-runner': '/ssh/agent-runner'}, own
        limits = RateLimitConfig.get_default_limits()
        for pattern in own.values():
            assert limits[pattern] == limits['_default'], pattern   # classified, not throttled
        for lookalike in LOOKALIKES:
            assert RateLimitConfig.pattern_for(lookalike) == '_default', lookalike

    def test_a_fleet_polling_from_one_egress_ip_is_not_throttled_by_default(
            self, client, auth_client, user_ca, monkeypatch, host_and_token):
        """A tick storm: 120 KRL pulls and 30 check-ins from one address, with the
        shipped defaults (`RATE_LIMIT_*` absent, LAN trust on) — the checklist's
        "verify a tick storm does not answer 429 to hosts behind one egress IP"."""
        for name in [k for k in os.environ if k.startswith('RATE_LIMIT_')]:
            monkeypatch.delenv(name, raising=False)
        hostname, token = host_and_token
        krl = f"/ssh/krl/{user_ca['refid']}"

        pulls = [client.get(krl).status_code for _ in range(120)]
        assert set(pulls) <= {200, 304}, pulls[:12]
        checkins = [client.post('/api/v2/ssh/hosts/check-in',
                                data=json.dumps({'krl_etag': '0'}),
                                content_type='application/json',
                                headers={'X-Host-Token': token}).status_code
                    for _ in range(30)]
        assert checkins == [200] * 30, checkins[:6]
        assert client.get('/ssh/agent-runner').status_code == 200
        assert client.get(f"/ssh/agent-setup?token=ucm_boot_nope").status_code == 404


# ── §10 cleartext caveat: the token travels to the origin the admin reached ─

class TestInstallCommandOrigin:
    def test_the_command_carries_the_origin_of_the_admin_request(self, auth_client):
        """`install_command` is built from `request.url_root`, the same convention
        as the existing `/ssh/setup/<refid>` flow. The https:// the checklist asks
        an operator to confirm is therefore the admin's own origin: whatever the
        browser reached UCM over is what the copy-pasted curl — and with it the
        one-time bootstrap token — will be sent over."""
        ca = _create_ssh_ca(auth_client, ca_type='host', descr='Surface install CA')
        for base in ('https://localhost:8443/', 'http://localhost:8080/'):
            r = auth_client.post('/api/v2/ssh/hosts', data=json.dumps({'host_ca_id': ca['id']}),
                                 content_type='application/json', base_url=base)
            assert r.status_code == 201, r.data
            command = r.get_json()['data']['install_command']
            assert command.startswith(f'curl -sSL "{base}ssh/agent-setup?token=ucm_boot_')
            assert command.count('http') == 1          # the host never adds a second hop
            assert 'ucm_boot_' in command              # a live token, in the URL
            assert base.rstrip('/') in command         # scheme, host and port: the request's


@pytest.fixture
def host_and_token(client, auth_client, user_ca):
    from tests.test_ssh import _create_ssh_ca as _ca
    host_ca = _ca(auth_client, ca_type='host', descr='Surface host CA', allow_any_principal=True)
    r = post_json(auth_client, '/api/v2/ssh/hosts',
                  {'host_ca_id': host_ca['id'], 'user_ca_id': user_ca['id']})
    data = r.get_json()['data']
    enrolled = client.post('/api/v2/ssh/hosts/enroll', data=json.dumps({
        'bootstrap_token': data['bootstrap_token'], 'hostname': data['host']['hostname'],
        'public_key': _generate_test_ssh_key()}), content_type='application/json')
    assert enrolled.status_code == 201, enrolled.data
    return data['host']['hostname'], enrolled.get_json()['data']['host_token']


# ── review round 1, IMPORTANT 3: the agent API is protocol surface too ──────

class TestTheAgentApiSurvivesTheAdminAllowlist:
    """#402 (`admin_allowed_networks`) used to answer 403 to enroll / check-in /
    renew from any address outside the admin subnets: the fleet got its KRL while
    its host certificate quietly expired at `host_cert_ttl`, forever."""

    @pytest.fixture
    def admins_only_from_localhost(self, app, monkeypatch):
        """Admin UI reachable from 127.0.0.1 only; yields a managed host address
        no admin subnet covers."""
        monkeypatch.delenv(admin_allowlist.ENV_NETWORKS, raising=False)
        monkeypatch.delenv(admin_allowlist.ENV_DISABLE, raising=False)

        def _store(value):
            with app.app_context():
                row = SystemConfig.query.filter_by(key=admin_allowlist.CONFIG_KEY).first()
                if value is None:
                    if row:
                        db.session.delete(row)
                elif row:
                    row.value = value
                else:
                    db.session.add(SystemConfig(key=admin_allowlist.CONFIG_KEY, value=value))
                db.session.commit()
            admin_allowlist.invalidate_cache()

        _store('127.0.0.0/8')
        try:
            yield _public_ip()
        finally:
            _store(None)          # never lock the rest of the suite out

    def test_a_host_outside_the_admin_subnets_enrolls_checks_in_and_renews(
            self, client, auth_client, admins_only_from_localhost):
        peer = {'REMOTE_ADDR': admins_only_from_localhost}
        host_ca = _create_ssh_ca(auth_client, ca_type='host', descr='Allowlist host CA',
                                 allow_any_principal=True)
        hostname = f'allowlist-{uuid.uuid4().hex[:10]}.test.example.com'
        registered = auth_client.post('/api/v2/ssh/hosts', data=json.dumps(
            {'host_ca_id': host_ca['id'], 'hostname': hostname}), content_type='application/json')
        assert registered.status_code == 201, registered.data

        enrolled = client.post('/api/v2/ssh/hosts/enroll', data=json.dumps({
            'bootstrap_token': registered.get_json()['data']['bootstrap_token'],
            'hostname': hostname, 'public_key': _generate_test_ssh_key()}),
            content_type='application/json', environ_base=peer)
        assert enrolled.status_code == 201, enrolled.data
        token = enrolled.get_json()['data']['host_token']

        checkin = client.post('/api/v2/ssh/hosts/check-in', data=json.dumps({'krl_etag': ''}),
                              content_type='application/json',
                              headers={'X-Host-Token': token}, environ_base=peer)
        assert checkin.status_code == 200, checkin.data

        renewed = client.post('/api/v2/ssh/hosts/renew', headers={'X-Host-Token': token},
                              environ_base=peer)
        assert renewed.status_code == 200, renewed.data

        # The exemption is only for the three machine routes: the very same address
        # is still locked out of the admin API.
        blocked = client.get('/api/v2/ssh/hosts', environ_base=peer)
        assert blocked.status_code == 403 and REFUSAL_MESSAGE.encode() in blocked.data
        assert client.get(f'/api/v2/ssh/hosts/{registered.get_json()["data"]["host"]["id"]}',
                          environ_base=peer).status_code == 403

    def test_the_three_routes_are_classified_and_measured_in_buckets_of_their_own(self):
        RateLimitConfig._load_limits()
        limits = RateLimitConfig.get_default_limits()
        for path in AGENT_API_PATHS:
            assert is_protocol_path(path) and is_public_protocol_path(path), path
            assert not is_admin_ui_path(path), path
            assert RateLimitConfig.pattern_for(path) == path, path
            assert limits[path] == limits['_default'], path   # classified, not throttled
        limiter = get_rate_limiter()
        for lookalike in API_LOOKALIKES:
            assert not is_protocol_path(lookalike), lookalike
            assert RateLimitConfig.pattern_for(lookalike) == '_default', lookalike
        for path in AGENT_API_PATHS:
            assert limiter._get_key('9.9.9.9', path) != limiter._get_key('9.9.9.9',
                                                                        '/api/v2/ssh/hosts')
        for host in ('localhost', '10.0.0.5', 'ucm.example.com', ''):
            for path in AGENT_API_PATHS:
                assert check_host_access(path, host) is None, f'{path} on {host}'
