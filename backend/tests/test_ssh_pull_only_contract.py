"""Issue #451 — the pull-only contract: the push mechanics must be provably gone.

The maintainer cut the wake-up contract (`callback_url`, the HMAC wake POST and
the long-poll `GET /api/v2/ssh/hosts/wait`). Delivery is the agent's 15-minute
timer plus the ETag/304 KRL pull, so what has to stay provable is the negative:

- the removed endpoints answer 404 for every method, and the agent-facing
  surface is exactly enroll / check-in / renew;
- no create/update payload field can name a callback, and none is stored;
- enrolling, checking in, renewing, revoking and deleting never open an
  outbound connection — every HTTP client in the process is watched for the
  whole host lifecycle;
- neither agent script (POSIX, PowerShell) carries wake / wait / callback code,
  and both only ever call UCM, never the other way round.

Uses the shared conftest fixtures: app, client, auth_client.
"""
import inspect
import json
import re
import subprocess
import uuid

import pytest

from models import db
from models.ssh import SSHManagedHost
from services.ucm_agent_scripts import build_agent_runner, build_agent_setup_script
from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json

UCM_URL = 'https://ucm.test.example.com:8443'

HOST_ROUTES = {
    '/api/v2/ssh/hosts',
    '/api/v2/ssh/hosts/<int:host_id>',
    '/api/v2/ssh/hosts/enroll',
    '/api/v2/ssh/hosts/renew',
    '/api/v2/ssh/hosts/check-in',
    '/api/v2/ssh/hosts/<int:host_id>/bootstrap',
    '/api/v2/ssh/hosts/<int:host_id>/rotate-token',
    '/api/v2/ssh/hosts/<int:host_id>/revoke-cert',
    '/api/v2/ssh/hosts/<int:host_id>/force-renew',
}

# Every word the removed Mode A/Mode B contract used in code and messages.
FORBIDDEN = ('callback', 'wait', 'wake', 'hmac', 'long-poll', 'longpoll',
             'x-ucm-signature', 'wake_token', 'push')

AGENT_ENDPOINTS = {'/api/v2/ssh/hosts/enroll', '/api/v2/ssh/hosts/renew',
                   '/api/v2/ssh/hosts/check-in'}


def _uniq(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:10]}.test.example.com"


def _register(auth_client, host_ca_id, user_ca_id=None, **extra):
    r = post_json(auth_client, '/api/v2/ssh/hosts', {
        'host_ca_id': host_ca_id, 'user_ca_id': user_ca_id, **extra})
    assert r.status_code == 201, r.data
    data = r.get_json()['data']
    return data['host'], data['bootstrap_token']


def _enroll(client, bootstrap, hostname=None, public_key=None):
    return client.post('/api/v2/ssh/hosts/enroll', data=json.dumps({
        'bootstrap_token': bootstrap,
        'hostname': hostname or _uniq('pull'),
        'public_key': public_key or _generate_test_ssh_key()}),
        content_type='application/json')


@pytest.fixture
def host_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='host', descr='Pull-only host CA',
                          allow_any_principal=True)


@pytest.fixture
def user_ca(auth_client):
    return _create_ssh_ca(auth_client, ca_type='user', descr='Pull-only user CA',
                          allow_any_principal=True)


@pytest.fixture
def egress_probe(monkeypatch):
    """Record every outbound HTTP attempt the process makes.

    Only HTTP clients are watched: the test application's own database
    connection (PostgreSQL in the PG job) must keep working.
    """
    calls = []

    def record(kind):
        def spy(*args, **kwargs):
            calls.append((kind, args, kwargs))
            raise OSError(f'test egress probe blocked {kind}')
        return spy

    import http.client
    import urllib.request

    import requests

    monkeypatch.setattr(requests.Session, 'request', record('requests.Session.request'))
    for name in ('get', 'post', 'put', 'delete', 'request', 'head', 'patch'):
        monkeypatch.setattr(requests, name, record(f'requests.{name}'))
    monkeypatch.setattr(urllib.request, 'urlopen', record('urllib.urlopen'))
    monkeypatch.setattr(http.client.HTTPConnection, 'request',
                        record('http.client.request'))
    monkeypatch.setattr(http.client.HTTPSConnection, 'request',
                        record('http.client.request'))
    return calls


# ── the removed endpoints ────────────────────────────────────────────────────

class TestPushEndpointsAreGone:
    def test_hosts_wait_is_indistinguishable_from_a_route_that_never_existed(self,
                                                                             auth_client,
                                                                             client):
        """404 for GET (the SPA catch-all refuses an /api/ path), 405 for the other
        methods (Flask only has the catch-all's GET rule for it) — and, which is
        the point, exactly what a path with no rule at all answers. Nothing is
        registered under `wait`, and nothing streams."""
        for path in ('/api/v2/ssh/hosts/wait', '/api/v2/ssh/hosts/never-registered'):
            for method in ('get', 'post', 'put', 'delete', 'patch'):
                for c, label in ((auth_client, 'as admin'), (client, 'anonymous')):
                    r = getattr(c, method)(path)
                    assert r.status_code in (404, 405), f'{path} {method.upper()} {label}: {r.status_code}'
                    assert r.status_code != 200, f'{path} answered with a payload'
                    if r.status_code == 404:
                        assert r.mimetype != 'text/event-stream'

    def test_the_agent_surface_is_exactly_enroll_check_in_renew(self, app):
        with app.app_context():
            rules = {rule.rule for rule in app.url_map.iter_rules()
                     if rule.rule.startswith('/api/v2/ssh/hosts')}
        assert rules == HOST_ROUTES, rules
        assert not any('wait' in rule for rule in rules)

    def test_agent_methods_are_narrow(self, app):
        """No long-poll GET sneaks onto an agent route."""
        with app.app_context():
            agent_rules = {rule.rule: sorted(rule.methods - {'HEAD', 'OPTIONS'})
                           for rule in app.url_map.iter_rules()
                           if rule.rule.startswith('/api/v2/ssh/hosts')
                           and rule.rule.split('/')[-1] in ('enroll', 'renew', 'check-in')}
        assert agent_rules == {'/api/v2/ssh/hosts/enroll': ['POST'],
                               '/api/v2/ssh/hosts/renew': ['POST'],
                               '/api/v2/ssh/hosts/check-in': ['POST']}

    def test_the_registry_columns_have_no_callback_or_wake_field(self, app):
        from sqlalchemy import inspect as sa_inspect
        with app.app_context():
            columns = {c['name'] for c in sa_inspect(db.engine)
                       .get_columns('ssh_managed_hosts')}
        assert not {c for c in columns if 'callback' in c or 'wake' in c or 'url' in c}
        assert not hasattr(SSHManagedHost, 'callback_url')
        assert not hasattr(SSHManagedHost, 'wake_url')


# ── payloads cannot name a callback ─────────────────────────────────────────

class TestPayloadHasNoCallback:
    def test_create_ignores_every_push_field(self, app, auth_client, host_ca, user_ca):
        name = _uniq('pushpayload')
        r = post_json(auth_client, '/api/v2/ssh/hosts', {
            'host_ca_id': host_ca['id'], 'user_ca_id': user_ca['id'], 'hostname': name,
            'callback_url': 'https://10.0.0.5:8443/ucm-wake',
            'wake_url': 'https://10.0.0.5:8443/ucm-wake',
            'callback_token': 'secret', 'hmac_secret': 'secret',
            'wake_on_revocation': True, 'long_poll': True})
        assert r.status_code == 201, r.data
        body = json.dumps(r.get_json()).lower()
        assert 'callback' not in body and 'wake' not in body
        with app.app_context():
            row = SSHManagedHost.query.filter_by(hostname=name).first()
            db.session.expire(row)
            assert row.hostname == name
            stored = {c.name for c in row.__table__.columns}
            assert not {c for c in stored if 'callback' in c or 'wake' in c}

    def test_install_command_points_at_ucm_only(self, auth_client, host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('cmd'))
        r = post_json(auth_client, '/api/v2/ssh/hosts',
                      {'host_ca_id': host_ca['id'], 'hostname': _uniq('cmd2')})
        command = r.get_json()['data']['install_command']
        assert '/ssh/agent-setup?token=ucm_boot_' in command
        # the target server never appears as a destination — the host pulls it
        assert 'sudo bash' in command and command.count('http') == 1

    def test_patch_with_a_push_field_changes_only_auto_renew(self, app, auth_client,
                                                              host_ca):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('patchme'))
        r = _enroll(auth_client, bootstrap, hostname=host['hostname'])
        assert r.status_code == 201, r.data
        r = auth_client.patch(f"/api/v2/ssh/hosts/{host['id']}", data=json.dumps({
            'auto_renew': False, 'callback_url': 'https://10.0.0.5:8443/wake'}),
            content_type='application/json')
        assert r.status_code == 200, r.data
        assert r.get_json()['data']['auto_renew'] is False
        assert 'callback' not in json.dumps(r.get_json()).lower()
        with app.app_context():
            db.session.expire_all()
            assert db.session.get(SSHManagedHost, host['id']).auto_renew is False


# ── nothing in UCM reaches out to a host ─────────────────────────────────────

class TestNoOutboundConnection:
    def test_the_pull_modules_import_no_network_client(self):
        """Static proof: the pull-model code cannot open a connection."""
        import services.ssh_managed_host_service as svc
        import services.ucm_agent_scripts as scripts
        from api.v2.ssh import host_management
        for module in (svc, scripts, host_management):
            source = inspect.getsource(module)
            for client in ('import requests', 'import urllib', 'import socket',
                           'import subprocess', 'import paramiko', 'from requests',
                           'from urllib', 'from socket'):
                assert client not in source, f'{module.__name__} uses {client}'

    def test_a_full_host_lifecycle_opens_no_egress_connection(self, app, auth_client,
                                                               client, host_ca, user_ca,
                                                               egress_probe):
        """create → installer → enroll → check-in → renew → force-renew → revoke →
        delete, with every HTTP client in the process blocked and recorded."""
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                    hostname=_uniq('noegress'))
        assert client.get(f'/ssh/agent-setup?token={bootstrap}').status_code == 200

        r = _enroll(client, bootstrap, hostname=host['hostname'])
        assert r.status_code == 201, r.data
        token = r.get_json()['data']['host_token']

        for _ in range(3):
            assert client.post('/api/v2/ssh/hosts/check-in', data=json.dumps({'krl_etag': '0'}),
                               content_type='application/json',
                               headers={'X-Host-Token': token}).status_code == 200
        assert client.post('/api/v2/ssh/hosts/renew',
                           headers={'X-Host-Token': token}).status_code == 200
        assert post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/force-renew",
                         {}).status_code == 200
        assert post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/rotate-token",
                         {}).status_code == 200
        assert post_json(auth_client, f"/api/v2/ssh/hosts/{host['id']}/revoke-cert",
                         {'reason': 'key compromise'}).status_code == 200
        assert auth_client.delete(f"/api/v2/ssh/hosts/{host['id']}").status_code == 204

        assert egress_probe == [], f'UCM reached out during the host lifecycle: {egress_probe}'

    def test_revoking_a_user_certificate_opens_no_egress_connection(self, auth_client,
                                                                     client, user_ca,
                                                                     egress_probe):
        """The KRL is pulled by the agents; UCM never pushes it."""
        r = post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': user_ca['id'], 'public_key': _generate_test_ssh_key(),
            'cert_type': 'user', 'principals': ['no-egress']})
        assert r.status_code == 201
        cert_id = r.get_json()['data']['id']
        assert client.get(f"/ssh/krl/{user_ca['refid']}").status_code == 200
        assert post_json(auth_client, f'/api/v2/ssh/certificates/{cert_id}/revoke',
                         {'reason': 'rotation'}).status_code == 200
        assert client.get(f"/ssh/krl/{user_ca['refid']}").status_code == 200
        assert egress_probe == [], egress_probe

    def test_a_host_token_is_not_a_credential_ucm_uses_outwards(self, auth_client,
                                                                 host_ca, egress_probe):
        host, bootstrap = _register(auth_client, host_ca['id'], hostname=_uniq('tokonly'))
        token = _enroll(auth_client, bootstrap, hostname=host['hostname']
                        ).get_json()['data']['host_token']
        # The token is only ever presented TO UCM; nothing in UCM authenticates
        # with it towards the host.
        assert auth_client.get('/api/v2/ssh/hosts',
                               headers={'X-API-Key': token}).status_code == 401
        assert egress_probe == [], egress_probe


# ── the agent scripts carry no push code ────────────────────────────────────

class TestAgentScriptsArePullOnly:
    @pytest.mark.parametrize('platform', ['unix', 'windows'])
    @pytest.mark.parametrize('builder', ['runner', 'setup'])
    def test_no_wake_wait_or_callback_code_anywhere(self, platform, builder):
        script = (build_agent_runner(platform) if builder == 'runner'
                  else build_agent_setup_script(UCM_URL, 'ucm_boot_TOKEN', platform))
        low = script.lower()
        for word in FORBIDDEN:
            assert word not in low, f'{platform}/{builder} script mentions {word!r}'
        assert '/hosts/wait' not in low

    @pytest.mark.parametrize('platform', ['unix', 'windows'])
    def test_the_runner_calls_exactly_the_three_agent_endpoints(self, platform):
        low = build_agent_runner(platform).lower()
        found = set(re.findall(r'/api/v2/ssh/hosts/[a-z-]+', low))
        assert found == AGENT_ENDPOINTS, found

    @pytest.mark.parametrize('platform', ['unix', 'windows'])
    def test_the_installer_pulls_the_runner_from_ucm(self, platform):
        script = build_agent_setup_script(UCM_URL, 'ucm_boot_TOKEN', platform)
        low = script.lower()
        found = set(re.findall(r'/ssh/[a-z-]+', low))
        assert found == {'/ssh/agent-runner'}, found
        assert UCM_URL.lower() in low  # every request goes to UCM, never the other way

    def test_the_timer_is_the_delivery_guarantee(self):
        """Per #451 the 15-minute pull timer is the whole delivery contract."""
        unix = build_agent_setup_script(UCM_URL, 'ucm_boot_TOKEN', 'unix')
        windows = build_agent_setup_script(UCM_URL, 'ucm_boot_TOKEN', 'windows')
        assert 'OnUnitActiveSec=15min' in unix
        assert '/SC MINUTE /MO 15' in windows
        assert 'ucm-ssh-agent.timer' in unix and 'schtasks' in windows

    def test_scripts_parse_under_sh_and_bash(self, tmp_path):
        """Checklist §3: a syntax error in the runner bricks the fleet install."""
        for platform in ('unix',):
            for name, script in (('runner', build_agent_runner(platform)),
                                 ('setup', build_agent_setup_script(UCM_URL, 'ucm_boot_T', platform))):
                path = tmp_path / f'{name}.sh'
                path.write_text(script)
                for interp in ('sh', 'bash'):
                    proc = subprocess.run([interp, '-n', str(path)],
                                          capture_output=True, text=True)
                    assert proc.returncode == 0, f'{interp} -n {name}: {proc.stderr}'


# ── KRL ETag/304 + generation cost, re-proved independently ─────────────────

class TestAgentAnswersCarryUtcTimestamps:
    """Review round 1, MINOR 7: `valid_to` in the enroll/renew answers was a bare
    isoformat() of a naive UTC value, which a browser reads as local time. Both
    answers now go through `utc_isoformat` like every other answer in the suite, and
    they still name the same instant the stored certificate carries (D6)."""

    def test_enroll_and_renew_answer_utc_isoformat_of_the_stored_window(
            self, app, auth_client, client, host_ca, user_ca):
        from datetime import datetime, timezone
        name = _uniq('utcZ')
        _host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'], hostname=name)

        enrolled = _enroll(client, bootstrap, hostname=name)
        assert enrolled.status_code == 201, enrolled.data
        answer = enrolled.get_json()['data']
        assert answer['valid_to'].endswith('Z'), answer['valid_to']
        assert '+00:00' not in answer['valid_to'] and answer['valid_to'].count('Z') == 1

        with app.app_context():
            db.session.expire_all()
            stored_at_enroll = SSHManagedHost.query.filter_by(
                hostname=name).first().current_cert.valid_to

        renewed = client.post('/api/v2/ssh/hosts/renew', headers={'X-Host-Token':
                                                                  answer['host_token']})
        assert renewed.status_code == 200, renewed.data
        fresh = renewed.get_json()['data']
        assert fresh['valid_to'].endswith('Z'), fresh['valid_to']

        with app.app_context():
            db.session.expire_all()
            stored_at_renew = SSHManagedHost.query.filter_by(
                hostname=name).first().current_cert.valid_to

        def naive_utc(value):
            """The D6 convention: the stored column is a naive UTC wall clock."""
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            assert parsed.utcoffset() == timezone.utc.utcoffset(None), value
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)

        assert naive_utc(answer['valid_to']) == stored_at_enroll
        assert naive_utc(fresh['valid_to']) == stored_at_renew


class TestKrlPullMechanics:
    def test_generation_happens_once_per_krl_version(self, app, auth_client, client,
                                                     monkeypatch, user_ca):
        import services.ssh_krl_service as krl_mod

        runs = []
        original = krl_mod.SSHKRLService.generate_krl
        monkeypatch.setattr(krl_mod.SSHKRLService, 'generate_krl',
                            staticmethod(lambda ca_id: (runs.append(ca_id), original(ca_id))[1]))

        for _ in range(8):
            r = client.get(f"/ssh/krl/{user_ca['refid']}")
            assert r.status_code == 200 and r.headers['ETag'] == '"0"'
        assert len(runs) == 1, f'KRL regenerated {len(runs)} times without a revocation'

        cert = post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': user_ca['id'], 'public_key': _generate_test_ssh_key(),
            'cert_type': 'user', 'principals': ['krl-pull']}).get_json()['data']
        post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                  {'reason': 'rotation'})

        r = client.get(f"/ssh/krl/{user_ca['refid']}")
        assert r.headers['ETag'] == '"1"' and r.headers['X-KRL-Version'] == '1'
        assert len(runs) == 2

        stale = client.get(f"/ssh/krl/{user_ca['refid']}", headers={'If-None-Match': '"1"'})
        assert stale.status_code == 304 and stale.data == b'' and stale.headers['ETag'] == '"1"'
        assert len(runs) == 2  # 304 short-circuits before any ssh-keygen run

    def test_the_krl_bytes_are_binary_safe_and_cached_by_version(self, app, auth_client,
                                                                  client, user_ca):
        """The agent writes these bytes with `cat`, NULs included — the file it
        writes must be byte-identical to what UCM served."""
        first = client.get(f"/ssh/krl/{user_ca['refid']}")
        assert first.data.startswith(b'SSHKRL') and b'\x00' in first.data
        cert = post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': user_ca['id'], 'public_key': _generate_test_ssh_key(),
            'cert_type': 'user', 'principals': ['krl-bytes']}).get_json()['data']
        post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                  {'reason': 'rotation'})
        second = client.get(f"/ssh/krl/{user_ca['refid']}")
        assert second.status_code == 200
        assert second.data != first.data and b'\x00' in second.data
        third = client.get(f"/ssh/krl/{user_ca['refid']}")
        assert third.data == second.data  # cached per krl_version, byte-stable

    def test_check_in_compares_the_etag_the_agent_stores(self, app, auth_client, client,
                                                          host_ca, user_ca):
        """The agent saves the unquoted ETag and replays it to check-in; the
        server must read it as a krl_version, not as an opaque string."""
        host, bootstrap = _register(auth_client, host_ca['id'], user_ca['id'],
                                    hostname=_uniq('etagmatch'))
        token = _enroll(auth_client, bootstrap, hostname=host['hostname']
                        ).get_json()['data']['host_token']
        etag = client.get(f"/ssh/krl/{user_ca['refid']}").headers['ETag'].strip('"')

        def check(value):
            return client.post('/api/v2/ssh/hosts/check-in',
                               data=json.dumps({'krl_etag': value}),
                               content_type='application/json',
                               headers={'X-Host-Token': token}).get_json()['data']

        assert check(etag)['krl_changed'] is False
        cert = post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': user_ca['id'], 'public_key': _generate_test_ssh_key(),
            'cert_type': 'user', 'principals': ['etag-move']}).get_json()['data']
        post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                  {'reason': 'rotation'})
        moved = check(etag)
        assert moved['krl_changed'] is True and moved['krl_version'] == 1
        assert check(str(moved['krl_version']))['krl_changed'] is False
