"""SSH CA deployment bindings: what saving a binding probes on the target, what each
delivery writes, and how a host certificate names the target it was signed for."""
import json
import shutil

import pytest

from models import db, DeployDelivery, SSHCADeployBinding
from services.deploy import ssh as ssh_mod
from services.deploy.service import SSH_CERT_EVENTS, DeployService
from services.deploy.ssh_ca import CANONICAL_DIR, FULL_EVENTS, PROBE_SUFFIX, artifact_defaults, \
    resolve_files
from tests.conftest import assert_success, get_json
from tests.deploy_leftovers import delete_leftovers
from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json

BASE = '/api/v2/deploy'
SUDO_PROBE = 'sudo -k -n -v'      # the exact command services/deploy/ssh_ca.py probes the grant with
_seq = [0]

# Binding, delivery and certificate rows carry ids a later file of the worker reuses
_cleanup = pytest.fixture(autouse=True)(delete_leftovers)


def _name(prefix):
    _seq[0] += 1
    return f'{prefix}-{_seq[0]}'


def _target(auth_client, **overrides):
    payload = {'name': _name('sshca-target'), 'host': 'host1.example.test',
               'username': 'ucm-deploy'}
    payload.update(overrides)
    return assert_success(post_json(auth_client, f'{BASE}/targets', payload), status=201)


def _paths(name, host_cert=True):
    """The artefact paths of one binding, named after the binding itself: two bindings of
    one target collide only when a test says so."""
    out = {'ca_pub_path': f'{CANONICAL_DIR}/{name}.pub',
           'krl_path': f'{CANONICAL_DIR}/{name}_revoked_keys'}
    if host_cert:
        out['host_cert_path'] = f'{CANONICAL_DIR}/{name}_host_key-cert.pub'
    return out


def _attach(auth_client, ca, target, host_cert=True, principals='default', **overrides):
    """Attach a CA to a target with the paths a default dialog would send."""
    payload = dict(_paths(_name('artefacts'), host_cert), target_id=target['id'], **overrides)
    if principals == 'default':
        if host_cert:
            payload['principals'] = [target['host']]
    elif principals is not None:
        payload['principals'] = principals
    return post_json(auth_client, f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings", payload)


def _listing(auth_client, ca_id):
    return assert_success(auth_client.get(f"/api/v2/ssh/cas/{ca_id}/deploy-bindings"))


def _binding(app, ca_id, target_id):
    """The stored binding in its API form, or None: what the row the save left behind is."""
    with app.app_context():
        row = SSHCADeployBinding.query.filter_by(ssh_ca_id=ca_id, target_id=target_id).first()
        return row.to_dict() if row else None


def _ca(app, ca_id):
    from models.ssh import SSHCertificateAuthority
    with app.app_context():
        return db.session.get(SSHCertificateAuthority, ca_id)


def _problem(response):
    body = get_json(response)
    return body, (body.get('details') or {}).get('fields') or {}


class _Host:
    """A target that answers: the host keys it publishes, the sudo grant its account has,
    and everything UCM wrote, removed or ran there."""

    PINNED = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIpinOfTheTestTarget000000000000000000'

    def __init__(self, monkeypatch, publishes=(), sudo_ok=True, exec_ok=True, refuse=(),
                 refuse_remove=()):
        self.publishes = list(publishes)
        self.sudo_ok, self.exec_ok = sudo_ok, exec_ok
        self.refuse = list(refuse)      # artefact paths whose write this target refuses
        self.refuse_remove = list(refuse_remove)   # paths whose removal this target refuses
        self.pushed, self.removed = [], []
        self.files = []                 # what is on the host right now, in the order written
        self.sudo_checks, self.key_reads, self.reloaded = [], [], []

        test = self

        class _Sftp:
            def remove(self, path):
                test.removed.append(path)
                if any(taken in path for taken in test.refuse_remove):
                    raise OSError(f'Cannot remove {path}: Operation not permitted')
                if path in test.files:
                    test.files.remove(path)

            def close(self):
                pass

        class _Client:
            def open_sftp(self):
                return _Sftp()

            def close(self):
                pass

        def open_client(host, port, username, key_text, expected):
            if expected is not None and expected != test.PINNED:
                raise ssh_mod.HostKeyMismatch(f'Host key verification failed: {expected}')
            return _Client(), test.PINNED

        def push_files(client, files):
            for path, content, mode in files:
                if any(taken in path for taken in test.refuse):
                    raise ssh_mod.DeploySSHError(f'SFTP write to {path} failed: Permission denied')
                test.pushed.append((path, content, mode))
                test.files.append(path)

        def read_stdout(client, command):
            if command == SUDO_PROBE:
                test.sudo_checks.append(command)
                return (0, '', '') if test.sudo_ok else (1, '', 'sudo: a password is required')
            if command.startswith('cat '):
                test.key_reads.append(command)
                if not test.exec_ok:
                    raise ssh_mod.DeploySSHError('Command failed to run on the target: exec refused')
                return 0, ''.join(line + '\n' for line in test.publishes), ''
            test.reloaded.append(command)
            return 0, '', ''

        monkeypatch.setattr(ssh_mod, 'open_client', open_client)
        monkeypatch.setattr(ssh_mod, 'push_files', push_files)
        monkeypatch.setattr(ssh_mod, 'read_stdout', read_stdout)

    def wrote(self):
        return [path for path, _, _ in self.pushed]


def _host_key(algorithm):
    """One public key line, in the form sshd publishes it under /etc/ssh."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import ssh as ssh_serialization

    key = (ed25519.Ed25519PrivateKey.generate() if algorithm == 'ed25519' else
           ec.generate_private_key(ec.SECP256R1()) if algorithm == 'ecdsa' else
           rsa.generate_private_key(public_exponent=65537, key_size=2048))
    return ssh_serialization.serialize_ssh_public_key(key.public_key()).decode()


def _deliver(app, binding_id, event):
    """One delivery, as the queue runs it: (delivered, status, last_error)."""
    with app.app_context():
        delivery = DeployDelivery(binding_id=binding_id,
                                  binding_type=DeployDelivery.BINDING_SSH_CA,
                                  event_type=event, status=DeployDelivery.STATUS_PENDING,
                                  max_attempts=1)
        db.session.add(delivery)
        db.session.commit()
        delivered = DeployService.execute_delivery(delivery)
        db.session.commit()
        return delivered, delivery.status, delivery.last_error


def _pending_deliveries(app, binding_ids):
    """The pending deliveries of these bindings, whatever event each one carries.

    A revocation that lands on a still-pending delivery reuses that row and keeps the
    wider job it already owed (KRL-12), so filtering by event type would hide exactly
    the row the claim is about."""
    with app.app_context():
        return (DeployDelivery.query
                .filter_by(binding_type=DeployDelivery.BINDING_SSH_CA,
                           status=DeployDelivery.STATUS_PENDING)
                .filter(DeployDelivery.binding_id.in_(binding_ids)).all())


def _drain(app):
    """Run the delivery queue once, the way the scheduler does it."""
    if not shutil.which('ssh-keygen'):
        pytest.skip('draining a KRL delivery builds the KRL with ssh-keygen')
    with app.app_context():
        return DeployService.process_pending_deliveries()


def _rows_for(app, binding_id):
    """Every delivery row one binding has, pending or settled."""
    with app.app_context():
        return (DeployDelivery.query
                .filter_by(binding_id=binding_id,
                           binding_type=DeployDelivery.BINDING_SSH_CA).all())


@pytest.fixture
def reader(app, auth_client):
    """A signed-in account of a built-in role, removed again with the test.

    `operator` and `viewer` both read SSH CAs and certificates and neither reads deployments:
    that is exactly the pair the deploy-related fields must not leak to.
    """
    made = []

    def _reader(role):
        name = _name(f'sshca-{role}')
        created = assert_success(post_json(auth_client, '/api/v2/users', {
            'username': name, 'password': 'ReaderPass123!', 'email': f'{name}@ucm.test',
            'role': role}), status=201)
        account = app.test_client()
        signed_in = account.post('/api/v2/auth/login', content_type='application/json',
                                 data=json.dumps({'username': name, 'password': 'ReaderPass123!'}))
        assert signed_in.status_code == 200, signed_in.data
        made.append((name, created['id']))
        return account

    yield _reader
    for _name_, user_id in made:
        auth_client.delete(f'/api/v2/users/{user_id}')


def _issued_host_certificate(auth_client, monkeypatch, descr):
    """A host CA bound to a target with no KRL path, its host certificate signed by a Deploy
    now. Returns (ca, target, binding, certificate)."""
    _Host(monkeypatch, publishes=[_host_key('ed25519')])
    ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name(descr))
    target = _target(auth_client)
    created = assert_success(_attach(auth_client, ca, target, principals=['host1.example.test', 'host1'],
                                     krl_path=None), status=201)
    deploy = auth_client.post(f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings/{created['id']}/deploy")
    assert deploy.status_code == 200, deploy.data
    certificate = next(b for b in _listing(auth_client, ca['id'])['bindings']
                       if b['id'] == created['id'])['host_certificate']
    return ca, target, created, certificate


class TestReloadCommandIsOneCommand:
    """The reload command is handed to the target's shell verbatim, so a chained one is a way to
    run anything on that host through a field whose whole job is "reload sshd", and a
    redirection through it is a way to write whatever that account can reach."""

    CHAINED = ['sudo systemctl reload sshd; sudo rm -rf /etc/ssh/ssh_ca_keys',
               'sudo systemctl reload sshd && echo reloaded',
               'sudo systemctl reload sshd || echo failed',
               'sudo systemctl reload sshd | tee /tmp/reload.log',
               'sudo systemctl reload sshd & sleep 1',
               'sudo systemctl reload sshd\nsudo systemctl restart sshd',
               'sudo systemctl reload sshd\rsudo systemctl restart sshd',
               'sudo systemctl reload `id -u`',
               'sudo systemctl reload $(echo sshd)',
               'sudo systemctl reload sshd > /tmp/reload.log',
               'sudo systemctl reload sshd >> /etc/ssh/ssh_ca_keys/ucm_hosts.pub',
               'sudo systemctl reload sshd < /dev/null']

    @pytest.mark.parametrize('command', CHAINED)
    def test_a_chained_reload_command_is_refused_under_the_field_it_concerns(
            self, app, auth_client, monkeypatch, command):
        host = _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Chained reload CA'))
        target = _target(auth_client)
        response = _attach(auth_client, ca, target, reload_command=command)
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['reload_command']
        assert entry['i18n_key'] == 'sshDeploy.errors.reloadChained'
        assert 'one command' in entry['message']
        # Refused before anything was asked of the target, and nothing was left configured
        assert host.wrote() == [] and host.sudo_checks == []
        assert _binding(app, ca['id'], target['id']) is None

    def test_a_single_command_with_a_path_and_flags_is_accepted(self, app, auth_client, monkeypatch):
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Single reload CA'))
        target = _target(auth_client)
        command = 'sudo -n /usr/bin/systemctl reload sshd'
        created = assert_success(_attach(auth_client, ca, target, reload_command=command), status=201)
        assert _binding(app, ca['id'], target['id'])['reload_command'] == command
        assert created['reload_command'] == command

    def test_a_chained_command_written_later_is_refused_and_changes_nothing(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Chained patch CA'))
        target = _target(auth_client)
        command = 'sudo systemctl reload sshd'
        created = assert_success(_attach(auth_client, ca, target, reload_command=command), status=201)
        response = auth_client.patch(f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings/{created['id']}",
                                     data=json.dumps({'reload_command': f'{command} && id'}),
                                     content_type='application/json')
        assert response.status_code == 422, response.data
        assert _problem(response)[1]['reload_command']['i18n_key'] == 'sshDeploy.errors.reloadChained'
        assert _binding(app, ca['id'], target['id'])['reload_command'] == command


class TestWhatADeployReaderSees:
    """Which target a host certificate was signed for, how many targets carry a CA's artefacts
    and which of them are missing its KRL is deployment information (design: a reader without
    the deploy right sees nothing deploy-related)."""

    @pytest.mark.parametrize('role', ('operator', 'viewer'))
    def test_the_certificate_list_and_detail_name_no_target_without_the_deploy_right(
            self, app, auth_client, monkeypatch, reader, role):
        ca, target, _created, certificate = _issued_host_certificate(auth_client, monkeypatch,
                                                                     'Hidden target CA')
        # The admin who deployed it sees the target in both places
        listed = assert_success(auth_client.get(f"/api/v2/ssh/certificates?ca_id={ca['id']}"))
        mine = next(c for c in listed if c['id'] == certificate['id'])
        assert mine['deploy_target_id'] == target['id']
        assert mine['deploy_target_name'] == target['name']
        assert 'deploy_target_path' not in mine
        detail = assert_success(auth_client.get(f"/api/v2/ssh/certificates/{certificate['id']}"))
        assert detail['deploy_target_path']

        account = reader(role)
        listed = assert_success(account.get(f"/api/v2/ssh/certificates?ca_id={ca['id']}"))
        row = next(c for c in listed if c['id'] == certificate['id'])
        assert row['deploy_target_id'] is None and row['deploy_target_name'] is None
        assert 'deploy_target_path' not in row

        detail = assert_success(account.get(f"/api/v2/ssh/certificates/{certificate['id']}"))
        assert detail['deploy_target_id'] is None and detail['deploy_target_name'] is None
        assert 'deploy_target_path' not in detail
        # The certificate itself is still the reader's to read: only the target is withheld
        assert detail['cert_type'] == 'host' and detail['source'] == 'deploy'
        assert detail['created_by'] == 'admin'

    @pytest.mark.parametrize('role', ('operator', 'viewer'))
    def test_the_ca_list_and_card_carry_no_deploy_state_without_the_deploy_right(
            self, app, auth_client, monkeypatch, reader, role):
        _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Reader CA'))
        assert _attach(auth_client, ca, _target(auth_client), host_cert=False).status_code == 201
        # Not drained: the bound target is one of the targets missing this CA's current KRL
        mine = next(c for c in assert_success(auth_client.get('/api/v2/ssh/cas'))
                    if c['id'] == ca['id'])
        assert mine['deploy_targets_total'] == 1 and mine['krl_undelivered_targets'] == 1
        assert mine['deploy_defaults'] == artifact_defaults(_ca(app, ca['id']))

        account = reader(role)
        row = next(c for c in assert_success(account.get('/api/v2/ssh/cas')) if c['id'] == ca['id'])
        assert row['deploy_targets_total'] == 0 and row['krl_undelivered_targets'] == 0
        assert row['deploy_defaults'] is None
        card = assert_success(account.get(f"/api/v2/ssh/cas/{ca['id']}"))
        assert card['krl_undelivered_targets'] == 0 and card['deploy_defaults'] is None
        # The bindings of the CA are a deploy route: a reader without the right cannot list them
        assert account.get(f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings").status_code == 403


class TestSaveTimeProbe:
    """Saving probes the privileges the binding asks for, in one SSH session, and refuses
    with one entry per field it concerns (422 + details.fields), or 502 when unreachable."""

    def test_a_probe_file_is_written_and_taken_back_out_of_every_non_empty_path(
            self, app, auth_client, monkeypatch):
        host = _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Probe user CA'))
        target = _target(auth_client)
        assert _attach(auth_client, ca, target, host_cert=False).status_code == 201

        binding = _binding(app, ca['id'], target['id'])
        named = [p for p in (binding['ca_pub_path'], binding['krl_path'], binding['host_cert_path'])
                 if p]
        assert named and binding['host_cert_path'] is None
        # Each named path was probed with an empty file of its own and removed again; the
        # unset path was not probed, and nothing ran: this binding sets no reload command
        assert host.wrote() == [p + PROBE_SUFFIX for p in named]
        assert [content for _, content, _ in host.pushed] == [b''] * len(named)
        assert host.removed == [p + PROBE_SUFFIX for p in named]
        assert host.key_reads == [] and host.sudo_checks == [] and host.reloaded == []

    def test_a_probe_file_the_host_will_not_give_back_leaves_the_save_accepted(
            self, app, auth_client, monkeypatch):
        """The probe answered one question — can this account write here — and a removal the
        host refuses does not change the answer. Refusing the save over it would hold a binding
        hostage to a file that is not an artefact and not anyone's delivery."""
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Probe stuck CA'))
        target = _target(auth_client)
        payload = dict(_paths('stuck', host_cert=False), target_id=target['id'])
        stuck = payload['krl_path']
        host = _Host(monkeypatch, refuse_remove=[stuck])

        assert_success(post_json(auth_client, f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings", payload),
                       status=201)
        assert _binding(app, ca['id'], target['id']) is not None

        named = [p for p in (payload['ca_pub_path'], payload['krl_path']) if p]
        probes = [p + PROBE_SUFFIX for p in named]
        # Every named path was still probed, and UCM still tried to take every probe file back
        assert host.wrote() == probes and host.removed == probes
        # The one this host refused to give back is the only thing left on it: a `.ucm-probe`,
        # never an artefact path, so nothing sshd reads was touched by the save.
        assert host.files == [stuck + PROBE_SUFFIX]
        assert all(path not in host.files for path in named)
        assert host.key_reads == [] and host.sudo_checks == [] and host.reloaded == []

    def test_the_sudo_grant_is_probed_only_when_a_reload_command_is_set(
            self, app, auth_client, monkeypatch):
        host = _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Probe sudo CA'))
        target = _target(auth_client)
        command = 'sudo systemctl reload sshd'
        assert _attach(auth_client, ca, target, reload_command=command).status_code == 201
        assert host.sudo_checks == [SUDO_PROBE]
        # The grant is checked, not acted on: attaching does not reload a host yet
        assert host.reloaded == []

    def test_a_refused_probe_write_refuses_the_save_naming_the_account_and_the_right(
            self, app, auth_client, monkeypatch):
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Probe unwritable CA'))
        target = _target(auth_client)
        payload = dict(_paths('unwritable', host_cert=False), target_id=target['id'])
        taken = payload['krl_path']
        host = _Host(monkeypatch, refuse=[taken])
        response = post_json(auth_client, f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings", payload)
        assert response.status_code == 422, response.data
        body, fields = _problem(response)
        entry = fields['krl_path']
        assert entry['i18n_key'] == 'sshDeploy.errors.pathNotWritable'
        assert entry['values'] == {'path': taken, 'directory': CANONICAL_DIR, 'user': 'ucm-deploy'}
        assert 'write access' in entry['message'] and 'ucm-deploy' in entry['message']
        assert 'ucm-deploy' in body['message']
        # Nothing half-configured is left: the row the save flushed before probing is gone
        assert _binding(app, ca['id'], target['id']) is None
        # The path that answered is the one the probe was going to write
        assert host.wrote() == [payload['ca_pub_path'] + PROBE_SUFFIX]

    def test_a_missing_sudo_grant_refuses_the_save_under_the_reload_command(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch, publishes=[_host_key('ed25519')], sudo_ok=False)
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Probe no sudo CA'))
        target = _target(auth_client)
        command = 'sudo systemctl reload sshd'
        response = _attach(auth_client, ca, target, reload_command=command)
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['reload_command']
        assert entry['i18n_key'] == 'sshDeploy.errors.sudoRequired'
        assert entry['values'] == {'user': 'ucm-deploy', 'command': command}
        assert 'NOPASSWD' in entry['message']
        assert _binding(app, ca['id'], target['id']) is None

    def test_an_unreachable_target_answers_502_and_not_as_a_permission_problem(
            self, app, auth_client, monkeypatch):
        def refuse_connection(host, port, username, key_text, expected):
            raise ssh_mod.DeploySSHError('SSH connection failed: [Errno 111] Connection refused')

        monkeypatch.setattr(ssh_mod, 'open_client', refuse_connection)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Probe unreachable CA'))
        target = _target(auth_client)
        response = _attach(auth_client, ca, target, host_cert=False)
        assert response.status_code == 502, response.data
        assert 'Connection refused' in get_json(response)['message']
        assert _binding(app, ca['id'], target['id']) is None

    def test_the_key_ucm_signs_is_the_one_sshd_prefers(self, app, auth_client, monkeypatch):
        # The host publishes its keys in an order that is not sshd's preference
        published = [_host_key('rsa'), _host_key('ed25519'), _host_key('ecdsa')]
        host = _Host(monkeypatch, publishes=published)
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Host key order CA'))
        target = _target(auth_client)
        assert _attach(auth_client, ca, target).status_code == 201
        assert _binding(app, ca['id'], target['id'])['host_public_key'] == published[1]
        # One read, in sshd's own order: /etc/ssh first, then the from-source location,
        # each of them ed25519, then ecdsa, then rsa
        command = host.key_reads[0]
        assert host.key_reads == [command] and command.count('cat ') == 1
        for name in ('ed25519', 'ecdsa', 'rsa'):
            assert command.index(f'/etc/ssh/ssh_host_{name}_key.pub') \
                < command.index(f'/usr/local/etc/ssh/ssh_host_{name}_key.pub')

    def test_without_an_ed25519_host_key_ucm_signs_the_ecdsa_one(
            self, app, auth_client, monkeypatch):
        published = [_host_key('rsa'), _host_key('ecdsa')]
        _Host(monkeypatch, publishes=published)
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Host key ecdsa CA'))
        target = _target(auth_client)
        assert _attach(auth_client, ca, target).status_code == 201
        assert _binding(app, ca['id'], target['id'])['host_public_key'] == published[1]

    def test_a_pasted_host_key_the_target_does_not_publish_is_refused(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Host key mismatch CA'))
        target = _target(auth_client)
        response = _attach(auth_client, ca, target, host_public_key=_host_key('ecdsa'))
        # A paste is checked against what the host runs; nothing is signed from a key UCM
        # invented. (docs/API_REFERENCE.md promises 409 here — see the release report.)
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['host_key']
        assert entry['i18n_key'] == 'sshDeploy.errors.hostKeyMismatch'
        assert entry['values']['host'] == target['host']
        assert _binding(app, ca['id'], target['id']) is None

    def test_a_target_that_refuses_exec_is_served_by_the_pasted_host_key(
            self, app, auth_client, monkeypatch):
        pasted = _host_key('ed25519')
        _Host(monkeypatch, publishes=[pasted], exec_ok=False)
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Exec refused CA'))
        target = _target(auth_client)
        assert _attach(auth_client, ca, target, host_public_key=pasted).status_code == 201, \
            'a chroot or internal-sftp target has to be attachable with a pasted key'
        assert _binding(app, ca['id'], target['id'])['host_public_key'] == pasted

    def test_a_target_that_refuses_exec_without_a_pasted_key_says_what_it_cannot_do(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch, exec_ok=False)
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Exec refused no key CA'))
        target = _target(auth_client)
        response = _attach(auth_client, ca, target)
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['host_key']
        assert entry['i18n_key'] == 'sshDeploy.hostKeyUnread'
        assert 'Paste' in entry['message'] and 'exec' in entry['message']
        assert _binding(app, ca['id'], target['id']) is None

    def test_the_probe_pins_the_host_key_it_connected_with_and_keeps_an_existing_pin(
            self, app, auth_client, monkeypatch):
        from models import DeployTarget

        _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Probe pinning CA'))
        target = _target(auth_client)
        assert _attach(auth_client, ca, target, host_cert=False).status_code == 201
        with app.app_context():
            assert db.session.get(DeployTarget, target['id']).host_key == _Host.PINNED

        pinned = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIthePinTheOperatorChose00000000000000'
        with app.app_context():
            db.session.get(DeployTarget, target['id']).host_key = pinned
            db.session.commit()
        host = _Host(monkeypatch)
        other = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Probe pinning CA 2'))
        response = _attach(auth_client, other, target, host_cert=False)
        # A pin is a trust decision: a key that differs from it fails closed, 409
        assert response.status_code == 409, response.data
        assert 'Host key verification failed' in get_json(response)['message']
        assert host.wrote() == [] and host.removed == []
        with app.app_context():
            assert db.session.get(DeployTarget, target['id']).host_key == pinned


class TestAttachRules:
    """What a save enforces before it probes anything."""

    def test_the_same_ca_on_the_same_target_twice_answers_409(self, app, auth_client, monkeypatch):
        _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Twice CA'))
        target = _target(auth_client)
        assert _attach(auth_client, ca, target, host_cert=False).status_code == 201
        assert _attach(auth_client, ca, target, host_cert=False).status_code == 409
        assert len(_listing(auth_client, ca['id'])['bindings']) == 1

    def test_two_cas_writing_one_file_on_one_target_are_refused_naming_both(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch)
        shared = _paths('shared', host_cert=False)
        first = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Collision CA one'))
        second = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Collision CA two'))
        target = _target(auth_client)
        assert _attach(auth_client, first, target, host_cert=False, **shared).status_code == 201
        response = _attach(auth_client, second, target, host_cert=False,
                           ca_pub_path=shared['ca_pub_path'],
                           krl_path=f'{CANONICAL_DIR}/second_revoked_keys')
        assert response.status_code == 409, response.data
        _, fields = _problem(response)
        assert list(fields) == ['ca_pub_path']
        assert fields['ca_pub_path']['i18n_key'] == 'sshDeploy.errors.pathTaken'
        assert first['descr'] in fields['ca_pub_path']['message']
        assert _binding(app, second['id'], target['id']) is None

    def test_a_user_ca_naming_a_host_certificate_field_is_refused(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('User CA host cert'))
        target = _target(auth_client)
        response = _attach(auth_client, ca, target)
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['host_cert_path']
        assert entry['i18n_key'] == 'sshDeploy.errors.hostCertNeedsHostCA'
        assert _binding(app, ca['id'], target['id']) is None

        # Host names on a user CA binding would read as "who may log in here"
        response = _attach(auth_client, ca, target, host_cert=False, principals=[target['host']])
        assert response.status_code == 422, response.data
        assert _problem(response)[1]['principals']['i18n_key'] == 'sshDeploy.errors.notForUserCA'

    def test_a_binding_principal_may_be_an_exact_name_the_ca_allows(
            self, app, auth_client, monkeypatch):
        # OpenSSH matches a host certificate's principals with strcmp: a pattern stored on
        # the binding is a principal no host ever matches, so patterns stay on the CA.
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        target = _target(auth_client)
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Principal pattern CA'),
                            allowed_principals=['host1.example.test'], allow_any_principal=False)
        response = _attach(auth_client, ca, target, principals=['host1.*'])
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['principals']
        assert entry['i18n_key'] == 'sshDeploy.errors.principalNotExact'
        response = _attach(auth_client, ca, target, principals=['other.example.net'])
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['principals']
        assert entry['i18n_key'] == 'sshDeploy.errors.principalNotAllowed'
        assert 'host1.example.test' in entry['values']['allowed']

    def test_validity_longer_than_the_cas_max_ttl_is_refused_not_clamped(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Max TTL CA'),
                            max_ttl=604800)
        target = _target(auth_client)
        response = _attach(auth_client, ca, target, validity=2592000)
        assert response.status_code == 422, response.data
        entry = _problem(response)[1]['validity']
        # The refusal is spelled in the durations the admin typed, not in seconds: an admin
        # who wrote 30d gets '30d is longer than ... (7d)', the same units the dialog shows.
        assert entry['values'] == {'validity': '30d', 'max_ttl': '7d'}
        assert entry['i18n_key'] == 'sshDeploy.errors.validityTooLong'
        assert '30d' in entry['message'] and '7d' in entry['message']
        assert '2592000' not in entry['message'] and '604800' not in entry['message']
        assert _binding(app, ca['id'], target['id']) is None

    def test_the_binding_list_offers_the_paths_the_default_attach_and_the_script_share(
            self, app, auth_client):
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Defaults CA'))
        defaults = _listing(auth_client, ca['id'])['ca']['deploy_defaults']
        assert defaults == artifact_defaults(_ca(app, ca['id']))
        assert defaults['ca_pub_path'].startswith(CANONICAL_DIR)
        assert defaults['krl_path'].endswith('_revoked_keys')
        assert defaults['host_cert_path'].endswith('_host_key-cert.pub')


class TestHostCertificateOfATarget:
    """A host certificate signed for a deploy target says so, and the detail names the
    file the binding writes it to."""

    def _issued(self, auth_client, monkeypatch, descr):
        return _issued_host_certificate(auth_client, monkeypatch, descr)

    def test_the_detail_names_the_target_and_the_file_the_binding_writes(
            self, app, auth_client, monkeypatch):
        ca, target, created, certificate = self._issued(auth_client, monkeypatch,
                                                        'Deployed host CA')
        assert certificate['status'] == 'valid'
        detail = assert_success(auth_client.get(f"/api/v2/ssh/certificates/{certificate['id']}"))
        assert detail['cert_type'] == 'host'
        assert detail['source'] == 'deploy'
        assert detail['deploy_target_id'] == target['id']
        assert detail['deploy_target_name'] == target['name']
        assert detail['deploy_target_path'] == created['host_cert_path']
        assert detail['principals'] == ['host1.example.test', 'host1']

    def test_the_certificate_list_names_the_target_but_not_its_path(
            self, app, auth_client, monkeypatch):
        ca, target, _created, certificate = self._issued(auth_client, monkeypatch,
                                                         'Listed host CA')
        listed = assert_success(auth_client.get(f"/api/v2/ssh/certificates?ca_id={ca['id']}"))
        row = next(c for c in listed if c['id'] == certificate['id'])
        assert row['deploy_target_id'] == target['id']
        assert row['deploy_target_name'] == target['name']
        assert 'deploy_target_path' not in row

    def test_a_certificate_signed_by_hand_carries_no_target(self, app, auth_client):
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Plain user CA'))
        cert = assert_success(post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': ca['id'], 'public_key': _generate_test_ssh_key(), 'cert_type': 'user',
            'principals': ['plain-user'], 'validity_seconds': 3600}), status=201)
        detail = assert_success(auth_client.get(f"/api/v2/ssh/certificates/{cert['id']}"))
        assert detail['deploy_target_id'] is None and detail['deploy_target_name'] is None
        assert 'deploy_target_path' not in detail


needs_ssh_keygen = pytest.mark.skipif(not shutil.which('ssh-keygen'),
                                      reason='the KRL is built with ssh-keygen')


@needs_ssh_keygen
class TestWhatEachDeliveryWrites:
    """A revoke or a delete refreshes the KRL and runs nothing; every other event writes
    what the binding names and runs its reload command."""

    def _bound(self, auth_client, monkeypatch, **overrides):
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Delivery CA'))
        target = _target(auth_client)
        created = assert_success(_attach(auth_client, ca, target,
                                         reload_command='sudo systemctl reload sshd', **overrides),
                                 status=201)
        return ca, target, created

    def test_the_full_events_write_every_path_the_binding_names(self, app, auth_client,
                                                                monkeypatch):
        ca, target, _created = self._bound(auth_client, monkeypatch)
        with app.app_context():
            binding = SSHCADeployBinding.query.filter_by(ssh_ca_id=ca['id'],
                                                         target_id=target['id']).first()
            paths = [p for p in (binding.ca_pub_path, binding.krl_path, binding.host_cert_path)
                     if p]
            for event in ('initial', 'binding.updated', 'manual'):
                files, needs_reload = resolve_files(binding, event)
                assert [path for path, _, _ in files] == paths
                assert needs_reload is True
            assert pytest.raises(ValueError, resolve_files, binding, 'certificate.issued')

    def test_a_krl_only_delivery_runs_no_reload_command_at_all(
            self, app, auth_client, monkeypatch):
        ca, target, created = self._bound(auth_client, monkeypatch)
        host = _Host(monkeypatch, publishes=[_host_key('ed25519')])
        for event in SSH_CERT_EVENTS:
            delivered, status, error = _deliver(app, created['id'], event)
            assert delivered is True, error
            assert status == DeployDelivery.STATUS_DELIVERED
            # Only the KRL is replaced, and the binding's command does not run: sshd
            # re-reads RevokedKeys on the next authentication
            assert host.wrote() == [_binding(app, ca['id'], target['id'])['krl_path']]
            assert host.reloaded == []
            host.pushed, host.reloaded = [], []

    def test_a_delivery_that_wrote_the_ca_key_or_the_host_certificate_runs_the_command(
            self, app, auth_client, monkeypatch):
        ca, target, created = self._bound(auth_client, monkeypatch)
        host = _Host(monkeypatch, publishes=[_host_key('ed25519')])
        delivered, status, error = _deliver(app, created['id'], 'manual')
        assert delivered is True, error
        binding = _binding(app, ca['id'], target['id'])
        assert host.wrote() == [binding['ca_pub_path'], binding['krl_path'],
                                binding['host_cert_path']]
        assert host.reloaded == [binding['reload_command']]

    def test_a_revoke_a_binding_cannot_answer_fails_the_delivery_readably(
            self, app, auth_client, monkeypatch):
        ca, target, created = self._bound(auth_client, monkeypatch, krl_path=None)
        delivered, status, error = _deliver(app, created['id'], 'ssh.cert.revoked')
        assert delivered is False
        assert status == DeployDelivery.STATUS_FAILED      # permanent: nothing to write
        assert 'krl_path' in error


class TestRevocationQueuesTheKrl:
    """Revoking or deleting a certificate of a bound CA queues one KRL push per target,
    coalesced into the pending one — which it may not narrow (KRL-12)."""

    def _user_cert(self, auth_client, ca, principal):
        return assert_success(post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': ca['id'], 'public_key': _generate_test_ssh_key(), 'cert_type': 'user',
            'principals': [principal], 'validity_seconds': 3600}), status=201)

    def test_a_revocation_queues_one_krl_push_per_bound_target(self, app, auth_client,
                                                               monkeypatch):
        host = _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Revoked CA'))
        bound = [assert_success(_attach(auth_client, ca, _target(auth_client), host_cert=False),
                               status=201) for _ in range(2)]
        no_krl = assert_success(_attach(auth_client, ca, _target(auth_client), host_cert=False,
                                        ca_pub_path=f'{CANONICAL_DIR}/no_krl_{_seq[0]}.pub',
                                        krl_path=None), status=201)
        _drain(app)
        every = [b['id'] for b in bound + [no_krl]]
        assert _pending_deliveries(app, every) == []      # only the saves' own pushes ran

        cert = self._user_cert(auth_client, ca, 'revoked-principal')
        assert post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                         {'reason': 'key_compromise'}).status_code == 200
        queued = _pending_deliveries(app, every)
        # Every enabled binding that has a KRL to refresh, and only those
        assert sorted(d.binding_id for d in queued) == sorted(b['id'] for b in bound)
        assert {d.event_type for d in queued} == {'ssh.cert.revoked'}
        assert all(d.max_attempts == DeployService.DEFAULT_MAX_ATTEMPTS for d in queued)
        # and running them refreshes the KRL on each bound target, runs nothing, and
        # leaves the binding with no krl_path with no delivery at all
        host.pushed, host.reloaded = [], []
        _drain(app)
        assert sorted(host.wrote()) == sorted(b['krl_path'] for b in bound)
        assert host.reloaded == []

    def test_revocations_while_a_target_is_down_do_not_multiply_deliveries(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Coalescing CA'))
        bound = assert_success(_attach(auth_client, ca, _target(auth_client), host_cert=False),
                               status=201)
        for n in range(3):
            cert = self._user_cert(auth_client, ca, f'coalesced-{n}')
            assert post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                             {'reason': 'key_compromise'}).status_code == 200
        queued = _pending_deliveries(app, [bound['id']])
        assert len(queued) == 1
        assert queued[0].attempts == 0 and queued[0].last_error is None
        # It is still the save's own push (KRL-12): coalescing three revokes into it
        # may not shrink it, and a full push writes the KRL as part of its job.
        assert queued[0].event_type in FULL_EVENTS

    def test_a_certificate_of_an_unbound_ca_queues_nothing(self, app, auth_client, monkeypatch):
        _Host(monkeypatch)
        unbound = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Unbound CA'))
        other = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Other CA'))
        bound = assert_success(_attach(auth_client, other, _target(auth_client), host_cert=False),
                               status=201)
        _drain(app)
        cert = self._user_cert(auth_client, unbound, 'unbound')
        assert post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                         {'reason': 'key_compromise'}).status_code == 200
        assert _pending_deliveries(app, [bound['id']]) == []

    def test_deleting_a_revoked_expired_certificate_queues_the_krl_too(
            self, app, auth_client, monkeypatch):
        from datetime import timedelta

        from models.ssh import SSHCertificate
        from utils.datetime_utils import utc_now

        _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Deleted cert CA'))
        bound = assert_success(_attach(auth_client, ca, _target(auth_client), host_cert=False),
                               status=201)
        _drain(app)
        cert = self._user_cert(auth_client, ca, 'expired-deleted')
        assert post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                         {'reason': 'key_compromise'}).status_code == 200
        with app.app_context():
            row = db.session.get(SSHCertificate, cert['id'])
            row.valid_to = utc_now() - timedelta(seconds=1)
            db.session.commit()
        assert auth_client.delete(f"/api/v2/ssh/certificates/{cert['id']}").status_code == 204
        # The delete refreshed the row the revoke queued, of one KRL-only kind
        assert [d.event_type for d in _pending_deliveries(app, [bound['id']])] == \
            ['ssh.cert.deleted']

    def test_a_binding_is_removable_and_frees_the_ca_for_deletion(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch)
        ca = _create_ssh_ca(auth_client, ca_type='user', descr=_name('Removable binding CA'))
        bound = assert_success(_attach(auth_client, ca, _target(auth_client), host_cert=False),
                               status=201)
        blocked = auth_client.delete(f"/api/v2/ssh/cas/{ca['id']}")
        assert blocked.status_code == 409, blocked.data
        assert 'binding' in get_json(blocked)['message'].lower()
        removed = auth_client.delete(f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings/{bound['id']}")
        assert removed.status_code == 200, removed.data
        assert 'not removed' in get_json(removed)['message']     # no undeploy, and it says so
        assert _binding(app, ca['id'], bound['target_id']) is None
        assert auth_client.delete(f"/api/v2/ssh/cas/{ca['id']}").status_code == 204


@needs_ssh_keygen
class TestRevokeBeatsTheFirstDelivery:
    """KRL-12, on the target: a revoke that arrives before a delivery has run reuses that
    delivery without shrinking what it writes; one that arrives after it queues a KRL-only
    delivery, which writes the KRL and runs no command."""

    def _bound(self, auth_client, monkeypatch):
        host = _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('KRL-12 CA'))
        target = _target(auth_client)
        created = assert_success(_attach(auth_client, ca, target,
                                         reload_command='sudo systemctl reload sshd'), status=201)
        host.pushed, host.removed, host.reloaded = [], [], []   # the save's probes are not a delivery
        return host, ca, target, created

    def _revoked_certificate(self, auth_client, ca, principal):
        cert = assert_success(post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': ca['id'], 'public_key': _generate_test_ssh_key(), 'cert_type': 'host',
            'principals': [principal], 'validity_seconds': 3600}), status=201)
        assert post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                         {'reason': 'key_compromise'}).status_code == 200
        return cert

    def test_a_revoke_before_the_first_drain_still_writes_every_artefact(
            self, app, auth_client, monkeypatch):
        host, ca, target, created = self._bound(auth_client, monkeypatch)
        self._revoked_certificate(auth_client, ca, target['host'])

        pending = _pending_deliveries(app, [created['id']])
        # One row, the save's own, reused: a revoke adds no second delivery to a target
        # that has not been pushed yet
        assert len(pending) == 1 and len(_rows_for(app, created['id'])) == 1
        assert pending[0].event_type in FULL_EVENTS, pending[0].event_type
        _drain(app)

        # The push the save owed still arrived, KRL included, and sshd was told about
        # its new CA key exactly once
        assert host.wrote() == [created['ca_pub_path'], created['krl_path'],
                                created['host_cert_path']]
        assert host.reloaded == [created['reload_command']]
        assert [(d.status, d.last_error) for d in _rows_for(app, created['id'])] == \
            [(DeployDelivery.STATUS_DELIVERED, None)]

    def test_a_revoke_after_a_delivered_push_writes_only_the_krl(
            self, app, auth_client, monkeypatch):
        host, ca, target, created = self._bound(auth_client, monkeypatch)
        _drain(app)
        host.pushed, host.reloaded = [], []

        self._revoked_certificate(auth_client, ca, target['host'])
        # Nothing wider is owed any more: this one is a plain KRL refresh
        assert [d.event_type for d in _pending_deliveries(app, [created['id']])] == \
            ['ssh.cert.revoked']
        _drain(app)
        assert host.wrote() == [created['krl_path']]
        assert host.reloaded == []

    def test_a_revoke_arriving_on_a_push_that_failed_keeps_the_whole_job(
            self, app, auth_client, monkeypatch):
        _host, ca, target, created = self._bound(auth_client, monkeypatch)
        broken = _Host(monkeypatch, publishes=[_host_key('ed25519')],
                       refuse=[created['krl_path']])
        _drain(app)
        rows = _rows_for(app, created['id'])
        assert len(rows) == 1 and rows[0].status == DeployDelivery.STATUS_PENDING
        assert rows[0].last_error and created['krl_path'] in rows[0].last_error

        self._revoked_certificate(auth_client, ca, target['host'])
        pending = _pending_deliveries(app, [created['id']])
        # The retry row is what a revoke now has to be careful with: it keeps the full
        # job, so a later Retry does not have to restore anything
        assert len(pending) == 1 and pending[0].event_type in FULL_EVENTS
        assert pending[0].attempts == 0 and pending[0].last_error is None

        fixed = _Host(monkeypatch, publishes=[_host_key('ed25519')])   # the operator fixed the path
        _drain(app)
        assert fixed.wrote() == [created['ca_pub_path'], created['krl_path'],
                                 created['host_cert_path']]
        assert fixed.reloaded == [created['reload_command']]
        assert _rows_for(app, created['id'])[0].status == DeployDelivery.STATUS_DELIVERED


def _krl(app, ca_id):
    """The KRL UCM would hand out for this CA right now."""
    from services.ssh_krl_service import SSHKRLService
    with app.app_context():
        return SSHKRLService.generate_krl(ca_id)


@needs_ssh_keygen
class TestTheActorOfADeliveredHostCertificate:
    """A host certificate signed by a delivery is signed because an admin pressed Deploy now:
    the audit of it has to name that admin, not 'system'."""

    def test_the_certificate_a_delivery_signs_bears_the_actor_of_that_delivery(
            self, app, auth_client, monkeypatch):
        _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Delivery actor CA'))
        target = _target(auth_client)
        created = assert_success(_attach(auth_client, ca, target,
                                         reload_command='sudo systemctl reload sshd'), status=201)
        deployed = assert_success(
            auth_client.post(f"/api/v2/ssh/cas/{ca['id']}/deploy-bindings/{created['id']}/deploy"))
        assert deployed['triggered_by'] == 'admin' and deployed['status'] == 'delivered'
        certificate = next(b for b in _listing(auth_client, ca['id'])['bindings']
                           if b['id'] == created['id'])['host_certificate']
        detail = assert_success(auth_client.get(f"/api/v2/ssh/certificates/{certificate['id']}"))
        # Not 'system': the signature is traceable to the account that asked for the push
        assert detail['created_by'] == deployed['triggered_by'] != 'system'
        assert detail['source'] == 'deploy'


@needs_ssh_keygen
class TestRevocationDuringADelivery:
    """A revocation that lands on a push which is already running: that push generated its KRL
    before the revocation committed, so it ends 'delivered' with a KRL one revocation short and
    'KRL missing on N targets' counts it as delivered. Over-queueing an idempotent KRL refresh is
    the cheap side of this race; losing a revocation is not."""

    def _bound(self, auth_client, monkeypatch):
        host = _Host(monkeypatch, publishes=[_host_key('ed25519')])
        ca = _create_ssh_ca(auth_client, ca_type='host', descr=_name('Mid-push CA'))
        target = _target(auth_client)
        created = assert_success(_attach(auth_client, ca, target,
                                         reload_command='sudo systemctl reload sshd'), status=201)
        host.pushed, host.removed, host.reloaded = [], [], []   # the save's probes are not a delivery
        return host, ca, target, created

    def test_a_revoke_that_lands_on_a_running_push_queues_exactly_one_more_krl_push(
            self, app, auth_client, monkeypatch):
        host, ca, target, created = self._bound(auth_client, monkeypatch)
        cert = assert_success(post_json(auth_client, '/api/v2/ssh/certificates', {
            'ca_id': ca['id'], 'public_key': _generate_test_ssh_key(), 'cert_type': 'host',
            'principals': [target['host']], 'validity_seconds': 3600}), status=201)

        stale, revoked_once = [], []
        pushing = ssh_mod.push_files

        def push_then_revoke(client, files):
            pushing(client, files)     # the artefacts of this delivery, its KRL included
            written = [content for path, content, _ in files if path == created['krl_path']]
            if written and not revoked_once:
                # The KRL is generated and on its way; the revocation commits here — the window
                # 'every revocation re-pushes the KRL to all bound hosts' has to survive. Once:
                # the requeued push writes the KRL too, and it must not revoke anything.
                revoked_once.append(True)
                stale.extend(written)
                response = post_json(auth_client, f"/api/v2/ssh/certificates/{cert['id']}/revoke",
                                     {'reason': 'key_compromise'})
                assert response.status_code == 200, get_json(response)

        monkeypatch.setattr(ssh_mod, 'push_files', push_then_revoke)
        _drain(app)

        pending = _pending_deliveries(app, [created['id']])
        assert len(pending) == 1, [(d.status, d.event_type) for d in _rows_for(app, created['id'])]
        requeued = pending[0]
        assert requeued.event_type == 'ssh.cert.revoked'
        assert requeued.max_attempts == DeployService.DEFAULT_MAX_ATTEMPTS
        assert requeued.triggered_by == 'admin'      # the actor of the push it follows
        # The full push the save owed still arrived in full, once
        assert host.wrote() == [created['ca_pub_path'], created['krl_path'],
                                created['host_cert_path']]
        assert host.reloaded == [created['reload_command']]
        assert sorted((d.status, d.event_type) for d in _rows_for(app, created['id'])) == [
            (DeployDelivery.STATUS_DELIVERED, 'initial'),
            (DeployDelivery.STATUS_PENDING, 'ssh.cert.revoked')]
        # The console does not report this target as up to date
        cas = next(c for c in assert_success(auth_client.get('/api/v2/ssh/cas')) if c['id'] == ca['id'])
        assert cas['krl_undelivered_targets'] == 1
        # A KRL version is the millisecond it was made in, so the two cannot be compared byte
        # for byte; what a revoked serial changes is what it holds, and its size with it
        current = _krl(app, ca['id'])
        assert len(stale[0]) < len(current), (len(stale[0]), len(current))

        host.pushed, host.reloaded = [], []
        _drain(app)
        # The extra push is a plain KRL refresh: one file, no command
        assert host.wrote() == [created['krl_path']] and host.reloaded == []
        assert len(host.pushed[0][1]) == len(current), (len(host.pushed[0][1]), len(current))
        cas = next(c for c in assert_success(auth_client.get('/api/v2/ssh/cas')) if c['id'] == ca['id'])
        assert cas['krl_undelivered_targets'] == 0
        assert sorted((d.status, d.event_type) for d in _rows_for(app, created['id'])) == [
            (DeployDelivery.STATUS_DELIVERED, 'initial'),
            (DeployDelivery.STATUS_DELIVERED, 'ssh.cert.revoked')]
