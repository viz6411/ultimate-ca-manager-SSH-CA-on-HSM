"""Revocations that never went through `POST /api/v2/ssh/certificates/<id>/revoke`.

A restore revokes SSH certificates by SQL (`SSHSerials.settle_marks`: the KRL revokes by serial,
so a valid holder of a revoked serial is revoked with it), with no certificate event behind it.
Without a queueing step every target bound to that CA keeps a KRL one revocation short while
`krl_undelivered_targets` says nothing about it. A restore queues what those revocations would
have queued; a 2.254 upgrade cannot hit this at all — its SSH step runs while the binding table
does not exist yet, because the migration that creates it (301) comes after the pivot (300).
"""
import copy
import uuid

import pytest
from sqlalchemy import inspect as sa_inspect

from models import DeployDelivery, DeployTarget, SSHCADeployBinding, db
from models.ssh import SSHCertificate
from services.deploy.ssh_ca import artifact_defaults
from services.deploy.service import DeployService
from services.ssh_cert import SSHCertificateService
from services.ssh_ca_service import SSHCAService
from tests.fresh_app import fresh_app_fixtures
from tests.test_backup_cross_installation import PASSWORD, Keys, _installation, _only
from tests.upgrade_2254_support import make_base

app, auth_client, create_ca, create_cert, create_user = fresh_app_fixtures()


@pytest.fixture(scope='module')
def installation(app, tmp_path_factory):
    """An installation of our own: a restore rewrites whole sections of the database, and this one
    is not the one the rest of the worker shares. It keeps an app context open while it is held,
    so the tests below query it directly."""
    directory = tmp_path_factory.mktemp('ssh-ca-restore-krl')
    keys = Keys(directory, 'ssh-ca-restore')
    with _installation(app, f"sqlite:///{directory / 'target.db'}", keys), app.app_context():
        yield


def _pubkey():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()


def _archive():
    from services.backup_service import BackupService
    service = BackupService()
    blob = service.create_backup(PASSWORD, include=_only('ssh_cas', 'ssh_certificates'))
    return service._decrypt_framed(blob, PASSWORD)


def _restore(master, payload, mode):
    from services.backup_service import BackupService
    return BackupService()._restore_payload(copy.deepcopy(payload), master, mode)


def _pair_rows(store, ids):
    """The archive's rows of the two certificates named by *ids*."""
    refids = {c.refid for c in db.session.query(SSHCertificate).filter(
        SSHCertificate.id.in_(list(ids))).all()}
    return [row for row in store['ssh_certificates'] if row['refid'] in refids]


def _ca(label):
    return SSHCAService.create_ca(descr=f'{label} {uuid.uuid4().hex[:8]}', ca_type='user',
                                  key_type='ed25519', username='t', allow_any_principal=True)


def _bind(ca, label):
    """Attach *ca* to one enabled target with its KRL path named, and nothing queued yet."""
    target = DeployTarget(name=f'{label} target', host='restore.example.test',
                          username='ucm-deploy', private_key='', enabled=True)
    db.session.add(target)
    db.session.flush()
    binding = SSHCADeployBinding(target_id=target.id, ssh_ca_id=ca.id, enabled=True,
                                 **artifact_defaults(ca))
    db.session.add(binding)
    db.session.commit()
    return target, binding


def _deliveries(binding_id):
    """What that binding owes right now. The `installation` fixture keeps the app context open."""
    return (DeployDelivery.query
            .filter_by(binding_id=binding_id, binding_type=DeployDelivery.BINDING_SSH_CA)
            .order_by(DeployDelivery.id).all())


def _payload(store):
    payload = {name: copy.deepcopy(list(store[name])) for name in ('ssh_cas', 'ssh_certificates')}
    for row in payload['ssh_certificates']:
        row.pop('serial_duplicate', None)
    return payload


def test_a_restore_that_revokes_certificates_of_a_bound_ca_queues_its_krl(installation):
    """The pair: one holder revoked in the archive, the other still valid here. Restoring revokes
    the valid one with it — and that revocation queues the KRL push the bound target is owed."""
    ca = _ca('restored pair')
    first, second = (SSHCertificateService.sign_certificate(ca.id, _pubkey(), 'user', ['pair'])
                     for _ in range(2))
    SSHCertificateService.revoke_certificate(first.id, 'keyCompromise', 't')

    master, store = _archive()
    payload = _payload(store)
    held = _pair_rows(payload, [first.id, second.id])
    serial = min(row['serial'] for row in held)
    for row in held:
        row['serial'] = serial                       # the pair the archive hands back
    db.session.execute(db.delete(SSHCertificate).where(SSHCertificate.id.in_([first.id, second.id])))
    db.session.commit()
    # Bound only now, after the revoke above: the row that revoke queued belongs to no binding,
    # so the one the assertion below finds can only have come from the restore.
    target, binding = _bind(ca, 'restored pair')

    results = _restore(master, payload, 'merge')
    assert results['ssh_revoked_with_serial'] == 1, results

    queued = _deliveries(binding.id)
    assert [(d.event_type, d.status, d.triggered_by) for d in queued] == [
        ('ssh.cert.revoked', DeployDelivery.STATUS_PENDING, 'system')]
    assert queued[0].max_attempts == DeployService.DEFAULT_MAX_ATTEMPTS
    # and the CA card says so: the bound target is one of the targets missing the current KRL
    assert SSHCADeployBinding.delivery_summary()[ca.id] == {'targets': 1, 'krl_undelivered': 1}


def test_a_restore_that_revoked_nothing_queues_nothing(installation):
    """The same restore, with no pair to align: revocations are what queue a KRL push, not
    restoring a bound CA."""
    ca = _ca('restored valid')
    certificate = SSHCertificateService.sign_certificate(ca.id, _pubkey(), 'user', ['single'])
    master, store = _archive()
    payload = _payload(store)
    db.session.execute(db.delete(SSHCertificate).where(SSHCertificate.id == certificate.id))
    db.session.commit()
    target, binding = _bind(ca, 'restored valid')

    results = _restore(master, payload, 'merge')
    assert results['ssh_revoked_with_serial'] == 0, results
    assert _deliveries(binding.id) == []
    # Nothing was queued, and the card says the target is missing its KRL for that very reason
    assert SSHCADeployBinding.delivery_summary()[ca.id] == {'targets': 1, 'krl_undelivered': 1}


def test_a_2254_upgrade_revokes_shared_serial_certificates_before_bindings_exist(tmp_path,
                                                                                  monkeypatch):
    """The other half of the same rule, and the reason the pivot needs no queueing step: at the
    moment step 168 revokes by serial, `ssh_ca_deploy_bindings` has not been created yet, so
    there is no binding to queue and no delivery row is written."""
    import migrations._from_2_254 as package
    from migrations._from_2_254 import step as real_step

    seen = {}
    for base in make_base('sqlite', tmp_path, monkeypatch, 'krlpivot'):
        def step(name):
            if name == '168_ssh_certificate_serial_unique':
                seen['tables'] = set(sa_inspect(base.engine).get_table_names())
            return real_step(name)

        monkeypatch.setattr(package, 'step', step)
        assert base.upgrade()
        assert seen['tables'], 'step 168 did not run'
        assert 'ssh_ca_deploy_bindings' not in seen['tables']
        assert base.run("SELECT COUNT(*) FROM deploy_deliveries") == [(0,)]
