"""Store-the-CA-certificate-on-the-token (fork issue #2).

DB rows and the CA-signing path are real: signing is served by a local key
through patched HsmService.sign/get_public_key (tests/test_ca_service_hsm.py
pattern). Only the PKCS#11 session is faked -- a dict-backed cert store
patched through HsmService._get_provider_instance, the single place the
upload path touches the token. The SoftHSM test at the bottom round-trips
the real provider certificate methods through a real PKCS#11 library.
"""
import base64
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from models import db, CA
from models.hsm import HsmKey, HsmProvider
from services.hsm.base_provider import HsmOperationError

from tests.test_hsm_sync_and_listing import (  # noqa: F401
    SOFTHSM_MODULE, needs_softhsm, softhsm_token,
)


def post_json(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type='application/json')


class FakeToken:
    """What a PKCS#11 session would answer for the certificate objects."""

    def __init__(self, certs=None, fail_store_with=None):
        self.certs = dict(certs or {})          # key_identifier -> DER
        self.fail_store_with = fail_store_with

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_certificate(self, key_identifier):
        return self.certs.get(key_identifier)

    def store_certificate(self, key_identifier, cert_der, label=None):
        if self.fail_store_with is not None:
            raise self.fail_store_with
        self.certs[key_identifier] = cert_der

    def delete_certificate(self, key_identifier):
        return 1 if self.certs.pop(key_identifier, None) else 0


def _self_signed_der(subject_cn):
    """A different certificate, to seed a slot before a CA is created."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    now = datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def hsm_key_pair(app, request):
    """Factory: stub provider + HSM key backed by a real local EC key."""
    created = []

    def make(provider_type='pkcs11'):
        real_key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = real_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        suffix = f'{len(created)}-{request.node.name[-12:]}'
        with app.app_context():
            from models.hsm import HsmKey, HsmProvider
            provider = HsmProvider(name=f'TokenCert-{provider_type}-{suffix}',
                                   type=provider_type, config='{}')
            db.session.add(provider)
            db.session.commit()
            key = HsmKey(provider_id=provider.id,
                         key_identifier=f'ca{suffix}'.encode().hex(),
                         label=f'ca-key-{suffix}',
                         algorithm='EC-P256', key_type='asymmetric', purpose='signing',
                         public_key_pem=pub_pem)
            db.session.add(key)
            db.session.commit()
            info = {'provider_id': provider.id, 'hsm_key_id': key.id,
                    'key_identifier': key.key_identifier,
                    'real_key': real_key, 'pub_pem': pub_pem}
        created.append((provider.id, key.id))
        return info

    yield make

    with app.app_context():
        db.session.rollback()
        for provider_id, key_id in created:
            for ca in CA.query.filter_by(hsm_key_id=key_id).all():
                db.session.delete(ca)
            HsmKey.query.filter_by(id=key_id).delete()
            HsmProvider.query.filter_by(id=provider_id).delete()
        db.session.commit()


@contextmanager
def _hsm_patches(hsm, fake):
    """Signing from ``real_key``; the token itself is the fake cert store."""
    def fake_sign(key_id, data, algo=None, hash_algorithm=None):
        digest = {'sha384': hashes.SHA384, 'sha512': hashes.SHA512}.get(hash_algorithm, hashes.SHA256)()
        return hsm['real_key'].sign(data, ec.ECDSA(digest))

    with patch('services.hsm.HsmService.sign', side_effect=fake_sign), \
            patch('services.hsm.HsmService.get_public_key', return_value=hsm['pub_pem']), \
            patch('services.hsm.HsmService._get_provider_instance', return_value=fake):
        yield


def _ca_der(ca):
    return x509.load_pem_x509_certificate(
        base64.b64decode(ca.crt)).public_bytes(serialization.Encoding.DER)


class TestCreateWithUpload:

    def test_upload_stores_the_ca_certificate_on_the_token(self, app, hsm_key_pair, auth_client):
        hsm = hsm_key_pair()
        fake = FakeToken()
        with _hsm_patches(hsm, fake):
            r = post_json(auth_client, '/api/v2/cas',
                          {'commonName': 'Token Upload CA', 'hsmKeyId': hsm['hsm_key_id'],
                           'updateTokenCert': True})
        assert r.status_code == 201, r.get_data(as_text=True)
        upload = r.json['data']['token_cert_upload']
        assert upload['ok'] and upload['uploaded'] and not upload['replaced']
        with app.app_context():
            ca = CA.query.filter_by(descr='Token Upload CA').first()
            assert fake.certs[hsm['key_identifier']] == _ca_der(ca)

    def test_existing_certificate_conflicts_before_the_ca_is_created(self, app, hsm_key_pair, auth_client):
        hsm = hsm_key_pair()
        placeholder = _self_signed_der('Old Placeholder Root')
        fake = FakeToken(certs={hsm['key_identifier']: placeholder})
        with _hsm_patches(hsm, fake):
            r = post_json(auth_client, '/api/v2/cas',
                          {'commonName': 'Conflict CA', 'hsmKeyId': hsm['hsm_key_id'],
                           'updateTokenCert': True})
            assert r.status_code == 409, r.get_data(as_text=True)
            existing = r.json['details']['existing']
            assert existing['subject'] == 'CN=Old Placeholder Root' and existing['serial'] and existing['not_after']
            assert fake.certs[hsm['key_identifier']] == placeholder  # untouched
            with app.app_context():
                assert CA.query.filter_by(descr='Conflict CA').count() == 0

            # the frontend repeats with the overwrite consent
            r2 = post_json(auth_client, '/api/v2/cas',
                           {'commonName': 'Conflict CA', 'hsmKeyId': hsm['hsm_key_id'],
                            'updateTokenCert': True, 'overwriteTokenCert': True})
        assert r2.status_code == 201, r2.get_data(as_text=True)
        upload = r2.json['data']['token_cert_upload']
        assert upload['ok'] and upload['uploaded'] and upload['replaced']
        with app.app_context():
            ca = CA.query.filter_by(descr='Conflict CA').first()
            assert fake.certs[hsm['key_identifier']] == _ca_der(ca)

    def test_failed_upload_keeps_the_ca_and_reports_a_warning(self, app, hsm_key_pair, auth_client):
        hsm = hsm_key_pair()
        fake = FakeToken(fail_store_with=HsmOperationError('card was pulled mid-write'))
        with _hsm_patches(hsm, fake):
            r = post_json(auth_client, '/api/v2/cas',
                          {'commonName': 'Halfway CA', 'hsmKeyId': hsm['hsm_key_id'],
                           'updateTokenCert': True})
        assert r.status_code == 201, r.get_data(as_text=True)
        upload = r.json['data']['token_cert_upload']
        assert upload['ok'] is False and 'card was pulled' in upload['error']
        with app.app_context():
            assert CA.query.filter_by(descr='Halfway CA').first() is not None

    def test_unreadable_slot_is_not_a_conflict(self, app, hsm_key_pair, auth_client):
        hsm = hsm_key_pair()
        fake = FakeToken(certs={hsm['key_identifier']: b'not-a-certificate'})
        with _hsm_patches(hsm, fake):
            r = post_json(auth_client, '/api/v2/cas',
                          {'commonName': 'Garbage Slot CA', 'hsmKeyId': hsm['hsm_key_id'],
                           'updateTokenCert': True})
        assert r.status_code == 409
        # the garbage still occupies the slot and is described, not parsed
        assert r.json['details']['existing']['subject'] == '(unreadable certificate)'

    def test_fields_are_refused_without_an_existing_pkcs11_hsm_key(self, app, hsm_key_pair, auth_client):
        r = post_json(auth_client, '/api/v2/cas',
                      {'commonName': 'Local CA', 'keyAlgo': 'EC', 'keySize': 256,
                       'updateTokenCert': True})
        assert r.status_code == 400 and 'existing HSM key' in r.json['detail']

        hsm = hsm_key_pair(provider_type='azure')  # cloud provider has no slots
        fake = FakeToken()
        with _hsm_patches(hsm, fake):
            r2 = post_json(auth_client, '/api/v2/cas',
                           {'commonName': 'Azure CA', 'hsmKeyId': hsm['hsm_key_id'],
                            'updateTokenCert': True})
        assert r2.status_code == 400 and 'PKCS#11' in r2.json['detail']


class TestUploadCertEndpoint:

    def _create_ca(self, auth_client, hsm):
        r = post_json(auth_client, '/api/v2/cas',
                      {'commonName': 'Retry CA', 'hsmKeyId': hsm['hsm_key_id']})
        assert r.status_code == 201, r.get_data(as_text=True)
        return r.json['data']['id']

    def test_retry_is_idempotent(self, app, hsm_key_pair, auth_client):
        hsm = hsm_key_pair()
        fake = FakeToken()
        with _hsm_patches(hsm, fake):
            ca_id = self._create_ca(auth_client, hsm)
            r = post_json(auth_client, f'/api/v2/cas/{ca_id}/hsm/upload-cert', {})
            assert r.status_code == 200, r.get_data(as_text=True)
            with app.app_context():
                assert fake.certs[hsm['key_identifier']] == _ca_der(db.session.get(CA, ca_id))
            r2 = post_json(auth_client, f'/api/v2/cas/{ca_id}/hsm/upload-cert', {})
        assert r2.status_code == 200
        assert r2.json['data']['already'] is True

    def test_conflict_and_forced_overwrite(self, app, hsm_key_pair, auth_client):
        hsm = hsm_key_pair()
        placeholder = _self_signed_der('Other Root')
        fake = FakeToken(certs={hsm['key_identifier']: placeholder})
        with _hsm_patches(hsm, fake):
            ca_id = self._create_ca(auth_client, hsm)   # no upload requested
            r = post_json(auth_client, f'/api/v2/cas/{ca_id}/hsm/upload-cert', {})
            assert r.status_code == 409
            assert r.json['details']['existing']['subject'] == 'CN=Other Root'
            assert fake.certs[hsm['key_identifier']] == placeholder
            r2 = post_json(auth_client, f'/api/v2/cas/{ca_id}/hsm/upload-cert',
                           {'overwriteTokenCert': True})
        assert r2.status_code == 200 and r2.json['data']['replaced'] is True
        with app.app_context():
            assert fake.certs[hsm['key_identifier']] == _ca_der(db.session.get(CA, ca_id))

    def test_software_ca_and_missing_ca_are_refused(self, app, auth_client):
        r = post_json(auth_client, '/api/v2/cas/999999/hsm/upload-cert', {})
        assert r.status_code == 404
        r = post_json(auth_client, '/api/v2/cas', {'commonName': 'Plain CA', 'keyAlgo': 'EC', 'keySize': 256})
        assert r.status_code == 201
        software_id = r.json['data']['id']
        r2 = post_json(auth_client, f'/api/v2/cas/{software_id}/hsm/upload-cert', {})
        assert r2.status_code == 400
        with app.app_context():
            ca = db.session.get(CA, software_id)
            db.session.delete(ca)
            db.session.commit()

    def test_token_failure_is_a_502_not_a_500(self, app, hsm_key_pair, auth_client):
        hsm = hsm_key_pair()
        fake = FakeToken(fail_store_with=HsmOperationError('PIN incorrect'))
        with _hsm_patches(hsm, fake):
            ca_id = self._create_ca(auth_client, hsm)
            r = post_json(auth_client, f'/api/v2/cas/{ca_id}/hsm/upload-cert', {})
        assert r.status_code == 502 and 'PIN incorrect' in r.json['detail']


@needs_softhsm
class TestRealPkcs11CertificateObjects:

    def test_provider_certificate_round_trip(self, softhsm_token):
        from services.hsm.pkcs11_provider import Pkcs11Provider
        provider = Pkcs11Provider(dict(softhsm_token))
        assert provider.connect()
        try:
            key_info = provider.generate_key('ca-cert-upload-test', 'EC-P256')
            der = _self_signed_der('SoftHSM Root')
            assert provider.get_certificate(key_info.key_identifier) is None
            provider.store_certificate(key_info.key_identifier, der, label='ca-cert')
            assert provider.get_certificate(key_info.key_identifier) == der
            assert provider.delete_certificate(key_info.key_identifier) == 1
            assert provider.get_certificate(key_info.key_identifier) is None
        finally:
            provider.disconnect()
