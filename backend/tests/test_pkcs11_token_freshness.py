"""Reading and writing a token that the server process did not change itself.

The PKCS#11 module caches the token's objects for the life of its initialized
instance, and OpenSC has no PKCS#15 init profile for PIV cards, so a certificate
gets onto such a card through piv-tool instead of C_CreateObject. Both are tested
against fakes here; the SoftHSM roundtrip in tests/test_ca_token_cert_upload.py
covers the PKCS#11 path that is left for tokens that do support it.
"""
import os
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import services.hsm.pkcs11_provider as pkcs11_module
from pkcs11 import Attribute, ObjectClass
from pkcs11.exceptions import FunctionNotSupported
from services.hsm.base_provider import HsmOperationError
from services.hsm.pkcs11_provider import Pkcs11Provider, cryptoki_library

from tests.test_ca_token_cert_upload import _self_signed_der  # noqa: F401


@pytest.fixture
def provider(tmp_path):
    """A provider that never reaches a real library: its session is replaced below."""
    module = tmp_path / 'token.so'
    module.write_bytes(b'')
    p = Pkcs11Provider({'module_path': str(module), 'token_label': 'test', 'user_pin': '1234'})
    yield p
    pkcs11_module._open_sessions = 0


class FakeSession:
    """A token that refuses to create or destroy objects, the way OpenSC does."""

    def __init__(self, cert_der=None):
        self.created = []
        self.cert_der = cert_der

    def create_object(self, attrs):
        raise FunctionNotSupported('CKR_FUNCTION_NOT_SUPPORTED')

    def destroy(self):
        raise FunctionNotSupported('CKR_FUNCTION_NOT_SUPPORTED')

    def get_objects(self, template):
        if self.cert_der and template.get(Attribute.CLASS) is ObjectClass.CERTIFICATE:
            return [FakeSession._CertObject(self.cert_der)]
        return []

    def close(self):
        pass

    class _CertObject:
        def __init__(self, value):
            self.value = value

        def __getitem__(self, attribute):
            if attribute is Attribute.VALUE:
                return self.value
            raise AssertionError(f'unexpected attribute {attribute}')


def test_certificate_reaches_a_piv_card_through_piv_tool(provider, monkeypatch):
    """Slot 9C holds the key whose CKA_ID is 02, so that is the slot to write."""
    cert_der = _self_signed_der('CN=test')
    session = FakeSession()
    provider._session = session
    monkeypatch.setattr(pkcs11_module.shutil, 'which', lambda name: '/usr/bin/piv-tool')

    written = {}

    def fake_run(argv, **kwargs):
        written['argv'] = argv
        written['pem'] = open(argv[-1], 'rb').read()
        return type('R', (), {'returncode': 55, 'stdout': '', 'stderr': ''})()

    # piv-tool exits non-zero even when it wrote the object, so the read-back decides.
    read_back = FakeSession(cert_der)
    with patch.object(pkcs11_module.subprocess, 'run', side_effect=fake_run), \
            patch.object(provider, 'connect',
                         lambda: setattr(provider, '_session', read_back)):
        provider.store_certificate('02', cert_der, label='SIGN key')

    tool, action, slot = written['argv'][:3]
    path = written['argv'][-1]
    assert (tool, action, slot) == ('/usr/bin/piv-tool', '-C', '9C')
    assert x509.load_pem_x509_certificate(written['pem']).public_bytes(
        serialization.Encoding.DER) == cert_der
    assert not os.path.exists(path), 'the certificate file is left behind'


def test_piv_write_is_a_failure_when_the_token_does_not_read_back(provider, monkeypatch):
    cert_der = _self_signed_der('CN=test')
    provider._session = FakeSession()
    monkeypatch.setattr(pkcs11_module.shutil, 'which', lambda name: '/usr/bin/piv-tool')
    with patch.object(pkcs11_module.subprocess, 'run',
                      side_effect=lambda argv, **kw: type('R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()), \
            patch.object(provider, 'connect',
                         lambda: setattr(provider, '_session', FakeSession(cert_der=None))):
        with pytest.raises(HsmOperationError, match='reads back no certificate'):
            provider.store_certificate('02', cert_der)


def test_a_key_id_without_a_piv_slot_is_not_written_silently(provider, monkeypatch):
    cert_der = _self_signed_der('CN=test')
    provider._session = FakeSession()
    monkeypatch.setattr(pkcs11_module.shutil, 'which', lambda name: '/usr/bin/piv-tool')
    with patch.object(pkcs11_module.subprocess, 'run') as run:
        with pytest.raises(HsmOperationError, match='no writable PIV slot'):
            provider.store_certificate('80beeddb', cert_der)
    run.assert_not_called()


def test_delete_reports_nothing_removed_when_the_token_cannot_destroy(provider):
    provider._session = FakeSession()
    assert provider.delete_certificate('02') == 0


def test_a_fresh_view_reloads_the_module_and_a_live_session_prevents_it(tmp_path):
    module = tmp_path / 'token.so'
    module.write_bytes(b'')
    pkcs11_module._initialized_by[module.name] = os.getpid()
    unloaded = []
    with patch.object(pkcs11_module.pkcs11, 'unload', side_effect=lambda path: unloaded.append(path)), \
            patch.object(pkcs11_module.pkcs11, 'lib', side_effect=lambda path: object()):
        cryptoki_library(module.name, refresh=True)
        assert unloaded == [module.name]

        pkcs11_module._open_sessions = 1
        cryptoki_library(module.name, refresh=True)
        assert unloaded == [module.name], 'a live session was pulled out from under'
    pkcs11_module._initialized_by.pop(module.name, None)
    pkcs11_module._open_sessions = 0
