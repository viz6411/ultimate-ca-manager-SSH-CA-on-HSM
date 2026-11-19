"""Tests for public SSH CA setup script endpoint (/ssh/setup/<refid>)."""

import json
import shutil
import subprocess

import pytest

from services.deploy.ssh_ca import CANONICAL_DIR, artifact_defaults
from tests.conftest import get_json
from tests.test_ssh import _create_ssh_ca


def _create_host_ca(auth_client):
    payload = {
        'descr': 'Public setup test CA',
        'ca_type': 'host',
        'key_type': 'ed25519',
    }
    r = auth_client.post(
        '/api/v2/ssh/cas',
        data=json.dumps(payload),
        content_type='application/json',
    )
    assert r.status_code == 201, r.data
    return get_json(r).get('data', get_json(r))


def _script(app, ca, ca_type):
    """The script the console's Download setup script hands out."""
    return app.test_client().get(f"/ssh/setup/{ca['refid']}?type={ca_type}").data.decode()


needs_sh = pytest.mark.skipif(not shutil.which('sh'), reason='no POSIX shell to parse a script')


class TestPublicSSHSetupScript:
  def test_rejects_shell_metacharacters_in_hostname(self, app, auth_client):
      ca = _create_host_ca(auth_client)
      refid = ca['refid']
      client = app.test_client()
      r = client.get(
          f'/ssh/setup/{refid}?type=host&hostname=$(id)'
      )
      assert r.status_code == 400
      assert b'Invalid hostname format' in r.data

  def test_rejects_quote_breakout_in_hostname(self, app, auth_client):
      ca = _create_host_ca(auth_client)
      refid = ca['refid']
      client = app.test_client()
      r = client.get(
          f'/ssh/setup/{refid}?type=host&hostname=x";id;"'
      )
      assert r.status_code == 400

  def test_valid_hostname_embedded_safely(self, app, auth_client):
      ca = _create_host_ca(auth_client)
      refid = ca['refid']
      hostname = 'web01.example.com'
      client = app.test_client()
      r = client.get(
          f'/ssh/setup/{refid}?type=host&hostname={hostname}'
      )
      assert r.status_code == 200
      body = r.data.decode('utf-8')
      assert f'HOSTNAME="{hostname}"' in body
      assert '$(id)' not in body


def _defaults(app, ca_id, ca_type=None):
    from models import db
    from models.ssh import SSHCertificateAuthority
    with app.app_context():
        return artifact_defaults(db.session.get(SSHCertificateAuthority, ca_id), ca_type)


def _as_shell(tmp_path, body):
    """What the operator's shell does with the downloaded script: parse it, run nothing."""
    script = tmp_path / 'setup.sh'
    script.write_text(body)
    run = subprocess.run(['sh', '-n', str(script)], capture_output=True, text=True, timeout=30)
    assert run.returncode == 0, run.stderr


@needs_sh
class TestSetupScriptsAndDeploymentsAgree:
  """The paths a setup script puts in sshd_config are the paths a UCM deployment writes,
  and neither of them invents a KRL."""

  def test_both_scripts_point_at_the_paths_a_default_binding_starts_from(self, app, auth_client,
                                                                        tmp_path):
      host_ca = _create_ssh_ca(auth_client, ca_type='host', descr='Lab Host CA')
      user_ca = _create_ssh_ca(auth_client, ca_type='user', descr='Lab User CA')
      for ca, ca_type in ((host_ca, 'host'), (user_ca, 'user')):
          defaults = _defaults(app, ca['id'])
          body = _script(app, ca, ca_type)
          assert body.startswith('#!/bin/sh')
          assert f'CA_KEY_FILE="{defaults["ca_pub_path"]}"' in body
          assert f'KRL_FILE="{defaults["krl_path"]}"' in body
          assert defaults['ca_pub_path'].startswith(CANONICAL_DIR)
          _as_shell(tmp_path, body)
      host_cert = _defaults(app, host_ca['id'])['host_cert_path']
      assert host_cert.endswith('_host_key-cert.pub')
      assert f'CERT_FILE="{host_cert}"' in _script(app, host_ca, 'host')
      # A user CA has no host certificate to write, and does not claim one
      assert _defaults(app, user_ca['id'])['host_cert_path'] is None
      assert 'CERT_FILE=' not in _script(app, user_ca, 'user')

  def test_the_scripts_tell_sshd_to_read_the_krl_without_writing_one(self, app, auth_client,
                                                                     tmp_path):
      for ca_type in ('host', 'user'):
          ca = _create_ssh_ca(auth_client, ca_type=ca_type, descr=f'Lab {ca_type} KRL CA')
          body = _script(app, ca, ca_type)
          assert 'RevokedKeys $KRL_FILE' in body
          assert 'does not install the key revocation list' in body
          # Nothing in the script writes $KRL_FILE: the KRL is UCM's to hand out
          assert [line for line in body.splitlines()
                  if '$KRL_FILE' in line and ('>' in line or 'tee' in line)] == []
          _as_shell(tmp_path, body)

  def test_a_user_ca_asked_for_a_host_script_still_names_a_host_certificate(self, app,
                                                                            auth_client,
                                                                            tmp_path):
      # ?type=host on a user CA is what the console's host download does; an empty
      # CERT_FILE would put a blank HostCertificate in sshd_config
      ca = _create_ssh_ca(auth_client, ca_type='user', descr='Ask Host CA')
      body = _script(app, ca, 'host')
      assert 'CERT_FILE=""' not in body
      assert f'CERT_FILE="{_defaults(app, ca["id"], "host")["host_cert_path"]}"' in body
      _as_shell(tmp_path, body)
