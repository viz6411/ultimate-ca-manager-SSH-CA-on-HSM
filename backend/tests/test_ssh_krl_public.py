"""Public SSH KRL distribution & tokenless auto-sync (PR 1 for issue #451)."""
import subprocess

from tests.test_ssh import _create_ssh_ca, _generate_test_ssh_key, post_json
from utils.public_endpoints import is_protocol_path


def _issue_and_revoke_user_cert(auth_client, ca_id):
    r = post_json(auth_client, '/api/v2/ssh/certificates', {
        'ca_id': ca_id,
        'cert_type': 'user',
        'principals': ['alice'],
        'public_key': _generate_test_ssh_key(),
    })
    assert r.status_code == 201, r.data
    cert_id = r.get_json()['data']['id']
    rev = post_json(auth_client, f'/api/v2/ssh/certificates/{cert_id}/revoke', {'reason': 'test'})
    assert rev.status_code == 200, rev.data
    return cert_id


class TestPublicKRL:
    def test_protocol_path_classification(self):
        assert is_protocol_path('/ssh/krl/abc-123')
        assert is_protocol_path('/ssh/krl/abc-123/setup')

    def test_public_krl_etag_304_and_revocation_bump(self, client, auth_client):
        ca = _create_ssh_ca(auth_client, ca_type='user', descr='Public KRL User CA',
                            allow_any_principal=True)
        r1 = client.get(f"/ssh/krl/{ca['refid']}")
        assert r1.status_code == 200
        assert r1.headers['ETag'] == '"0"'
        assert r1.headers['X-KRL-Version'] == '0'
        assert r1.data.startswith(b'SSHKRL')

        r304 = client.get(f"/ssh/krl/{ca['refid']}", headers={'If-None-Match': '"0"'})
        assert r304.status_code == 304

        _issue_and_revoke_user_cert(auth_client, ca['id'])

        r2 = client.get(f"/ssh/krl/{ca['refid']}", headers={'If-None-Match': '"0"'})
        assert r2.status_code == 200
        assert r2.headers['ETag'] == '"1"'
        assert r2.headers['X-KRL-Version'] == '1'
        assert r2.data != r1.data


class TestPublicKRLSyncSetup:
    def test_user_ca_setup_script_unix_and_windows(self, client, auth_client, tmp_path):
        user_ca = _create_ssh_ca(auth_client, ca_type='user', descr='Sync User CA')
        host_ca = _create_ssh_ca(auth_client, ca_type='host', descr='Sync Host CA')

        # Host CA is rejected for User CA KRL auto-sync setup
        r_host = client.get(f"/ssh/krl/{host_ca['refid']}/setup")
        assert r_host.status_code == 400

        # Unix setup script
        r_unix = client.get(f"/ssh/krl/{user_ca['refid']}/setup")
        assert r_unix.status_code == 200
        script = r_unix.get_data(as_text=True)
        assert f"/ssh/krl/{user_ca['refid']}" in script
        assert 'TrustedUserCAKeys' in script
        assert 'RevokedKeys' in script
        assert 'systemd' in script and 'crontab' in script
        assert 'WARN: No systemd or crontab found.' in script

        p = tmp_path / 'krl_sync.sh'
        p.write_text(script)
        assert subprocess.run(['sh', '-n', str(p)], capture_output=True).returncode == 0

        # Windows setup script
        r_win = client.get(f"/ssh/krl/{user_ca['refid']}/setup?platform=windows")
        assert r_win.status_code == 200
        ps = r_win.get_data(as_text=True)
        assert 'sshd.exe -t' in ps
        assert 'Register-ScheduledTask' in ps
