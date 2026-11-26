"""ucm-ssh-agent script builders — POSIX syntax gate + offline smoke test.

The agent runner is delivered over the public /ssh/agent-runner route and run
with `sudo sh` on every managed host: a syntax error bricks the fleet install.
These tests gate `sh -n` / `bash -n` on the generated scripts and then run the
real runner against a local mock UCM (no external network) to prove the
ETag/304 KRL loop, the JSON field extraction and the atomic cert install.
"""
import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from services.ucm_agent_scripts import (
    CONF_PATH, RUNNER_PATH, build_agent_runner, build_agent_setup_script,
)

UCM_URL = 'http://mock-ucm.invalid'
TOKEN = 'ucm_boot_SMOKEtoken123'


def _syntax_check(script, *interpreters):
    for interp in interpreters:
        proc = subprocess.run([interp, '-n', script], capture_output=True, text=True)
        assert proc.returncode == 0, f'{interp} -n failed: {proc.stderr}'


def _write(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content)
    return str(path)


class TestScriptSyntax:
    def test_posix_runner_parses_under_sh_and_bash(self, tmp_path):
        script = _write(tmp_path, 'runner.sh', build_agent_runner('unix'))
        _syntax_check(script, 'sh', 'bash')

    def test_posix_installer_parses_under_sh_and_bash(self, tmp_path):
        script = _write(tmp_path, 'setup.sh',
                        build_agent_setup_script(UCM_URL, TOKEN, 'unix'))
        _syntax_check(script, 'sh', 'bash')

    def test_installer_bakes_the_token_and_pulls_the_runner(self, tmp_path):
        script = build_agent_setup_script(UCM_URL, TOKEN, 'unix')
        # The token is baked into the conf update the installer performs.
        assert 'BOOTSTRAP_TOKEN=' in script and f'"{TOKEN}"' in script
        assert f'UCM_URL="{UCM_URL}"' in script
        assert f'curl -sS --fail --connect-timeout 10 -o {RUNNER_PATH} "{UCM_URL}/ssh/agent-runner"' in script
        assert f'{RUNNER_PATH} enroll' in script
        assert CONF_PATH in script and 'chmod 600' in script
        assert 'ucm-ssh-agent.timer' in script and 'OnUnitActiveSec=15min' in script

    def test_windows_builders_carry_the_token(self):
        runner = build_agent_runner('windows')
        installer = build_agent_setup_script(UCM_URL, TOKEN, 'windows')
        assert 'param([string]$Mode' in runner
        assert TOKEN in installer and UCM_URL in installer
        assert 'schtasks' in installer
        # shortcut: no pwsh in CI — only the content is asserted here. A real
        # PowerShell parse happens in the manual checklist (Windows target).


# ── offline smoke: the runner against a mock UCM ─────────────────────────────

KRL_BODY = b'KRL\x00\x00\x00\x01smoke-krl-bytes'
CERT_LINE = 'ssh-ed25519-cert-v01@openssh.com AAAAB3NzaC1kc3 smoke-cert-blob=='
CA_PUB_LINE = 'ssh-ed25519 AAAAB3NzaC1kc3 smoke-user-ca-blob=='
ERROR_PAGE = b'<html><body>rate limit exceeded</body></html>'


class _MockUCM(BaseHTTPRequestHandler):
    """Serves just enough of the agent API to drive the runner's `run` mode."""
    def log_message(self, *args):  # silence per-request logging
        pass
    state = {'krl_gets': [], 'renews': 0, 'checkins': [], 'enrolls': [], 'krl_error': None}

    def _json(self, payload, code=200):
        body = json.dumps(payload, separators=(',', ':')).encode()  # compact, like Flask
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/ssh/agent-runner':
            # What `curl -o /usr/local/bin/ucm-ssh-agent <UCM>/ssh/agent-runner` gets.
            body = build_agent_runner('unix').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith('/ssh/krl/'):
            inm = self.headers.get('If-None-Match')
            _MockUCM.state['krl_gets'].append(inm)
            error = _MockUCM.state['krl_error']
            if error:
                # What a throttled or broken UCM actually answers: an error page
                # with a body, served with the status line.
                self.send_response(error)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(ERROR_PAGE)))
                self.end_headers()
                self.wfile.write(ERROR_PAGE)
                return
            if inm and inm.strip('"') == '1':
                self.send_response(304)
                self.send_header('ETag', '"1"')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('ETag', '"1"')
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(KRL_BODY)))
            self.end_headers()
            self.wfile.write(KRL_BODY)
            return
        self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        # The same proxy answer on either half: a 5xx status line plus a multi-line HTML
        # error page. `enroll_html` is the enroll point, `tick_html_refusals` the tick's
        # check-in / renew points (round 10).
        html = (_MockUCM.state.get('enroll_html') if self.path == '/api/v2/ssh/hosts/enroll'
                else None) or (_MockUCM.state.get('tick_html_refusals') or {}).get(
                    self.path.rsplit('/', 1)[-1])
        if html:
            _MockUCM.state.setdefault('refused', []).append(self.path)
            self.send_response(500)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        refused = (_MockUCM.state.get('refusals') or {}).get(self.path.rsplit('/', 1)[-1])
        if refused:
            # What UCM really answers when it says no: the status line AND a body.
            _MockUCM.state.setdefault('refused', []).append(self.path)
            self._json(refused[1], refused[0])
            return
        if self.path == '/api/v2/ssh/hosts/enroll':
            _MockUCM.state['enrolls'].append((body, self.headers.get('Content-Type')))
            self._json({'success': True, 'data': {
                'host_token': 'ucm_sh_newtoken', 'refid': 'smoke-refid',
                'krl_path': '/ssh/krl/smoke-refid', 'public_key': CA_PUB_LINE,
                'certificate': CERT_LINE, 'valid_to': '2030-01-01T00:00:00'}}, 201)
            return
        assert self.headers.get('X-Host-Token') == 'ucm_sh_smoketoken'
        if self.path == '/api/v2/ssh/hosts/check-in':
            _MockUCM.state['checkins'].append(body)
            first = len(_MockUCM.state['checkins']) == 1
            # 1st tick: KRL moved + renewal due. 2nd tick: UCM still asks for a
            # sync, but the agent's stored ETag matches → /ssh/krl answers 304.
            self._json({'success': True, 'data': {
                'krl_changed': True, 'krl_version': 1,
                'renew_required': first, 'valid_to': '2030-01-01T00:00:00'}})
            return
        if self.path == '/api/v2/ssh/hosts/renew':
            _MockUCM.state['renews'] += 1
            self._json({'success': True, 'data': {
                'certificate': CERT_LINE, 'serial': 2,
                'valid_to': '2030-01-01T00:00:00'}})
            return
        self.send_error(404)


@pytest.fixture
def mock_ucm():
    server = ThreadingHTTPServer(('127.0.0.1', 0), _MockUCM)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _MockUCM.state = {'krl_gets': [], 'renews': 0, 'checkins': [], 'enrolls': [],
                      'krl_error': None}
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown()


@pytest.fixture
def sandbox_bin(tmp_path):
    """A PATH with only the coreutils/curl the runner needs — systemctl and
    service are deliberately absent so the smoke test cannot touch a real sshd."""
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for tool in ('curl', 'sed', 'grep', 'head', 'cat', 'mktemp', 'chmod', 'mv', 'tr',
                 'rm', 'cp', 'cut', 'ls', 'date'):
        src = subprocess.run(['which', tool], capture_output=True, text=True).stdout.strip()
        assert src, f'{tool} not available for the sandbox PATH'
        os.symlink(src, bindir / tool)
    (bindir / 'hostname').write_text('#!/bin/sh\necho ucm-smoke-host\n')
    os.chmod(bindir / 'hostname', 0o755)
    return str(bindir)


def test_runner_run_mode_syncs_krl_renews_and_honours_304(tmp_path, mock_ucm, sandbox_bin):
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    state = tmp_path / 'state'
    state.mkdir()
    conf = tmp_path / 'agent.conf'
    conf.write_text(
        f'UCM_URL="{mock_ucm}"\n'
        'HOST_TOKEN="ucm_sh_smoketoken"\n'
        'USER_CA_REFID="smoke-refid"\n'
        'KRL_PATH="/ssh/krl/smoke-refid"\n'
        f'KRL_FILE="{tmp_path / "user_krl"}"\n'
        f'USER_CA_PUB_FILE="{tmp_path / "user_ca.pub"}"\n'
        f'CERT_FILE="{tmp_path / "host-cert.pub"}"\n'
        f'SSHD_CONFIG="{tmp_path / "sshd_config"}"\n'
    )
    conf.chmod(0o600)
    env = {
        'PATH': sandbox_bin,
        'UCM_AGENT_CONF': str(conf),
        'UCM_AGENT_STATE': str(state),
        'HOME': str(tmp_path),
    }

    def run_agent():
        proc = subprocess.run(['/bin/sh', runner, 'run'], env=env, capture_output=True,
                              text=True, timeout=60)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    out = run_agent()

    # check-in said krl_changed + renew_required → the runner acted on both
    assert 'KRL synced' in out
    assert (tmp_path / 'user_krl').read_bytes() == KRL_BODY
    assert (state / 'krl.etag').read_text() == '1'
    assert (tmp_path / 'host-cert.pub').read_text().strip() == CERT_LINE
    assert _MockUCM.state['renews'] == 1

    # second timer tick: the ETag round-trips, UCM answers 304, nothing re-syncs
    out = run_agent()
    assert 'KRL synced' not in out
    assert None in _MockUCM.state['krl_gets']       # first poll: no If-None-Match
    assert '"1"' in _MockUCM.state['krl_gets']      # second poll: ETag replayed
    assert _MockUCM.state['renews'] == 1            # renew_required was false now
    assert (tmp_path / 'host-cert.pub').read_text().strip() == CERT_LINE
    # the agent.conf survived the run mode untouched (no re-enroll without a bootstrap token)
    assert 'BOOTSTRAP_TOKEN' not in conf.read_text()


def test_runner_derives_cert_path_from_host_key(tmp_path, mock_ucm, sandbox_bin):
    """B1: with no CERT_FILE the runner must install the certificate where
    sshd actually looks: <private host key>-cert.pub (the .pub stripped from
    the PUBLIC key path), not 'ssh_host_ed25519_key.pub-cert.pub'.
    The timer run mode must also never create or edit sshd_config (B2)."""
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    state = tmp_path / 'state'
    state.mkdir()
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    conf = tmp_path / 'agent.conf'
    conf.write_text(
        f'UCM_URL="{mock_ucm}"\n'
        'HOST_TOKEN="ucm_sh_smoketoken"\n'
        'USER_CA_REFID="smoke-refid"\n'
        'KRL_PATH="/ssh/krl/smoke-refid"\n'
        f'KRL_FILE="{tmp_path / "user_krl"}"\n'
        f'SSHD_CONFIG="{tmp_path / "sshd_config"}"\n'
    )
    conf.chmod(0o600)
    env = {
        'PATH': sandbox_bin,
        'UCM_AGENT_CONF': str(conf),
        'UCM_AGENT_STATE': str(state),
        'HOME': str(tmp_path),
        'SSH_HOST_KEY_DIR': str(keys),
    }
    proc = subprocess.run(['/bin/sh', runner, 'run'], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert (keys / 'ssh_host_ed25519_key-cert.pub').read_text().strip() == CERT_LINE
    assert not (keys / 'ssh_host_ed25519_key.pub-cert.pub').exists()
    assert not (tmp_path / 'sshd_config').exists()  # run mode does not touch it


def test_runner_fails_loudly_without_a_conf(tmp_path, sandbox_bin):
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    proc = subprocess.run(['/bin/sh', runner, 'run'],
                          env={'PATH': sandbox_bin, 'UCM_AGENT_CONF': str(tmp_path / 'nope.conf')},
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 1
    assert 'config not found' in proc.stderr


def _conf_and_env(tmp_path, mock_ucm, sandbox_bin, **values):
    """A runner conf + the sandbox environment every smoke test below needs."""
    state = tmp_path / 'state'
    state.mkdir()
    conf = tmp_path / 'agent.conf'
    lines = [f'UCM_URL="{mock_ucm}"']
    lines += [f'{key}="{value}"' for key, value in values.items()]
    conf.write_text('\n'.join(lines) + '\n')
    conf.chmod(0o600)
    return state, conf, {
        'PATH': str(sandbox_bin),
        'UCM_AGENT_CONF': str(conf),
        'UCM_AGENT_STATE': str(state),
        'HOME': str(tmp_path),
    }


def _run(tmp_path, env, mode):
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    proc = subprocess.run(['/bin/sh', runner, mode], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, f'{proc.stderr}\n{proc.stdout}'
    return proc.stdout


@pytest.mark.parametrize('status', [429, 500])
def test_krl_error_page_never_becomes_the_revokedkeys_file(tmp_path, mock_ucm, sandbox_bin,
                                                            status):
    """Review round 1, IMPORTANT 1: curl without `--fail` accepted a 429/500 answer
    and wrote its HTML error page into the RevokedKeys file — the host stopped
    enforcing revocations while the agent logged 'KRL synced'. Nothing is written
    and the failure is said out loud."""
    state, conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, HOST_TOKEN='ucm_sh_smoketoken',
        USER_CA_REFID='smoke-refid', KRL_PATH='/ssh/krl/smoke-refid',
        KRL_FILE=str(tmp_path / 'ucm_user_krl'), CERT_FILE=str(tmp_path / 'host-cert.pub'),
        SSHD_CONFIG=str(tmp_path / 'sshd_config'))
    good = b'good-krl-bytes\x00\x01'
    (tmp_path / 'ucm_user_krl').write_bytes(good)
    (state / 'krl.etag').write_text('old-etag')
    _MockUCM.state['krl_error'] = status

    out = _run(tmp_path, env, 'run')

    assert (tmp_path / 'ucm_user_krl').read_bytes() == good, 'an error page became the KRL'
    assert (state / 'krl.etag').read_text() == 'old-etag', 'the stored etag was overwritten'
    assert 'KRL synced' not in out
    assert 'WARN: KRL fetch failed' in out and str(status) in out
    assert _MockUCM.state['krl_gets'], 'the KRL pull never happened'
    assert not list(tmp_path.glob('ucm_user_krl.*')), 'a half-written scratch file survived'


@pytest.mark.parametrize('sep', ['\t', ' '], ids=['tab', 'space'])
def test_a_foreign_revokedkeys_path_stays_the_write_target_with_a_tab(tmp_path, mock_ucm,
                                                                       sandbox_bin, sep):
    """Review round 1, IMPORTANT 5: `RevokedKeys<TAB>/path` is the same directive to
    sshd as the space form. `directive_value` matched a literal space only, so the
    agent appended a second RevokedKeys line OpenSSH ignores — the first-value rule
    the whole write-target design rests on. `enroll` is the mode that edits the
    config, so the smoke test runs enroll against a config written with a tab."""
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    foreign_krl = tmp_path / 'pre_ucm_krl'
    foreign_krl.write_bytes(b'pre-UCM krl content')
    foreign_ca = tmp_path / 'pre_ucm_ca.pub'
    foreign_ca.write_text('ssh-ed25519 AAAAB3NzaC1kc3 pre-ucm-ca\n')
    sshd_config = tmp_path / 'sshd_config'
    sshd_config.write_text(f'TrustedUserCAKeys{sep}{foreign_ca}\nRevokedKeys{sep}{foreign_krl}\n')
    _state, _conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, BOOTSTRAP_TOKEN='ucm_boot_SMOKEtoken123',
        USER_CA_PUB_FILE=str(tmp_path / 'ucm_user_ca.pub'),
        KRL_FILE=str(tmp_path / 'ucm_user_krl'), SSH_HOST_KEY_DIR=str(keys),
        SSHD_CONFIG=str(sshd_config))

    out = _run(tmp_path, env, 'enroll')

    assert f'WARN: RevokedKeys already set to {foreign_krl}' in out, out
    assert f'WARN: TrustedUserCAKeys already set to {foreign_ca}' in out, out
    written = sshd_config.read_text()
    assert written.count('RevokedKeys') == 1 and written.count('TrustedUserCAKeys') == 1, written
    assert not (tmp_path / 'ucm_user_krl').exists(), 'wrote where nobody reads'
    assert not (tmp_path / 'ucm_user_ca.pub').exists(), 'wrote where nobody reads'
    assert foreign_krl.read_bytes() == KRL_BODY
    assert foreign_ca.read_text().strip() == CA_PUB_LINE
    assert (keys / 'ssh_host_ed25519_key-cert.pub').read_text().strip() == CERT_LINE
    backups = list(tmp_path.glob('pre_ucm_krl.ucmbak.*'))
    assert backups and backups[0].read_bytes() == b'pre-UCM krl content', 'no foreign backup'
    assert written.count('HostCertificate') == 1        # it was absent: the agent adds it
    assert _MockUCM.state['enrolls'] and _MockUCM.state['krl_gets']


def test_agent_scratch_files_are_private_under_umask_077(tmp_path, mock_ucm, sandbox_bin):
    """Review round 1, IMPORTANT 4: agent.conf is rewritten through `$CONF.tmp.$$` and
    ends up holding the long-lived host token; under the old umask that scratch file
    was 0644 between write and chmod. umask 077 must not take away what sshd reads —
    atomic_file sets 644 explicitly."""
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    _state, conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, BOOTSTRAP_TOKEN='ucm_boot_SMOKEtoken123',
        USER_CA_PUB_FILE=str(tmp_path / 'ucm_user_ca.pub'),
        KRL_FILE=str(tmp_path / 'ucm_user_krl'), SSH_HOST_KEY_DIR=str(keys),
        SSHD_CONFIG=str(tmp_path / 'sshd_config'))

    out = _run(tmp_path, env, 'enroll')

    assert 'enrolled' in out
    assert 'BOOTSTRAP_TOKEN' not in conf.read_text()
    assert 'HOST_TOKEN="ucm_sh_newtoken"' in conf.read_text()
    assert conf.stat().st_mode & 0o777 == 0o600, oct(conf.stat().st_mode)
    etag = _state / 'krl.etag'
    assert etag.read_text() == '1'
    assert etag.stat().st_mode & 0o777 == 0o600, oct(etag.stat().st_mode)   # umask reached it
    for path in (tmp_path / 'ucm_user_krl', tmp_path / 'ucm_user_ca.pub',
                 keys / 'ssh_host_ed25519_key-cert.pub'):
        assert path.stat().st_mode & 0o777 == 0o644, f'{path} not readable by sshd'
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived the run'
    assert not list(_state.glob('*.tmp.*'))


def test_runner_rejects_unknown_mode(tmp_path, sandbox_bin):
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    conf = tmp_path / 'agent.conf'
    conf.write_text('UCM_URL="http://127.0.0.1:1"\n')
    proc = subprocess.run(['/bin/sh', runner, 'explode'],
                          env={'PATH': sandbox_bin, 'UCM_AGENT_CONF': str(conf),
                               'CERT_FILE': str(tmp_path / 'cert.pub')},
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 1
    assert 'unknown mode' in proc.stderr


# ── review round 1: the builder-level fixes ─────────────────────────────────

class TestReviewerRoundOneScripts:
    def test_both_posix_scripts_set_umask_077_before_they_write_anything(self):
        """IMPORTANT 4: agent.conf holds the long-lived host token and is rewritten
        through a scratch file; /etc/ucm used to be created 0755."""
        runner = build_agent_runner('unix')
        installer = build_agent_setup_script(UCM_URL, TOKEN, 'unix')
        assert 'umask 077' in runner and 'umask 077' in installer
        # before the helper that creates scratch files / before the conf heredoc
        assert runner.index('umask 077') < runner.index('atomic_file() {')
        assert installer.index('umask 077') < installer.index('mkdir -p /etc/ucm')
        assert installer.index('umask 077') < installer.index(f'cat > {CONF_PATH}')
        assert 'chmod 600' in installer and 'chmod 700' in installer   # 0700/0600 kept

    def test_the_windows_krl_write_is_raw_bytes_not_decoded_text(self):
        """IMPORTANT 2: `$resp.Content` + `Set-Content` re-encoded a binary KRL with
        the default codepage and CRLF on every sync. The raw bytes go to a temp file
        and move in, with the same foreign-target backup the POSIX half takes."""
        runner = build_agent_runner('windows')
        body = runner[runner.index('function Fetch-Krl'):runner.index('function Renew')]
        code = '\n'.join(line for line in body.splitlines()
                         if not line.strip().startswith('#'))
        assert '[IO.File]::WriteAllBytes($tmp, $resp.RawContentStream.ToArray())' in code
        assert 'Move-Item -Force $tmp $target' in code
        assert 'Copy-Item $target "$target.ucmbak" -Force' in code
        assert '$resp.Content' not in code
        assert 'Set-Content $target' not in code and 'Write-Content $target' not in code
        # shortcut: no pwsh in CI or here — only the generated text is asserted.
        # Running the Windows half on a real host stays a manual checklist item.

    def test_without_systemd_the_installer_adds_crontab_entry(self):
        installer = build_agent_setup_script(UCM_URL, TOKEN, 'unix')
        line = next(l for l in installer.splitlines() if '*/15' in l)
        assert 'crontab -l' in line
        assert f'echo \'*/15 * * * * {RUNNER_PATH} run\'' in line
        assert line.rstrip().endswith('| crontab - 2>/dev/null || true')

    def test_without_systemd_and_without_crontab_warns_no_systemd_or_crontab_found(self, tmp_path):
        installer = build_agent_setup_script(UCM_URL, TOKEN, 'unix')
        assert 'WARN: No systemd or crontab found.' in installer

        # Verify execution in isolated PATH without systemctl or crontab
        empty_bin = tmp_path / 'empty_bin'
        empty_bin.mkdir()
        lines = installer.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith('if [ "$scheduled" -ne 1 ]; then'))
        end = next(i for i in range(start, len(lines)) if lines[i].strip() == 'fi\nfi' or (lines[i].strip() == 'fi' and lines[i+1].strip() == 'fi')) + 2
        sched_block = 'scheduled=0\n' + '\n'.join(lines[start:end])
        out = subprocess.run(['/bin/sh', '-c', f'PATH="{empty_bin}"\n{sched_block}'],
                             capture_output=True, text=True)
        assert 'WARN: No systemd or crontab found.' in out.stdout

    def test_a_cleartext_ucm_url_is_warned_about_in_the_installer(self, tmp_path):
        """MINOR 9: the host token, the certificates and the KRL cross the network
        unencrypted for the whole lifetime of the host, not only during bootstrap.
        The warning is live shell (a case on the baked URL), not a comment: run the
        extracted block against both URL forms."""
        plain = build_agent_setup_script('http://ucm.lan.local', TOKEN, 'unix')
        secure = build_agent_setup_script('https://ucm.example.com', TOKEN, 'unix')
        _syntax_check(_write(tmp_path, 'plain.sh', plain), 'sh', 'bash')

        def warning(script):
            lines = script.splitlines()
            start = next(i for i, line in enumerate(lines) if line.startswith('case "'))
            end = next(i for i in range(start, len(lines)) if lines[i].strip() == 'esac')
            out = subprocess.run(['sh', '-c', '\n'.join(lines[start:end + 1])],
                                 capture_output=True, text=True)
            assert out.returncode == 0, out.stderr
            return out.stdout

        loud = warning(plain)
        assert 'IN THE CLEAR' in loud and 'http://ucm.lan.local' in loud and 'WARN:' in loud
        assert warning(secure) == '', 'an https install must not cry cleartext'


# ── review round 2: canonical PATH, KRL placeholder, crontab, Windows order ───

CANONICAL_PATH_LITERAL = ('PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:'
                          '/sbin:/bin${PATH:+:$PATH}"')


class TestReviewerRoundTwoScripts:
    def test_the_runner_sets_and_exports_the_canonical_system_path(self):
        """IMPORTANT 2: cron exports PATH=/usr/bin:/bin on Debian/Ubuntu, where
        /usr/sbin and /sbin are not in it — sshd, systemctl and service are simply
        not found, so the timer never validates or reloads sshd."""
        runner = build_agent_runner('unix')
        assert CANONICAL_PATH_LITERAL in runner
        assert 'export PATH' in runner
        # exported before anything that resolves a binary or writes a file
        assert runner.index('PATH="/usr/local/sbin') < runner.index('. "$CONF"')
        assert runner.index('export PATH') < runner.index('umask 077')
        assert runner.index('export PATH') < runner.index('curl_get() {')

    def test_the_crontab_line_replaces_the_agent_entry_instead_of_stacking(self):
        """IMPORTANT 3, RE-PINNED for review round 3 (MINOR 1). The old contract said
        `grep -v ucm-ssh-agent`; re-installing on a host that already had the entry left
        two identical `*/15 ... run` lines (two agents per tick, double renewals).

        Re-pinned because the production contract changed on purpose, and the old wording
        was the worse bug: `grep -v ucm-ssh-agent` deletes every line that merely mentions
        the agent, so a re-install silently removed the admin's own cron job (the same
        runner at a different interval) and their comments. `grep -vF` on the exact entry
        this installer writes removes only what this installer itself writes — all copies
        of it — and leaves anything else in the crontab alone. RUNNER_PATH is fixed, so a
        fixed-string match is exact. The quote around the pattern is part of the contract:
        `*/15 * * * * /usr/local/bin/ucm-ssh-agent run` unquoted would be a glob and a
        `*` field. test_the_reprinted_crontab_line_keeps_a_hand_written_schedule runs the
        printed line against a fake crontab and proves both halves."""
        installer = build_agent_setup_script(UCM_URL, TOKEN, 'unix')
        line = next(l for l in installer.splitlines() if '*/15' in l)
        entry = f'*/15 * * * * {RUNNER_PATH} run'
        assert f"crontab -l 2>/dev/null | grep -vF '{entry}'" in line, line
        assert line.index(f"grep -vF '{entry}'") < line.index(f"; echo '{entry}'"), line
        assert line.count(f"'{entry}'") == 2, line          # filtered + re-appended
        assert 'grep -v ucm-ssh-agent' not in line, line

    def test_the_krl_placeholder_is_created_by_atomic_file_not_a_bare_redirect(self):
        """IMPORTANT 1: the placeholder the RevokedKeys line points at must carry the
        same mode every other sshd-read file gets (644), not the 0600 a bare
        redirect leaves behind under umask 077."""
        runner = build_agent_runner('unix')
        assert 'atomic_file "$krl_target" 644 < /dev/null' in runner
        assert ': > "$krl_target"' not in runner


@pytest.mark.parametrize('preset', ['unset', 'foreign-but-missing'],
                         ids=['default-path', 'foreign-path'])
def test_the_revokedkeys_placeholder_exists_at_644_when_the_first_fetch_fails(
        tmp_path, mock_ucm, sandbox_bin, preset):
    """Round 2, IMPORTANT 1, runtime half: enroll points RevokedKeys at a file, the
    first KRL fetch fails (a throttled / broken UCM on install day), and sshd is
    reloaded with a config whose RevokedKeys file is missing — sshd refuses to load
    it, so the host boots with no revocation enforcement at all."""
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    sshd_config = tmp_path / 'sshd_config'
    krl_file = tmp_path / 'ucm_user_krl'          # what a fresh install wants
    target = krl_file
    if preset == 'unset':
        sshd_config.write_text('')
    else:
        # the host already had the directive pointing elsewhere and the file behind
        # it is gone: the first value wins, so THAT path gets the placeholder
        target = tmp_path / 'pre_ucm_krl'
        sshd_config.write_text(f'RevokedKeys {target}\n')
    _state, _conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, BOOTSTRAP_TOKEN=TOKEN,
        USER_CA_PUB_FILE=str(tmp_path / 'ucm_user_ca.pub'), KRL_FILE=str(krl_file),
        SSH_HOST_KEY_DIR=str(keys), SSHD_CONFIG=str(sshd_config))
    _MockUCM.state['krl_error'] = 500

    out = _run(tmp_path, env, 'enroll')

    assert 'WARN: initial KRL fetch failed' in out, out
    assert target.exists(), f'RevokedKeys points at a missing file: {target}'
    assert target.read_bytes() == b'', 'the placeholder is not empty'
    assert target.stat().st_mode & 0o777 == 0o644, oct(target.stat().st_mode)
    written = sshd_config.read_text()
    assert written.count('RevokedKeys') == 1 and str(target) in written, written
    if preset == 'foreign-but-missing':
        assert f'WARN: RevokedKeys already set to {target}' in out, out
        assert not krl_file.exists(), 'wrote where nobody reads'
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived'


_HAS_BWRAP = shutil.which('bwrap') is not None


@pytest.mark.skipif(not _HAS_BWRAP, reason='no bubblewrap here; the cron-PATH half stays manual')
def test_cron_path_cannot_hide_sshd_from_the_runner(tmp_path, mock_ucm):
    """Round 2, IMPORTANT 2, runtime half: run the real runner with exactly what cron
    exports (PATH=/usr/bin:/bin, nothing else inherited) inside a mount sandbox whose
    /usr/sbin holds the only sshd on the box. Finding it proves the runner's own
    canonical PATH, not the caller's, is what the timer gets."""
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    state = tmp_path / 'state'
    state.mkdir()
    sshd_config = tmp_path / 'sshd_config'
    conf = tmp_path / 'agent.conf'
    conf.write_text(
        f'UCM_URL="{mock_ucm}"\n'
        f'BOOTSTRAP_TOKEN="{TOKEN}"\n'
        f'KRL_FILE="{tmp_path / "ucm_user_krl"}"\n'
        f'USER_CA_PUB_FILE="{tmp_path / "ucm_user_ca.pub"}"\n'
        f'SSHD_CONFIG="{sshd_config}"\n')
    conf.chmod(0o600)
    # A fake /usr/sbin + /usr/local/sbin (the canonical dirs cron leaves out) with
    # the only sshd/systemctl visible to the agent; each one leaves a marker.
    sbin = tmp_path / 'fakeroot' / 'usr' / 'sbin'
    local_sbin = tmp_path / 'fakeroot' / 'usr' / 'local' / 'sbin'
    sbin.mkdir(parents=True)
    local_sbin.mkdir(parents=True)
    for path in (sbin / 'sshd', sbin / 'systemctl', local_sbin / 'systemctl'):
        marker = tmp_path / ('sshd.marker' if path.name == 'sshd' else 'systemctl.marker')
        path.write_text(f'#!/bin/sh\necho {path.name} "$@" >> {marker}\nexit 0\n')
        os.chmod(path, 0o755)
    proc = subprocess.run(
        ['bwrap', '--unshare-user', '--unshare-ipc', '--unshare-pid',
         '--dev-bind', '/', '/',
         '--bind', str(local_sbin), '/usr/local/sbin',
         '--bind', str(sbin), '/usr/sbin',
         '/bin/sh', runner, 'enroll'],
        env={'PATH': '/usr/bin:/bin', 'UCM_AGENT_CONF': str(conf),
             'UCM_AGENT_STATE': str(state), 'HOME': str(tmp_path),
             'SSH_HOST_KEY_DIR': str(keys)},
        capture_output=True, text=True, timeout=90)
    assert proc.returncode == 0, f'{proc.stderr}\n{proc.stdout}'
    assert 'enrolled' in proc.stdout, proc.stdout
    marker = tmp_path / 'sshd.marker'
    assert marker.exists(), f'sshd was not found on the canonical PATH: {proc.stdout}'
    assert '-t' in marker.read_text() and str(sshd_config) in marker.read_text()
    assert 'HostCertificate' in sshd_config.read_text(), 'the guard restored the config'


def test_windows_enroll_saves_the_host_token_before_the_krl_fetch():
    """Round 2, IMPORTANT 4: on Windows the conf was written only after the KRL fetch,
    so a throwing Fetch-Krl lost the freshly issued host token (the bootstrap token is
    already spent — the host had to be reinstalled from the UI). Order, tolerance and
    the RevokedKeys placeholder are asserted on the generated text: shortcut: no pwsh
    here or in CI, running the .ps1 on a real host stays a manual checklist item."""
    runner = build_agent_runner('windows')
    enroll = runner[runner.index('function Enroll'):runner.index('if ($Mode -eq "enroll")')]
    code = '\n'.join(line for line in enroll.splitlines() if not line.strip().startswith('#'))
    assert code.index('Set-Content $confPath $lines') < code.index('Fetch-Krl'), \
        'the host token was saved after the fetch'
    assert 'WriteAllBytes($krlTarget, [byte[]]::new(0))' in code
    assert code.index('WriteAllBytes($krlTarget') < code.index('Fetch-Krl')
    assert 'try { Fetch-Krl | Out-Null } catch {' in code, 'Fetch-Krl is not tolerated'
    body = runner[runner.index('# A failed KRL fetch must not end the tick'):]
    assert 'try { $krlChanged = Fetch-Krl } catch {' in body
    assert 'if ($d.krl_changed) { $krlChanged = Fetch-Krl }' in body


# ── review round 3 (f6fed0ac3): PowerShell arrays, early KRL fields, WARN ─────

CRON_BEFORE = """MAILTO=root
# ucm-ssh-agent was scheduled by hand, slower than the installer
*/30 * * * * /usr/local/bin/ucm-ssh-agent run
0 5 * * * /usr/local/bin/ucm-ssh-agent run --quiet
*/15 * * * * /usr/local/bin/ucm-ssh-agent run
*/15 * * * * /usr/local/bin/ucm-ssh-agent run
"""


def _run_printed_crontab_line(tmp_path, snippet, before, after):
    """Feed `before` to the crontab line the installer prints and capture what it
    hands back to `crontab -`. The fake crontab is the only one on PATH."""
    bindir = tmp_path / 'cronbin'
    bindir.mkdir(exist_ok=True)      # the helper runs twice: idempotence check
    for tool in ('grep', 'cat'):
        link = bindir / tool
        if link.exists():
            continue
        src = subprocess.run(['which', tool], capture_output=True, text=True).stdout.strip()
        os.symlink(src, link)
    fake = bindir / 'crontab'
    fake.write_text('#!/bin/sh\nif [ "$1" = "-l" ]; then cat "$CRON_BEFORE"; '
                    'else cat > "$CRON_AFTER"; fi\n')
    os.chmod(fake, 0o755)
    before.write_text(CRON_BEFORE)
    proc = subprocess.run(['/bin/sh', '-c', snippet], timeout=30, capture_output=True,
                          text=True, env={'PATH': str(bindir), 'CRON_BEFORE': str(before),
                                          'CRON_AFTER': str(after)})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


class TestReviewerRoundThreeScripts:
    def test_the_reprinted_crontab_line_keeps_a_hand_written_schedule(self, tmp_path):
        """Round 3 MINOR 1, runtime half: the crontab line is executed against a fake
        crontab that already holds the installer's entry twice, a hand-written */30 for
        the same agent, another schedule and a comment. Only the exact entry may go."""
        installer = build_agent_setup_script(UCM_URL, TOKEN, 'unix')
        line = next(l for l in installer.splitlines() if '*/15' in l).strip()
        if line.endswith('2>/dev/null || true'):
            snippet = line[:-len('2>/dev/null || true')].strip()
        else:
            snippet = line
        entry = f'*/15 * * * * {RUNNER_PATH} run'
        # Why the re-pin is right: the OLD `grep -v ucm-ssh-agent` matched this line too,
        # i.e. it deleted an admin's schedule, not just the installer's own duplicate.
        assert 'ucm-ssh-agent' in [l for l in CRON_BEFORE.splitlines() if l.startswith('*/30')][0]

        before, after = tmp_path / 'cron.before', tmp_path / 'cron.after'
        _run_printed_crontab_line(tmp_path, snippet, before, after)
        result = after.read_text().splitlines()
        assert result.count(entry) == 1, result          # deduped, not stacked
        assert any(l.startswith('*/30 * * * * ') and RUNNER_PATH in l for l in result), result
        assert any(l.startswith('0 5 * * * ') for l in result), result
        assert 'MAILTO=root' in result and any(l.startswith('# ucm-ssh-agent') for l in result), result
        # Running the installer a second time must not stack anything either.
        before.write_text(after.read_text())
        _run_printed_crontab_line(tmp_path, snippet, before, after)
        assert after.read_text().splitlines().count(entry) == 1, after.read_text()

    def test_every_windows_append_to_a_get_content_result_is_an_array(self):
        """The defect f6fed0ac3 fixes: Get-Content hands back a scalar String when one
        line survives a filter, and then `+= "HOST_TOKEN=…"` concatenates onto that string
        instead of appending a line. A fresh agent.conf is UCM_URL + BOOTSTRAP_TOKEN, so
        after the bootstrap filter exactly ONE line survives — the host token got glued to
        the UCM_URL, no HOST_TOKEN existed, and the agent never checked in or renewed again.
        Same shape in the retry path ($kept) and in Ensure-Directive (a one-line
        sshd_config took the new directive glued to its only line)."""
        runner = build_agent_runner('windows')
        installer = build_agent_setup_script(UCM_URL, TOKEN, 'windows')
        code = '\n'.join(l for l in runner.splitlines() if not l.strip().startswith('#'))
        assert '$lines = @(Get-Content $confPath | Where-Object' in code
        assert '$kept = @(Get-Content $confPath | Where-Object' in code
        assert '@(Get-Content $cfgFile) + "$name $path" | Set-Content $cfgFile' in code
        # Nothing left in the unwrapped shape, in either script.
        assert '$lines = Get-Content' not in code and '$kept = Get-Content' not in code
        for text in (runner, installer):
            for line in text.splitlines():
                if line.strip().startswith('#'):
                    continue
                if '+ "' in line and 'Get-Content' in line:
                    assert '@(Get-Content' in line, f'unwrapped Get-Content append: {line}'

    def test_windows_enroll_writes_the_krl_fields_before_anything_that_can_throw(self):
        """Round 3 fix 2: USER_CA_REFID / KRL_PATH were appended to $lines only inside the
        user_ca block, AFTER `Set-Content $confPath $lines`. A throw in Ensure-Directive,
        Write-Content or Fetch-Krl left the conf holding a host token and no KRL_PATH, and
        Fetch-Krl returns $false forever after that (check-in does not repair it): the host
        kept checking in and renewing and never pulled a revocation list again. Now the two
        fields are appended with the host token, before the save, and the save is the last
        step before the directive writes."""
        runner = build_agent_runner('windows')
        enroll = runner[runner.index('function Enroll'):runner.index('if ($Mode -eq "enroll")')]
        code = '\n'.join(l for l in enroll.splitlines() if not l.strip().startswith('#'))
        save = 'Set-Content $confPath $lines'
        head, tail = code[:code.index(save)], code[code.index(save):]
        assert code.count(save) == 1, 'the conf is written twice — the late write is still there'
        assert '$lines += "HOST_TOKEN=$($data.host_token)"' in head
        assert 'if ($data.user_ca) {' in head and '$lines += "USER_CA_REFID=$($data.user_ca.refid)"' in head
        assert '$lines += "KRL_PATH=$($data.user_ca.krl_path)"' in head
        assert '+ "USER_CA_REFID=' not in tail and '+ "KRL_PATH=' not in tail
        for later in ('Ensure-Directive "HostCertificate"', 'Write-Content $target',
                      'Ensure-Directive "TrustedUserCAKeys"', 'Ensure-Directive "RevokedKeys"',
                      'Fetch-Krl', 'Reload-SSH'):
            assert code.index(save) < code.index(later), f'{later} runs before the conf save'

    def test_the_posix_placeholder_failure_logs_instead_of_aborting_enrollment(self):
        """Round 3 fix 3: `[ -f "$krl_target" ] || atomic_file … < /dev/null` was the last
        command of a `set -e` block — an unwritable RevokedKeys directory killed enroll
        right after the RevokedKeys directive had been appended to sshd_config, i.e. the
        config was left pointing at a file that does not exist (sshd would refuse to start)
        with no host-side log line. The WARN must be the same command, via a line
        continuation: as a separate statement it never runs, because set -e already exited."""
        runner = build_agent_runner('unix')
        assert 'set -e' in runner, 'the premise of the fix changed — re-check this test'
        line = next(l for l in runner.splitlines() if 'atomic_file "$krl_target" 644 < /dev/null' in l)
        assert line.rstrip().endswith('\\'), f'the WARN is a separate statement: {line}'
        tail = runner[runner.index('atomic_file "$krl_target" 644 < /dev/null'):]
        assert '|| log "WARN: could not create the placeholder for $krl_target' in tail[:220]
        # the guard still runs afterwards: a config nobody can validate is not left behind
        assert tail.index('log "WARN: could not create the placeholder') < tail.index('apply_sshd_guard')


def _enroll_sandbox(tmp_path, mock_ucm, sandbox_bin, krl_file, sshd_exit=0):
    """A fresh enroll against a host where the RevokedKeys target lives in a directory
    that does not exist. `sshd_exit` is what `sshd -t` answers on that host."""
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    sshd_config = tmp_path / 'sshd_config'
    sshd_config.write_text('')
    marker = tmp_path / 'sshd.marker'
    fake_sshd = tmp_path / 'bin' / 'sshd'          # the sandbox PATH, so the guard is real
    fake_sshd.write_text(f'#!/bin/sh\necho "$@" >> {marker}\nexit {sshd_exit}\n')
    os.chmod(fake_sshd, 0o755)
    _state, conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, BOOTSTRAP_TOKEN=TOKEN,
        USER_CA_PUB_FILE=str(tmp_path / 'ucm_user_ca.pub'), KRL_FILE=str(krl_file),
        SSH_HOST_KEY_DIR=str(keys), SSHD_CONFIG=str(sshd_config))
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    proc = subprocess.run(['/bin/sh', runner, 'enroll'], env=env, capture_output=True,
                          text=True, timeout=60)
    return proc, conf, sshd_config, marker


def test_enroll_survives_an_unwritable_revokedkeys_directory(tmp_path, mock_ucm, sandbox_bin):
    """Round 3 fix 3, runtime half: KRL_FILE points into a directory that does not exist.
    Before the fix set -e killed the script there — after `RevokedKeys <missing path>` had
    already been appended to sshd_config — and the only trace was a dead pipeline. Now the
    agent says it out loud, finishes the enroll, and the sshd -t guard still runs."""
    krl_file = tmp_path / 'no-such-dir' / 'ucm_user_krl'
    _MockUCM.state['krl_error'] = 500               # the fetch fails as well
    proc, conf, sshd_config, marker = _enroll_sandbox(tmp_path, mock_ucm, sandbox_bin, krl_file)

    assert proc.returncode == 0, f'{proc.stderr}\n{proc.stdout}'
    assert 'enrolled' in proc.stdout, proc.stdout
    assert 'WARN: initial KRL fetch failed' in proc.stdout, proc.stdout
    assert 'WARN: could not create the placeholder for' in proc.stdout, proc.stdout
    assert not krl_file.parent.exists(), 'the agent created a directory nobody asked for'
    assert 'RevokedKeys' in sshd_config.read_text(), 'the directive was never applied'
    assert marker.exists(), 'sshd -t never ran: the config was left unguarded'
    assert '-t' in marker.read_text() and str(sshd_config) in marker.read_text(), marker.read_text()
    # the host token and the KRL fields survived everything that failed
    text = conf.read_text()
    assert 'HOST_TOKEN="ucm_sh_newtoken"' in text and 'KRL_PATH="/ssh/krl/smoke-refid"' in text
    assert 'BOOTSTRAP_TOKEN' not in text
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived'


def test_a_failing_sshd_check_restores_the_config_after_the_placeholder_warning(
        tmp_path, mock_ucm, sandbox_bin):
    """The other half of 'not half-applied': sshd -t refuses the appended RevokedKeys line
    (its file cannot be created), so the guard must roll the config back instead of leaving
    a directive behind that would stop sshd from starting at all."""
    krl_file = tmp_path / 'no-such-dir' / 'ucm_user_krl'
    _MockUCM.state['krl_error'] = 500
    proc, _conf, sshd_config, _marker = _enroll_sandbox(
        tmp_path, mock_ucm, sandbox_bin, krl_file, sshd_exit=1)

    assert proc.returncode == 0, f'{proc.stderr}\n{proc.stdout}'
    assert 'WARN: sshd_config failed sshd -t; restored it, no reload' in proc.stdout, proc.stdout
    assert 'RevokedKeys' not in sshd_config.read_text(), sshd_config.read_text()
    assert not list(tmp_path.glob('sshd_config.ucmbak.*')), sshd_config.read_text()
    assert 'enrolled' in proc.stdout


# ── round 4, T4-1: an unwritable RevokedKeys target is not "synced" ──────────

def _tick(tmp_path, env):
    """One timer tick of the runner against the mock UCM; a KRL problem must not
    kill the tick, so the exit code is part of the assertion."""
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    proc = subprocess.run(['/bin/sh', runner, 'run'], env=env, capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, f'{proc.stderr}\n{proc.stdout}'
    return proc.stdout


def test_a_krl_that_cannot_be_written_is_never_reported_as_synced(
        tmp_path, mock_ucm, sandbox_bin):
    """Runtime half of T4-1, driven the way every other smoke test drives the runner
    (a `run` tick against the mock UCM): check-in succeeds, /ssh/krl answers 200 with a
    fresh body and an ETag, but the RevokedKeys target lives in a directory the agent
    must not create. Before the fix the runner logged 'KRL synced to <missing path>',
    saved the ETag and every later poll got 304 — the missing RevokedKeys file was never
    recreated while the log claimed the host enforced revocations."""
    krl_file = tmp_path / 'no-such-dir' / 'ucm_user_krl'          # deliberately absent
    state, _conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, HOST_TOKEN='ucm_sh_smoketoken',
        USER_CA_REFID='smoke-refid', KRL_PATH='/ssh/krl/smoke-refid',
        KRL_FILE=str(krl_file), CERT_FILE=str(tmp_path / 'host-cert.pub'),
        SSHD_CONFIG=str(tmp_path / 'sshd_config'))

    out = _tick(tmp_path, env)
    assert 'WARN: could not write the KRL to' in out, out
    assert 'KRL synced' not in out, out
    assert not krl_file.parent.exists(), 'the agent created a directory nobody asked for'
    assert not krl_file.exists()
    assert not (state / 'krl.etag').exists(), 'the ETag of a KRL that was not applied'
    assert not list(tmp_path.glob('*tmp*')), 'a half-written scratch file survived'

    # No 304 lock-in: the next tick polls again without If-None-Match and is served the
    # fresh body, so the write is retried instead of the agent being told nothing changed.
    out = _tick(tmp_path, env)
    assert 'KRL synced' not in out, out
    assert 'WARN: could not write the KRL to' in out, out
    polls = _MockUCM.state['krl_gets']
    assert all(p is None for p in polls), f'an unsaved KRL replayed an ETag: {polls}'
    # ... and no rewrite churn: only the renew the server actually asked for happened,
    # sshd_config was neither created nor edited nor backed up.
    assert _MockUCM.state['renews'] == 1, _MockUCM.state['renews']
    assert (tmp_path / 'host-cert.pub').read_text().strip() == CERT_LINE
    assert not (tmp_path / 'sshd_config').exists(), 'the failed KRL edited sshd_config'
    assert not list(tmp_path.glob('*.ucmbak.*')), list(tmp_path.iterdir())


def test_a_writable_revokedkeys_target_still_lands_at_644_with_an_etag(
        tmp_path, mock_ucm, sandbox_bin):
    """Positive control for the same guard: the normal path is untouched — 644, the
    KRL bytes, a saved ETag and the 304 round-trip on the next tick."""
    krl_file = tmp_path / 'ucm_user_krl'
    state, _conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, HOST_TOKEN='ucm_sh_smoketoken',
        USER_CA_REFID='smoke-refid', KRL_PATH='/ssh/krl/smoke-refid',
        KRL_FILE=str(krl_file), CERT_FILE=str(tmp_path / 'host-cert.pub'),
        SSHD_CONFIG=str(tmp_path / 'sshd_config'))

    out = _tick(tmp_path, env)
    assert f'KRL synced to {krl_file}' in out, out
    assert 'could not write the KRL' not in out, out
    assert krl_file.read_bytes() == KRL_BODY
    assert krl_file.stat().st_mode & 0o777 == 0o644, oct(krl_file.stat().st_mode)
    assert (state / 'krl.etag').read_text() == '1'
    assert not list(tmp_path.glob('*tmp*')), 'a scratch file survived'

    out = _tick(tmp_path, env)
    assert '"1"' in _MockUCM.state['krl_gets'], _MockUCM.state['krl_gets']
    assert 'KRL synced' not in out, out


class TestReviewerRoundFourScripts:
    def test_the_fetch_krl_write_is_guarded_and_both_scripts_still_parse(self, tmp_path):
        """Text half of T4-1: `atomic_file "$target" 644 < "$out"` stood alone in a
        `set -e` function, so its result was never looked at. It must sit inside a
        conditional whose failure branch logs the WARN and returns 1 BEFORE the ETag
        or CONTENT_CHANGED are touched — and the generated scripts must still parse."""
        runner = build_agent_runner('unix')
        _syntax_check(_write(tmp_path, 'runner.sh', runner), 'sh', 'bash')
        _syntax_check(_write(tmp_path, 'setup.sh',
                             build_agent_setup_script(UCM_URL, TOKEN, 'unix')), 'sh', 'bash')
        assert 'set -e' in runner, 'the premise of the fix changed — re-check this test'
        lines = [l for l in runner.splitlines() if 'atomic_file "$target" 644 < "$out"' in l]
        assert len(lines) == 1, f'a second, unguarded write appeared: {lines}'
        assert lines[0].strip() == 'if ! atomic_file "$target" 644 < "$out"; then', lines[0]
        tail = runner[runner.index('if ! atomic_file "$target" 644 < "$out"; then'):]
        guard = tail[:tail.index('\n        fi\n')]
        assert 'log "WARN: could not write the KRL to $target' in guard, guard
        assert 'return 1' in guard, guard
        assert '$ETAG_FILE' not in guard and 'CONTENT_CHANGED=1' not in guard, guard
        after = tail[tail.index('\n        fi\n'):]
        assert 'printf \'%s\' "$newetag" > "$ETAG_FILE"' in after, after[:400]
        assert 'CONTENT_CHANGED=1' in after and 'log "KRL synced' in after, after[:400]


# ── round 6, D8 (live stand): systemctl exists, systemd does not run ─────────

@pytest.mark.skipif(not _HAS_BWRAP, reason='no bubblewrap here; the installer sandbox stays manual')
@pytest.mark.parametrize('systemd_case', ['no-unit-dir', 'not-booted', 'timer-ok'],
                         ids=['unit-dir-unwritable', 'systemctl-answers-not-booted',
                              'systemd-host-gets-the-timer'])
def test_the_installer_finishes_when_systemctl_exists_but_systemd_does_not_run(tmp_path,
                                                                              mock_ucm,
                                                                              systemd_case):
    """D8, found only on the live stand: the installer chose the systemd branch by
    `command -v systemctl`, not by systemd actually running. In a container / on
    OpenRC the binary is installed, /etc/systemd/system need not exist and
    `systemctl daemon-reload` answers "System has not been booted with systemd as
    init system (PID 1)" — the old `cat > /etc/systemd/system/...: No such file or
    directory` under `set -eu` aborted the install mid-way (runner downloaded, conf
    written, no enrollment, no schedule).

    Mechanism: a bubblewrap mount sandbox (the same `_HAS_BWRAP` gate and the same
    mount shape as `test_cron_path_cannot_hide_sshd_from_the_runner`: a bind of the
    whole tree plus read-only overrides — needed because the installer redirects to
    /dev/null) with the test tree bind-mounted over /etc and a stub
    /usr/local/bin holding the stub systemctl / sshd / id, so the host system is
    unreachable for writing. `id` is stubbed to 0 because bwrap on this machine
    keeps the caller uid inside --unshare-user (measured: `id -u` prints 1000)
    while the installer insists on root; `curl` stays the real binary. Stays
    manual: a real systemd host and a real OpenRC/SysV host (report §"ручное")."""
    etc = tmp_path / 'sandbox' / 'etc'
    (etc / 'ucm').mkdir(parents=True)
    (etc / 'ssh').mkdir(parents=True)
    (etc / 'ssh' / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    (etc / 'systemd').mkdir()                       # present, but not writable below it
    units = etc / 'systemd' / 'system'
    if systemd_case != 'no-unit-dir':
        units.mkdir(parents=True)                   # a host whose unit dir is writable

    stubbin = tmp_path / 'stubbin'
    stubbin.mkdir()
    marker = tmp_path / 'systemctl.marker'
    if systemd_case == 'not-booted':
        systemctl = ('#!/bin/sh\necho "$@" >> %s\n'
                     'echo "System has not been booted with systemd as init system (PID 1)" >&2\n'
                     'exit 1\n') % marker
    else:
        systemctl = '#!/bin/sh\necho "$@" >> %s\nexit 0\n' % marker
    for name, content in (('systemctl', systemctl), ('sshd', '#!/bin/sh\nexit 0\n'),
                          ('id', '#!/bin/sh\necho 0\n')):
        (stubbin / name).write_text(content)
        os.chmod(stubbin / name, 0o755)

    installer = _write(tmp_path, 'setup.sh', build_agent_setup_script(mock_ucm, TOKEN, 'unix'))
    args = ['bwrap', '--unshare-user', '--unshare-ipc', '--unshare-pid',
            '--dev-bind', '/', '/',
            '--bind', str(etc), '/etc',
            '--bind', str(stubbin), '/usr/local/bin']
    if systemd_case == 'no-unit-dir':      # the live stand's /etc: no writable unit dir
        args += ['--ro-bind', str(etc / 'systemd'), '/etc/systemd']
    args += ['/bin/sh', installer]
    proc = subprocess.run(args, env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(tmp_path)},
                          capture_output=True, text=True, timeout=120)
    out = proc.stdout + proc.stderr
    entry = f'*/15 * * * * {RUNNER_PATH} run'

    # The install is not half-done any more: exit 0, the runner landed, the conf
    # holds the freshly issued host token, and the enroll POST reached UCM.
    assert proc.returncode == 0, out
    assert (stubbin / 'ucm-ssh-agent').exists(), out
    assert _MockUCM.state['enrolls'], f'the installer never reached enrollment: {out}'
    conf = (etc / 'ucm' / 'agent.conf').read_text()
    assert 'HOST_TOKEN="ucm_sh_newtoken"' in conf, conf
    assert 'BOOTSTRAP_TOKEN' not in conf, conf

    calls = marker.read_text() if marker.exists() else ''
    if systemd_case == 'timer-ok':
        service = (units / 'ucm-ssh-agent.service').read_text()
        timer = (units / 'ucm-ssh-agent.timer').read_text()
        assert service.count('ExecStart') == 1 and f'ExecStart={RUNNER_PATH} run' in service, service
        assert 'OnUnitActiveSec=15min' in timer, timer
        assert 'daemon-reload' in calls and 'enable --now ucm-ssh-agent.timer' in calls, calls
        assert 'timer every 15 minutes' in out, out
        assert entry not in out, f'a systemd host was told to schedule by hand: {out}'
    else:
        assert 'crontab entry added' in out, out
        assert 'enable --now ucm-ssh-agent.timer' not in calls, calls
        if systemd_case == 'no-unit-dir':
            assert not (units / 'ucm-ssh-agent.service').exists(), \
                'unit files were written where systemd does not run'
        else:
            assert 'System has not been booted with systemd as init system (PID 1)' in out, out
            assert (units / 'ucm-ssh-agent.service').exists(), out


# ── round 6, D9 (live stand): the refusal reason UCM already sent ────────────

REFUSALS = {
    'enroll': (403, {'detail': "Principal 'x' is not in the CA's allowed principals list"}),
    'check-in': (401, {'detail': 'Invalid host token'}),
    'renew': (403, {'detail': "This enrollment is bound to hostname 'host1.lab.internal'"}),
}


@pytest.mark.parametrize('advertises', [True, False],
                         ids=['curl-advertises-fail-with-body', 'curl-too-old'])
def test_the_runner_prefers_fail_with_body_and_still_falls_back_on_an_old_curl(tmp_path,
                                                                              advertises):
    """D9: `curl_get` used plain `--fail`, which throws the answer body away — the
    agent logged `ERROR: enroll refused: no response` while UCM had answered the
    exact reason. `--fail-with-body` needs curl >= 7.76, so it is detected through
    `curl --help all`.

    The generated detection is run live against a stub curl that advertises the
    flag and one that does not: an old curl keeps plain `--fail` and the runner
    still parses and keeps working (only the reason is missing there — this box
    has curl 8.18, so the fallback reason branch itself cannot be executed here).
    """
    runner = build_agent_runner('unix')
    block = [l for l in runner.splitlines()
             if l.startswith("CURL_FAIL='") or 'curl --help all' in l]
    assert len(block) == 2, block
    assert "CURL_FAIL='--fail'" in block[0], block          # the safe default first
    assert 'curl --help all 2>/dev/null | grep -q' in block[1], block
    assert "curl -sS $CURL_FAIL --connect-timeout 10 --max-time 60" in runner
    for site in ('enroll refused', 'renew refused', 'check-in refused'):
        assert site in runner, site

    stub = tmp_path / ('newcurl' if advertises else 'oldcurl')
    stub.mkdir()
    (stub / 'curl').write_text('#!/bin/sh\necho --fail-with-body\n' if advertises
                               else '#!/bin/sh\nexit 0\n')
    os.chmod(stub / 'curl', 0o755)
    proc = subprocess.run(['/bin/sh', '-c', '\n'.join(block) + '\nprintf \'%s\\n\' "$CURL_FAIL"'],
                          env={'PATH': f"{stub}:{os.environ.get('PATH', '')}"},
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    expected = '--fail-with-body' if advertises else '--fail'
    assert proc.stdout.strip() == expected, proc.stdout


def test_a_refused_enroll_logs_the_reason_instead_of_no_response(tmp_path, mock_ucm, sandbox_bin):
    """The enroll half of D9, runtime: a CA principal policy refusal must reach the
    operator verbatim. A refused enroll is still a refusal: exit 1, and the conf
    keeps its bootstrap token so the install is retryable after fixing the CA."""
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    _state, conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, BOOTSTRAP_TOKEN=TOKEN,
        USER_CA_PUB_FILE=str(tmp_path / 'ucm_user_ca.pub'), KRL_FILE=str(tmp_path / 'ucm_user_krl'),
        SSH_HOST_KEY_DIR=str(keys), SSHD_CONFIG=str(tmp_path / 'sshd_config'))
    _MockUCM.state['refusals'] = {'enroll': REFUSALS['enroll']}

    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    proc = subprocess.run(['/bin/sh', runner, 'enroll'], env=env, capture_output=True,
                          text=True, timeout=60)

    assert proc.returncode == 1, proc.stdout
    assert '/api/v2/ssh/hosts/enroll' in _MockUCM.state['refused'], _MockUCM.state['refused']
    assert "Principal 'x' is not in the CA's allowed principals list" in proc.stderr, proc.stderr
    assert 'enroll refused:' in proc.stderr, proc.stderr
    assert 'no response' not in proc.stderr, 'the old answer is back'
    text = conf.read_text()
    assert f'BOOTSTRAP_TOKEN="{TOKEN}"' in text and 'HOST_TOKEN' not in text, text
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived'


def test_a_refused_check_in_logs_the_reason_and_does_not_kill_the_tick(tmp_path, mock_ucm,
                                                                       sandbox_bin):
    """The check-in half of D9, runtime (the `Invalid host token` the live stand saw
    after a token rotation): the reason is logged, the tick still exits 0, and neither
    agent.conf nor the RevokedKeys file nor its ETag is touched by a refused call."""
    good = b'good-krl-bytes\x00\x01'
    krl_file = tmp_path / 'ucm_user_krl'
    state, conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, HOST_TOKEN='ucm_sh_smoketoken',
        USER_CA_REFID='smoke-refid', KRL_PATH='/ssh/krl/smoke-refid', KRL_FILE=str(krl_file),
        CERT_FILE=str(tmp_path / 'host-cert.pub'), SSHD_CONFIG=str(tmp_path / 'sshd_config'))
    krl_file.write_bytes(good)
    (state / 'krl.etag').write_text('1')
    conf_before = conf.read_text()
    _MockUCM.state['refusals'] = {'check-in': REFUSALS['check-in']}

    out = _tick(tmp_path, env)                     # _tick asserts exit 0 itself

    assert 'check-in refused: {"detail":"Invalid host token"}' in out, out
    assert '/api/v2/ssh/hosts/check-in' in _MockUCM.state['refused'], _MockUCM.state['refused']
    assert krl_file.read_bytes() == good, 'a refused check-in rewrote the RevokedKeys file'
    assert (state / 'krl.etag').read_text() == '1', 'the ETag of an untouched KRL moved'
    assert conf.read_text() == conf_before, 'agent.conf was rewritten by a refused check-in'
    assert not (tmp_path / 'host-cert.pub').exists(), 'a refused check-in wrote a certificate'
    assert not list(tmp_path.glob('*tmp*')), 'a scratch file survived'


def test_a_refused_renew_logs_the_reason_and_keeps_the_tick(tmp_path, mock_ucm, sandbox_bin):
    """The renew half of D9: UCM answered 403 with the reason (bound hostname /
    principal policy), so the agent must say it instead of failing silently — and the
    refusal must not fail the tick, must not write a certificate, and must not touch
    the KRL, its ETag or agent.conf."""
    good = b'good-krl-bytes\x00\x01'
    krl_file = tmp_path / 'ucm_user_krl'
    state, conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, HOST_TOKEN='ucm_sh_smoketoken',
        USER_CA_REFID='smoke-refid', KRL_PATH='/ssh/krl/smoke-refid', KRL_FILE=str(krl_file),
        CERT_FILE=str(tmp_path / 'host-cert.pub'), SSHD_CONFIG=str(tmp_path / 'sshd_config'))
    krl_file.write_bytes(good)
    (state / 'krl.etag').write_text('1')
    conf_before = conf.read_text()
    _MockUCM.state['refusals'] = {'renew': REFUSALS['renew']}

    out = _tick(tmp_path, env)                     # check-in says renew_required=true

    assert '/api/v2/ssh/hosts/renew' in _MockUCM.state['refused'], _MockUCM.state['refused']
    assert 'renew refused:' in out and "This enrollment is bound to hostname" in out, out
    assert 'WARN: check-in failed' not in out, out      # one call refused, not the tick
    assert _MockUCM.state['checkins'], 'check-in never ran'
    assert _MockUCM.state['renews'] == 0, 'the refused renew was counted as a renewal'
    assert krl_file.read_bytes() == good, 'a refused renew rewrote the RevokedKeys file'
    assert (state / 'krl.etag').read_text() == '1'
    assert conf.read_text() == conf_before, 'agent.conf was rewritten by a refused renew'
    assert not (tmp_path / 'host-cert.pub').exists(), 'a refused renew wrote a certificate'


# ── round 8, D10 (live stand): the re-install branch must show UCM's reason ────

REINSTALL_REFUSALS = [
    {'detail': "Principal 'stand4.lab.internal' is not in the CA's allowed principals list"},
    {'detail': 'CA policy rejects 100% of "principals" for this host'},   # a % and quotes
]


def _reinstall_conf(tmp_path, mock_ucm, sandbox_bin, host_token):
    """agent.conf exactly as the live stand's re-install has it: the installer just wrote
    a fresh BOOTSTRAP_TOKEN next to the long-lived HOST_TOKEN."""
    keys = tmp_path / 'sshkeys'
    keys.mkdir()
    (keys / 'ssh_host_ed25519_key.pub').write_text('ssh-ed25519 AAAAB3NzaC1kc3 hostkey\n')
    values = {'BOOTSTRAP_TOKEN': TOKEN, 'USER_CA_PUB_FILE': str(tmp_path / 'ucm_user_ca.pub'),
              'KRL_FILE': str(tmp_path / 'ucm_user_krl'), 'SSH_HOST_KEY_DIR': str(keys),
              'SSHD_CONFIG': str(tmp_path / 'sshd_config')}
    if host_token:
        values.update(HOST_TOKEN=host_token, USER_CA_REFID='smoke-refid',
                      KRL_PATH='/ssh/krl/smoke-refid')
    _state, conf, env = _conf_and_env(tmp_path, mock_ucm, sandbox_bin, **values)
    return conf, env, keys / 'ssh_host_ed25519_key-cert.pub'


def _enroll_once(tmp_path, env):
    proc = subprocess.run(['/bin/sh', _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix')),
                           'enroll'], env=env, capture_output=True, text=True, timeout=60)
    return proc, proc.stdout + proc.stderr


@pytest.mark.parametrize('payload', REINSTALL_REFUSALS, ids=['principal-policy', 'quotes-and-percent'])
def test_a_refused_reinstall_on_an_enrolled_host_says_why_ucm_said_no(tmp_path, mock_ucm,
                                                                      sandbox_bin, payload):
    """D10, found by the live re-install on stand4.lab.internal: UCM answered 403 with the
    principal-policy reason, the agent printed a guessed `token expired?`. The branch that
    keeps an enrolled host alive now prints the answer curl_get had already captured — and it
    still keeps the host alive: HOST_TOKEN and the KRL fields untouched, conf 0600, exit 0, and
    the next timer tick syncs the KRL with the same token instead of re-offering the spent
    bootstrap one. `quotes-and-percent` pins the interpolation itself: `${resp:-no response}`
    is a parameter expansion inside double quotes, so JSON quotes and a % reach the log
    verbatim — nothing re-parses the body and nothing formats it."""
    reason = json.dumps(payload, separators=(',', ':'))
    conf, env, cert_path = _reinstall_conf(tmp_path, mock_ucm, sandbox_bin,
                                          host_token='ucm_sh_smoketoken')
    _MockUCM.state['refusals'] = {'enroll': (403, payload)}

    proc, out = _enroll_once(tmp_path, env)

    assert proc.returncode == 0, out            # a re-install must not break an enrolled host
    assert f'WARN: enrollment failed ({reason})' in out, out
    assert 'continuing as enrolled host' in out, out
    assert 'token expired?' not in out, 'the guessed reason is back'
    assert 'no response' not in out, 'the reason UCM sent was thrown away'
    assert 'enroll refused:' not in out, out     # this host is not left in a failed state
    assert 'host certificate installed' not in out and 'user CA installed' not in out, out
    text = conf.read_text()
    assert 'HOST_TOKEN="ucm_sh_smoketoken"' in text, text        # kept verbatim, not re-issued
    assert text.count('HOST_TOKEN=') == 1 and text.count('ucm_sh_') == 1, text
    assert 'BOOTSTRAP_TOKEN' not in text, text
    assert f'UCM_URL="{mock_ucm}"' in text and 'USER_CA_REFID="smoke-refid"' in text, text
    assert 'KRL_PATH="/ssh/krl/smoke-refid"' in text, text       # KRL sync must survive
    assert conf.stat().st_mode & 0o777 == 0o600, oct(conf.stat().st_mode)
    assert not cert_path.exists(), 'a refused re-install wrote a certificate'
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived'
    assert _MockUCM.state['refused'] == ['/api/v2/ssh/hosts/enroll'], _MockUCM.state['refused']

    tick = _tick(tmp_path, env)                  # the host is still an enrolled host
    assert 'KRL synced' in tick, tick
    assert 'check-in refused' not in tick and 'WARN: check-in failed' not in tick, tick
    assert len(_MockUCM.state['refused']) == 1, 'the spent bootstrap token was re-offered'


def test_the_same_refusal_is_still_a_hard_failure_without_a_host_token(tmp_path, mock_ucm,
                                                                       sandbox_bin):
    """D10's contrast case: the WARN half of the branch exists only for a host that already
    has a token. A fresh host refused by the very same 403 must still fail hard (exit 1,
    `enroll refused: <reason>`) and keep its bootstrap token so the install is retryable
    after fixing the CA. Both shapes come from one generated branch — one run set."""
    payload = REINSTALL_REFUSALS[0]
    reason = json.dumps(payload, separators=(',', ':'))
    conf, env, cert_path = _reinstall_conf(tmp_path, mock_ucm, sandbox_bin, host_token=None)
    _MockUCM.state['refusals'] = {'enroll': (403, payload)}

    proc, out = _enroll_once(tmp_path, env)

    assert proc.returncode == 1, out
    assert f'enroll refused: {reason}' in out, out
    assert 'continuing as enrolled host' not in out and 'WARN: enrollment failed' not in out, out
    assert 'token expired?' not in out and 'no response' not in out, out
    text = conf.read_text()
    assert f'BOOTSTRAP_TOKEN="{TOKEN}"' in text and 'HOST_TOKEN' not in text, text
    assert not cert_path.exists(), 'a refused enroll wrote a certificate'
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived'


def test_the_posix_scripts_parse_and_carry_the_answer_exactly_once(tmp_path):
    """D10's text half, re-pinned for round 9. What matters is the contract, not the exact
    source punctuation: the enrollment-failure reason must reach the log through the
    containment helper on BOTH of its output points (the WARN branch and the enroll `die`),
    the guessed reason is gone, the enrolled-host branch is guarded on HOST_TOKEN, and both
    POSIX scripts still parse under sh -n / bash -n (a syntax error here bricks the install
    on every managed host). The exact folded text is asserted behaviourally by the runtime
    re-install tests, so this half pins the wiring — which the emitted reason cannot hide."""
    runner = build_agent_runner('unix')
    installer = build_agent_setup_script(UCM_URL, TOKEN, 'unix')
    _syntax_check(_write(tmp_path, 'runner.sh', runner), 'sh', 'bash')
    _syntax_check(_write(tmp_path, 'setup.sh', installer), 'sh', 'bash')

    warns = [l for l in runner.splitlines() if 'WARN: enrollment failed' in l]
    assert len(warns) == 1, warns
    # Exactly two brief() call sites in the whole runner: the WARN branch and the enroll die.
    # A raw `${resp}` dump — the multi-line-5xx leak the fix removes — would fail this.
    assert runner.count('brief "${resp:-no response}"') == 2, runner
    assert 'brief "${resp:-no response}"' in warns[0], warns[0]
    assert 'continuing as enrolled host' in warns[0], warns[0]
    dies = [l for l in runner.splitlines() if 'die "enroll refused' in l]
    assert len(dies) == 1 and 'brief "${resp:-no response}"' in dies[0], dies
    assert "if [ -n \"${HOST_TOKEN:-}\" ]; then" in runner
    # The guessed reason must be gone from both POSIX builds.
    assert 'token expired?' not in runner and 'token expired?' not in installer


# ── round 9, reviewer-cycle close-out (rows 1–2): the reason body is contained ──

# A proxy 5xx is a multi-line HTML page; dumping it raw floods the cron/syslog stream with
# lines that carry no [ucm-ssh-agent] prefix (reviewer round 6, MINOR 2).
HTML_5XX_PAGE = (
    b'<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n'
    b'<center><h1>502 Bad Gateway</h1></center>\n'
    b'<center>nginx proxy could not reach the UCM upstream host</center>\n'
    b'<hr><address>nginx/1.27 at 8080</address>\n</body>\n</html>'
)


def test_a_multi_line_5xx_html_body_folds_into_one_prefixed_die_line(tmp_path, mock_ucm,
                                                                      sandbox_bin):
    """Round 9 runtime half (the fresh-host `die` point). A proxy 5xx during enroll is a
    multi-line HTML page. A host with no HOST_TOKEN must still fail hard, but brief() folds
    the WHOLE page into the single prefixed `enroll refused:` line: no continuation line of
    the HTML reaches the log stream without the `[ucm-ssh-agent]` prefix, and the folded
    reason fits the 160-column cut. The bootstrap token survives so the install is retryable."""
    conf, env, cert_path = _reinstall_conf(tmp_path, mock_ucm, sandbox_bin, host_token=None)
    _MockUCM.state['enroll_html'] = HTML_5XX_PAGE

    proc, out = _enroll_once(tmp_path, env)

    assert proc.returncode == 1, out
    assert HTML_5XX_PAGE.count(b'\n') >= 4, 'the premise (a multi-line 5xx page) changed'
    lines = [l for l in out.splitlines() if l.strip()]
    refusal = [l for l in lines if 'enroll refused' in l]
    assert len(refusal) == 1, out
    line = refusal[0]
    assert line.startswith('[ucm-ssh-agent] ERROR: enroll refused: '), line
    reason = line[line.index('enroll refused: ') + len('enroll refused: '):]
    assert len(reason) <= 160, f'{len(reason)} chars leaked past the brief() cut: {reason}'
    # The front survived folded onto that one line; the long page was cut, so the closing
    # tags never show — and no HTML fragment stands on its own line.
    assert '<html>' in reason and '502 Bad Gateway' in reason, reason
    assert '</html>' not in reason and '<address>' not in reason, reason
    assert all(('<' not in l) or l.startswith('[ucm-ssh-agent] ') for l in lines), out
    text = conf.read_text()
    assert f'BOOTSTRAP_TOKEN="{TOKEN}"' in text and 'HOST_TOKEN' not in text, text
    assert not cert_path.exists(), 'a refused enroll wrote a certificate'
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived'


def test_a_multi_line_5xx_html_body_folds_into_one_prefixed_warn_line(tmp_path, mock_ucm,
                                                                       sandbox_bin):
    """Round 9 runtime half (the already-enrolled WARN point). The very same multi-line 5xx
    reaches a host that already has a token: brief() folds it into the single prefixed
    `WARN: enrollment failed (...)` line, and the host stays alive — exit 0, HOST_TOKEN and
    the KRL fields preserved, conf 0600, no scratch file left. A short JSON refusal keeps
    reaching the log verbatim; that half is pinned by the D10 re-install tests."""
    conf, env, cert_path = _reinstall_conf(tmp_path, mock_ucm, sandbox_bin,
                                           host_token='ucm_sh_smoketoken')
    _MockUCM.state['enroll_html'] = HTML_5XX_PAGE

    proc, out = _enroll_once(tmp_path, env)

    assert proc.returncode == 0, out
    lines = [l for l in out.splitlines() if l.strip()]
    warn = [l for l in lines if 'WARN: enrollment failed' in l]
    assert len(warn) == 1, out
    assert warn[0].startswith('[ucm-ssh-agent] WARN: enrollment failed ('), warn[0]
    inner = warn[0].split('enrollment failed (', 1)[1].rsplit('); continuing as enrolled host', 1)[0]
    assert len(inner) <= 160, f'{len(inner)} chars leaked past the brief() cut: {inner}'
    assert '<html>' in inner and '</html>' not in inner, inner
    assert 'continuing as enrolled host' in warn[0], warn[0]
    assert all(('<' not in l) or l.startswith('[ucm-ssh-agent] ') for l in lines), out
    assert 'token expired?' not in out, 'the guessed reason is back'
    assert 'enroll refused:' not in out, 'the enrolled host was left in a failed state'
    text = conf.read_text()
    assert 'HOST_TOKEN="ucm_sh_smoketoken"' in text and 'BOOTSTRAP_TOKEN' not in text, text
    assert text.count('HOST_TOKEN=') == 1 and text.count('ucm_sh_') == 1, text
    assert conf.stat().st_mode & 0o777 == 0o600, oct(conf.stat().st_mode)
    assert not cert_path.exists(), 'a refused re-install wrote a certificate'
    assert not list(tmp_path.glob('*.tmp.*')), 'a scratch file survived'


def test_the_windows_enroll_branch_carries_the_error_detail_and_the_guess_is_gone():
    """Reviewer round 6, IMPORTANT 1, text half: the Windows `Enroll` catch surfaces UCM's
    answer through $_.ErrorDetails.Message (the idiom exists in Windows PowerShell 5.1 and in
    pwsh 7) instead of the guessed `token expired?`. Pinned on the generated text only —
    shortcut: no pwsh in this environment, so the branch's runtime behaviour on a real
    5.1/pwsh 7 host (reason logged + HOST_TOKEN kept in C:\\ProgramData\\ucm\\agent.conf)
    stays the manual §3 checklist item; I did not execute it."""
    runner = build_agent_runner('windows')
    enroll = runner[runner.index('function Enroll'):runner.index('if ($Mode -eq "enroll")')]
    assert enroll.count('$_.ErrorDetails.Message') == 1, enroll
    assert 'catch {' in enroll and "if ($conf['HOST_TOKEN']) {" in enroll, enroll
    assert 'WARN enrollment failed ($($_.ErrorDetails.Message)); continuing as enrolled host' in enroll, enroll
    # The guessed reason must be gone from every generated half.
    for text in (runner, build_agent_runner('unix'),
                 build_agent_setup_script(UCM_URL, TOKEN, 'unix'),
                 build_agent_setup_script(UCM_URL, TOKEN, 'windows')):
        assert 'token expired?' not in text, text[:120]


# ── round 10, close-out of 5ed7dd1a5: the tick-path refusals are folded too ─────

def _tick_host(tmp_path, mock_ucm, sandbox_bin):
    """An enrolled host whose RevokedKeys file is already current: the stored etag is the
    mock's own, so every KRL GET in the tick answers 304. Then a KRL that survived the tick
    can only mean the refused call never touched it."""
    good = b'good-krl-bytes\x00\x01'
    krl_file = tmp_path / 'ucm_user_krl'
    state, conf, env = _conf_and_env(
        tmp_path, mock_ucm, sandbox_bin, HOST_TOKEN='ucm_sh_smoketoken',
        USER_CA_REFID='smoke-refid', KRL_PATH='/ssh/krl/smoke-refid', KRL_FILE=str(krl_file),
        CERT_FILE=str(tmp_path / 'host-cert.pub'), SSHD_CONFIG=str(tmp_path / 'sshd_config'))
    krl_file.write_bytes(good)
    (state / 'krl.etag').write_text('1')
    return good, krl_file, state, conf, env


def _one_tick(tmp_path, env, html_refusals):
    """One timer tick against a mock UCM that answers one of its POSTs with 500 plus the
    multi-line HTML page from round 9. Returns (exit code, stdout + stderr)."""
    _MockUCM.state['tick_html_refusals'] = html_refusals
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    proc = subprocess.run(['/bin/sh', runner, 'run'], env=env, capture_output=True,
                          text=True, timeout=60)
    return proc.returncode, proc.stdout + proc.stderr


def _assert_one_folded_refusal(out, label):
    """The containment contract on a tick line: exactly one line names the refusal, its
    reason is folded into at most 160 columns, and no fragment of the multi-line page stands
    on a line of its own without the `[ucm-ssh-agent]` prefix. Before 5ed7dd1a5 these three
    points printed `${resp}` raw, so the page arrived as seven unprefixed syslog/cron lines."""
    lines = [l for l in out.splitlines() if l.strip()]
    hits = [l for l in lines if label in l]
    assert len(hits) == 1, out
    line = hits[0]
    assert line.startswith('[ucm-ssh-agent] '), line
    reason = line.split(label, 1)[1]
    assert len(reason) <= 160, f'{len(reason)} chars leaked past the brief() cut: {reason}'
    assert HTML_5XX_PAGE.count(b'\n') >= 4, 'the premise (a multi-line 5xx page) changed'
    assert '<html>' in reason and '502 Bad Gateway' in reason, reason
    assert '</html>' not in reason and '<address>' not in reason, reason
    assert all(('<' not in l) or l.startswith('[ucm-ssh-agent] ') for l in lines), out


def test_a_multi_line_5xx_on_the_check_in_stays_one_prefixed_folded_line(tmp_path, mock_ucm,
                                                                        sandbox_bin):
    """Item 1: the check-in POST answers 500 with a proxy's HTML page. The tick must say it on
    ONE prefixed line and stay a healthy tick: exit 0, the retry warning present, and the
    RevokedKeys file, its ETag and agent.conf exactly as they were before the refused call."""
    good, krl_file, state, conf, env = _tick_host(tmp_path, mock_ucm, sandbox_bin)
    conf_before = conf.read_text()

    code, out = _one_tick(tmp_path, env, {'check-in': HTML_5XX_PAGE})

    assert code == 0, out
    _assert_one_folded_refusal(out, 'check-in refused: ')
    assert 'WARN: check-in failed' in out, out
    assert '/api/v2/ssh/hosts/check-in' in _MockUCM.state['refused'], _MockUCM.state['refused']
    assert krl_file.read_bytes() == good, 'a refused check-in rewrote the RevokedKeys file'
    assert (state / 'krl.etag').read_text() == '1', 'the ETag of an untouched KRL moved'
    assert conf.read_text() == conf_before, 'agent.conf was rewritten by a refused check-in'
    assert not (tmp_path / 'host-cert.pub').exists(), 'a refused check-in wrote a certificate'
    assert not list(tmp_path.glob('*tmp*')), 'a scratch file survived'


def test_a_multi_line_5xx_on_the_renew_is_not_counted_as_a_renewal(tmp_path, mock_ucm,
                                                                   sandbox_bin):
    """Item 2: check-in says renew_required, then the renew POST answers 500 with the same
    multi-line page. One prefixed `renew refused:` line, reason folded, no certificate, no
    renewal counted (the mock's renew counter is the outside witness), KRL/etag/agent.conf
    untouched, and — as designed for a failed renew inside a timer tick — exit 0, because the
    next tick can try again."""
    good, krl_file, state, conf, env = _tick_host(tmp_path, mock_ucm, sandbox_bin)
    conf_before = conf.read_text()

    code, out = _one_tick(tmp_path, env, {'renew': HTML_5XX_PAGE})

    assert code == 0, out
    _assert_one_folded_refusal(out, 'renew refused: ')
    assert '/api/v2/ssh/hosts/renew' in _MockUCM.state['refused'], _MockUCM.state['refused']
    assert _MockUCM.state['checkins'], 'check-in never ran'
    assert _MockUCM.state['renews'] == 0, 'the refused renew was counted as a renewal'
    assert 'host certificate renewed' not in out, out
    assert 'WARN: check-in failed' not in out, out      # the check-in answered: only renew failed
    assert krl_file.read_bytes() == good, 'a refused renew rewrote the RevokedKeys file'
    assert (state / 'krl.etag').read_text() == '1'
    assert conf.read_text() == conf_before, 'agent.conf was rewritten by a refused renew'
    assert not (tmp_path / 'host-cert.pub').exists(), 'a refused renew wrote a certificate'


def test_every_posix_refusal_print_is_folded_and_both_scripts_still_parse(tmp_path):
    """Item 3, the text half: five brief() call sites in the generated runner — the enroll
    `die` and the enrolled-host WARN (the round-9 pair, `brief "${resp:-no response}"`), plus
    the three this commit moved: two `renew refused:` and one `check-in refused:` (`brief
    "$resp"`). Every emitted refusal line goes through the fold, so no raw `${resp}` dump is
    left on either half of the runner. Both POSIX scripts must still parse: a syntax error
    here bricks the install on every managed host."""
    runner = build_agent_runner('unix')
    _syntax_check(_write(tmp_path, 'runner.sh', runner), 'sh', 'bash')
    _syntax_check(_write(tmp_path, 'setup.sh', build_agent_setup_script(UCM_URL, TOKEN, 'unix')),
                  'sh', 'bash')

    assert runner.count('brief "') == 5, [l for l in runner.splitlines() if 'brief "' in l]
    assert runner.count('brief "$resp"') == 3, runner      # 2 renew + 1 check-in
    assert runner.count('brief "${resp:-no response}"') == 2, runner   # enroll die + WARN
    prints = [l.strip() for l in runner.splitlines()
              if 'refused:' in l and ('log "' in l or 'die "' in l)]
    assert len(prints) == 4, prints
    assert all('brief "' in l for l in prints), prints


def test_the_windows_runner_has_no_raw_body_print_left(tmp_path):
    """Item 4. Invoke-RestMethod throws on a non-2xx status, so the Windows half never holds a
    body object to dump: nothing prints `$resp.content`/`.rawContent` and no line writes the
    error record itself. The answers it can print are the parsed JSON `message` and, in the
    enroll catch, `$_.ErrorDetails.Message` — NOTE: PowerShell has no brief() counterpart, so
    that one is the only place a multi-line proxy page could still span unprefixed lines.
    shortcut: no pwsh/PowerShell 5.1 in this container, so the size of that leak on a real 5xx
    stays the manual §3 checklist item; the text half below is all this environment can prove."""
    runner = build_agent_runner('windows')
    for raw in ('$resp.content', '.rawContent', 'Out-File $Error', 'Write-Output $_',
                'Write-Error $_'):
        assert raw not in runner, raw
    # Invoke-WebRequest is only there to download the BINARY RevokedKeys file; no line that
    # prints anything carries a response body.
    printed = [l.strip() for l in runner.splitlines()
               if 'Write-Output' in l or 'Write-Error' in l or 'Write-Host' in l]
    assert not [l for l in printed if 'RawContentStream' in l or 'Invoke-WebRequest' in l], printed
    # The one RawContentStream occurrence is the binary RevokedKeys file written to disk,
    # not a log print.
    raw_lines = [l.strip() for l in runner.splitlines() if 'RawContentStream' in l]
    assert len(raw_lines) == 1 and '$tmp' in raw_lines[0], raw_lines
    assert 'renew refused: $($resp.message)' in runner
    assert 'check-in refused' not in runner, 'the check-in reason is POSIX-only on Windows'
    assert not [l for l in runner.splitlines() if 'refused' in l and 'ErrorDetails' not in l
                and 'Write-' in l and '$resp.message' not in l and '$data.host_token' not in l]



def test_runner_honours_custom_hostkey_in_sshd_config(tmp_path):
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    conf = tmp_path / 'agent.conf'
    conf.write_text('UCM_URL="https://ucm.example"\n')
    keys = tmp_path / 'custom_keys'
    keys.mkdir()
    custom_pub = keys / 'my_custom_hostkey.pub'
    custom_pub.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICustomKey my_key\n")
    cfg = tmp_path / 'sshd_config'
    cfg.write_text(f"HostKey {keys}/my_custom_hostkey\n")

    script = (
        f'UCM_AGENT_CONF="{conf}"\n'
        f'SSHD_CONFIG="{cfg}"\n'
        f'SSH_HOST_KEY_DIR="{tmp_path}/unused"\n'
        f'. "{runner}"\n'
        'host_pubkey_file\n'
    )
    res = subprocess.run(['/bin/sh', '-c', script, 'sh', 'noop'], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert res.stdout.strip() == str(custom_pub)


def test_runner_generates_ed25519_key_when_no_keys_exist(tmp_path):
    runner = _write(tmp_path, 'ucm-ssh-agent', build_agent_runner('unix'))
    conf = tmp_path / 'agent.conf'
    conf.write_text('UCM_URL="https://ucm.example"\n')
    empty_dir = tmp_path / 'empty_ssh'
    empty_dir.mkdir()
    cfg = tmp_path / 'empty_sshd_config'
    cfg.write_text("# no HostKey\n")

    script = (
        f'UCM_AGENT_CONF="{conf}"\n'
        f'SSHD_CONFIG="{cfg}"\n'
        f'SSH_HOST_KEY_DIR="{empty_dir}"\n'
        f'. "{runner}"\n'
        'host_pubkey_file\n'
    )
    res = subprocess.run(['/bin/sh', '-c', script, 'sh', 'noop'], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    expected_pub = empty_dir / 'ssh_host_ed25519_key.pub'
    assert res.stdout.strip() == str(expected_pub)
    assert expected_pub.exists()
    assert (empty_dir / 'ssh_host_ed25519_key').exists()
