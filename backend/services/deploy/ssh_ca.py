"""SSH CA deployment bindings.

An SSH CA attached to an SSH deploy target says what UCM writes on that host:
the CA's public key, its KRL, and — for a host CA — a host certificate signed
for that host from the host key UCM reads on the target itself.

Why a revoke reaches every host immediately: sshd re-reads ``RevokedKeys`` on
every authentication attempt (PROTOCOL.krl), so a KRL delivery pushes a file and
runs nothing. The binding's ``reload_command`` runs only on a delivery that
changed what sshd trusts — the CA public key or the host certificate — and UCM
never calls ``sshd -t`` itself: that needs root, while the binding carries one
NOPASSWD grant, and ``systemctl reload`` validates the configuration itself on
the distributions UCM documents.
"""
import fnmatch
import logging
import posixpath
import re

from models import SSHCADeployBinding
from models.ssh import SSHCertificate
from security.encryption import decrypt_text
from services.deploy import http as deploy_http
from services.deploy import ssh as deploy_ssh
from services.ssh_cert.utils import SSHCertificateUtilsMixin
from services.ssh_krl_service import SSHKRLService
from utils.datetime_utils import utc_now
from utils.duration import parse_duration_seconds

logger = logging.getLogger(__name__)

# sshd and every client of the CA key only read these files
MODE_ARTIFACT = 0o644

# The directory UCM's own SSH CA installer creates and hands to the deploy
# service user. Everything UCM writes defaults to it, because writing into
# /etc/ssh itself would mean making sshd's directory writable by a low-privilege
# account — which is exactly what this feature must not do.
CANONICAL_DIR = '/etc/ssh/ssh_ca_keys'

# OpenSSH installs these; ed25519 first, which is also the order sshd itself
# prefers, so the key UCM signs is the key sshd presents.
HOST_KEY_FILES = tuple(
    f'{directory}/ssh_host_{name}_key.pub'
    for directory in ('/etc/ssh', '/usr/local/etc/ssh')
    for name in ('ed25519', 'ecdsa', 'rsa')
)
KEY_TYPE_PREFERENCE = ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
                       'ecdsa-sha2-nistp521', 'ssh-rsa')

# A revoke or a delete changes one file. Nothing else.
KRL_ONLY_EVENTS = ('ssh.cert.revoked', 'ssh.cert.deleted')
# Everything else writes every artefact the binding names.
FULL_EVENTS = ('initial', 'binding.updated', 'manual')

# Written into the destination directory and removed again: the only way to ask
# "may this account create a file here" without touching the real artefact.
PROBE_SUFFIX = '.ucm-probe'

# The variables a key-ID template may name. {{name}} is the target's own name,
# which is what the HTTP targets' {{name}} means for a certificate.
KEY_ID_VARIABLES = ('hostname', 'name', 'target_name', 'ca_name', 'principal', 'serial')

_HOST_KEY_GLOB = ' '.join(HOST_KEY_FILES)


class BindingRefusal(ValueError):
    """A refusal that names the field its message belongs under.

    Subclass of ValueError so the shared deploy failure handling still catches
    it, while the SSH CA routes answer RFC 7807 ``details.fields`` — the shape
    the deployment dialog maps back onto its inputs. A probe that fails for two
    paths and the sudo grant reports each of them instead of one generic error.
    """

    def __init__(self, message, field=None, i18n_key=None, values=None, fields=None):
        super().__init__(message)
        self.fields = dict(fields or {})
        if field:
            self.fields[field] = {
                'message': message,
                'i18n_key': i18n_key or 'sshDeploy.errors.invalid',
                'values': values or {},
            }


# ----------------------------------------------------------------- defaults


def ca_slug(ca) -> str:
    """The file-name form of a CA name, the way UCM's setup script names them:
    ``user CA`` -> ``user_ca``, so ``/etc/ssh/ssh_ca_keys/user_ca.pub`` is the
    same file the installer's ``TrustedUserCAKeys`` line points at."""
    slug = re.sub(r'[^a-z0-9_.-]+', '_', (ca.descr or '').lower()).strip('_.-')
    return slug or f'ca_{ca.refid[:8]}'


def _ttl_text(seconds) -> str:
    """A duration in the form the dialog writes and reads (``7d``, ``24h``), so an admin who
    typed 30d and is refused by the CA's cap reads the two numbers in the same unit. The same
    algorithm the dialog's own ``ttlText`` uses."""
    value = int(seconds or 0)
    if not value:
        return '0s'
    for unit_seconds, unit in ((86400, 'd'), (3600, 'h'), (60, 'm')):
        if value >= unit_seconds and value % unit_seconds == 0:
            return f'{value // unit_seconds}{unit}'
    return f'{value}s'


def artifact_defaults(ca, ca_type=None) -> dict:
    """The paths an attach starts from, and the paths the CA's setup script
    writes into its drop-in. One source, so a default attach and a default
    drop-in cannot name different files. ``ca_type`` overrides the CA's own type
    only for a setup script asked for one (``?type=host`` on a user CA)."""
    slug = ca_slug(ca)
    defaults = {
        'ca_pub_path': f'{CANONICAL_DIR}/{slug}.pub',
        'krl_path': f'{CANONICAL_DIR}/{slug}_revoked_keys',
        # Named after the CA, not after an algorithm: the certificate is signed
        # for whichever host key UCM reads on that target (sshd matches it to
        # HostKey by type, not by file name), and two host CAs on one host get
        # one file each instead of fighting over the same one.
        'host_cert_path': (f'{CANONICAL_DIR}/{slug}_host_key-cert.pub'
                           if (ca_type or ca.ca_type) == 'host' else None),
    }
    return defaults


# --------------------------------------------------------------- validation


def _validate_paths(data, current, out):
    for field in ('ca_pub_path', 'krl_path', 'host_cert_path'):
        if current is not None and field not in data:
            continue
        path = str(data.get(field) or '').strip()
        if path:
            if not posixpath.isabs(path) or len(path) > 512:
                raise BindingRefusal(f'{field} must be an absolute path (max 512 chars)', field,
                                     'sshDeploy.errors.pathNotAbsolute', {'field': field})
            if path.endswith('/'):
                raise BindingRefusal(f'{field} must be a file path, not a directory', field,
                                     'sshDeploy.errors.pathNotFile', {'field': field})
        out[field] = path or None


def _final(current, out, field):
    """The value the binding will hold after this request is applied."""
    if field in out:
        return out[field]
    return getattr(current, field) if current is not None else None


def _validate_principals(ca, names):
    """Exact host names only, and each one something this CA is allowed to sign.

    OpenSSH matches a host certificate's principals with strcmp (sshkey.c,
    wildcard_pattern is only ever set by ssh-agent), so a pattern stored here
    would be a principal no host ever matches. Patterns belong in the CA's
    allowed_principals, which is fnmatch.
    """
    cleaned = []
    for name in names:
        name = str(name or '').strip()
        if not name:
            continue
        if any(char in name for char in '*?[]') or any(char.isspace() for char in name):
            raise BindingRefusal(
                f"Principal '{name}' is not an exact host name: a host certificate "
                "matches exact names only, put the pattern on the CA's allowed principals",
                'principals', 'sshDeploy.errors.principalNotExact', {'principal': name})
        if len(name) > 255:
            raise BindingRefusal(f"Principal '{name}' is too long (max 255 chars)",
                                 'principals', 'sshDeploy.errors.principalTooLong',
                                 {'principal': name})
        if name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        raise BindingRefusal('At least one principal is required for the host certificate',
                            'principals', 'sshDeploy.errors.principalsRequired')

    allowed = ca.get_allowed_principals()
    if not allowed and not ca.allow_any_principal:
        raise BindingRefusal(
            f"SSH CA '{ca.descr}' lists no allowed principals: add the host names there, "
            "or allow any principal on the CA",
            'principals', 'sshDeploy.errors.caAllowsNone')
    outside = [name for name in cleaned
               if allowed and not any(fnmatch.fnmatchcase(name, pattern) for pattern in allowed)]
    if outside:
        raise BindingRefusal(
            f"Principal(s) {', '.join(repr(name) for name in outside[:5])} are not in the allowed "
            f"principals of SSH CA '{ca.descr}' ({', '.join(allowed[:10])})",
            'principals', 'sshDeploy.errors.principalNotAllowed',
            {'principals': ', '.join(outside[:5]), 'allowed': ', '.join(allowed[:10])})
    return cleaned


def _validate_key_id_template(ca, template, sample_variables):
    """Render the template now, with the values the target and the CA really
    have: the same rule HTTP targets follow — what cannot render at save time
    cannot render at push time either. Key IDs take no filter: a key ID is the
    name sshd logs, not a value to be quoted or escaped."""
    for match in deploy_http._VAR_RE.finditer(template):
        name, flt = match.group(1), match.group(2)
        if name not in KEY_ID_VARIABLES:
            raise BindingRefusal(f"Unknown template variable: {name} "
                                 f"(use {' '.join(KEY_ID_VARIABLES)})",
                                 'key_id_template', 'sshDeploy.errors.templateUnknownVariable',
                                 {'name': name})
        if flt and flt != 'raw':
            raise BindingRefusal(f"Unknown template filter: {flt} (a key ID takes {{{{{name}}}}})",
                                 'key_id_template', 'sshDeploy.errors.templateFilter',
                                 {'filter': flt, 'name': name})
    if '{{' in deploy_http._VAR_RE.sub(' ', template):
        malformed = template[template.index('{{'):][:60]
        raise BindingRefusal(f'Malformed template placeholder: {malformed} '
                             '(expected {{name}})',
                             'key_id_template', 'sshDeploy.errors.templateMalformed',
                             {'placeholder': malformed})
    try:
        deploy_http.render(template, sample_variables)
    except ValueError as e:
        raise BindingRefusal(str(e), 'key_id_template')


def validate_binding(ca, target, data, current=None) -> dict:
    """Normalised binding fields. Raises BindingRefusal naming the field at fault.

    ``current=None`` is an attach, ``current=<binding>`` is a PATCH: only the
    fields the request names are returned, but every cross-field rule is checked
    against the final state, so a partial edit cannot leave a binding that asks
    for a host certificate with nothing to sign or an expired key grant.
    """
    out = {}
    if target.is_http:
        raise BindingRefusal('SSH CA deployment requires an SSH target', 'target_id',
                            'sshDeploy.errors.httpTarget')
    _validate_paths(data, current, out)

    if not any((_final(current, out, field) for field in
                ('ca_pub_path', 'krl_path', 'host_cert_path'))):
        raise BindingRefusal('At least one artefact path is required', 'ca_pub_path',
                            'sshDeploy.errors.noPath')
    named = [path for path in (_final(current, out, field) for field in
                              ('ca_pub_path', 'krl_path', 'host_cert_path')) if path]
    if len(named) != len({posixpath.normpath(path) for path in named}):
        raise BindingRefusal('ca_pub_path, krl_path and host_cert_path must be distinct files',
                            'krl_path', 'sshDeploy.errors.pathsCollide')

    host_cert_path = _final(current, out, 'host_cert_path')
    if host_cert_path and ca.ca_type != 'host':
        raise BindingRefusal(
            f"SSH CA '{ca.descr}' is a {ca.ca_type} CA: only a host CA signs a host "
            "certificate. Leave the host certificate path empty",
            'host_cert_path', 'sshDeploy.errors.hostCertNeedsHostCA', {'ca_type': ca.ca_type})
    if ca.ca_type != 'host':
        # A user CA binding carries its CA's artefacts and nothing else: host
        # names in it would read as "who may log in here".
        for field in ('principals', 'validity', 'key_id_template'):
            if data.get(field) not in (None, '', []):
                raise BindingRefusal(
                    f"{field} does not apply to a {ca.ca_type} CA binding: only a host CA "
                    "issues host certificates", field, 'sshDeploy.errors.notForUserCA',
                    {'ca_type': ca.ca_type})

    if 'principals' in data:
        if not host_cert_path:
            raise BindingRefusal('principals apply to the host certificate: set its path first',
                                 'principals', 'sshDeploy.errors.principalsNeedHostCert')
        out['principals'] = _validate_principals(ca, data.get('principals') or [])
    elif host_cert_path and (current is None or not current.get_principals()):
        raise BindingRefusal('At least one principal is required for the host certificate',
                            'principals', 'sshDeploy.errors.principalsRequired')

    if 'validity' in data and data['validity'] not in (None, ''):
        if not host_cert_path:
            raise BindingRefusal('validity applies to the host certificate: set its path first',
                                 'validity', 'sshDeploy.errors.validityNeedHostCert')
        try:
            validity = parse_duration_seconds(data['validity'], field='validity')
        except ValueError as e:
            raise BindingRefusal(str(e), 'validity', 'sshDeploy.errors.invalidDuration')
        max_ttl = int(ca.max_ttl or 0)
        # Refuse here instead of letting the signing path clamp it silently:
        # an admin who asked for 30 days must learn the CA caps it at 7.
        if max_ttl and validity > max_ttl:
            raise BindingRefusal(
                f"validity {_ttl_text(validity)} is longer than the max_ttl of SSH CA "
                f"'{ca.descr}' ({_ttl_text(max_ttl)})", 'validity', 'sshDeploy.errors.validityTooLong',
                {'validity': _ttl_text(validity), 'max_ttl': _ttl_text(max_ttl)})
        out['validity'] = validity
    elif current is not None and 'validity' in data:
        out['validity'] = None

    if 'key_id_template' in data:
        template = str(data.get('key_id_template') or '').strip()
        if template:
            if not ca.allow_custom_key_id:
                raise BindingRefusal(
                    f"SSH CA '{ca.descr}' sets the certificate key ID itself: remove the "
                    "key ID template, or allow custom key IDs on the CA",
                    'key_id_template', 'sshDeploy.errors.keyIdNotAllowed')
            if not host_cert_path:
                raise BindingRefusal(
                    'key_id_template applies to the host certificate: set its path first',
                    'key_id_template', 'sshDeploy.errors.keyIdNeedHostCert')
            principals = out.get('principals') or (current.get_principals() if current else [])
            _validate_key_id_template(ca, template, key_id_variables(
                target, ca, principals[0] if principals else target.name, ca.serial_counter + 1))
            out['key_id_template'] = template
        else:
            out['key_id_template'] = None

    if 'host_public_key' in data:
        pasted = str(data.get('host_public_key') or '').strip()
        if pasted:
            if not host_cert_path:
                raise BindingRefusal(
                    'host_public_key applies to the host certificate: set its path first',
                    'host_public_key', 'sshDeploy.errors.hostKeyNeedHostCert')
            try:
                SSHCertificateUtilsMixin._parse_public_key(pasted)
            except ValueError as e:
                raise BindingRefusal(f'host_public_key is not an OpenSSH public key: {e}',
                                     'host_public_key', 'sshDeploy.errors.hostKeyInvalid')
            out['host_public_key'] = pasted
        else:
            out['host_public_key'] = None

    if 'reload_command' in data or current is None:
        command = str((data.get('reload_command') if 'reload_command' in data
                       else getattr(current, 'reload_command', None)) or '').strip()
        if len(command) > 512:
            raise BindingRefusal('reload_command is too long (max 512 chars)', 'reload_command')
        # The remote sshd's command is one command: the string goes to the target's shell
        # verbatim, so chaining a second command here would be a way to run anything on that
        # host through a field whose whole job is "reload sshd".
        if re.search(r'[;\n\r]|&&|\|\||\||&|`|\$\(|[<>]', command):
            raise BindingRefusal(
                'reload_command is one command: remove the shell chaining (; | & newlines, '
                'redirection > <, command substitution) and put the second command in a script '
                'the binding runs',
                'reload_command', 'sshDeploy.errors.reloadChained')
        out['reload_command'] = command or None
    if 'enabled' in data:
        out['enabled'] = bool(data['enabled'])

    return out


def key_id_variables(target, ca, principal, serial) -> dict:
    """The values a key-ID template renders with, for this target and CA."""
    return {
        'hostname': target.host,
        'name': target.name,
        'target_name': target.name,
        'ca_name': ca.descr,
        'principal': principal,
        'serial': str(serial),
    }


# ------------------------------------------------------------- path collisions


def path_collisions(target_id, ca_id, binding_id, paths):
    """The paths of ``paths`` another binding of this target already writes.

    Two CAs writing one file on one host is not two artefacts: the last push
    wins, and one CA quietly stops being trusted while its UCM card still says
    deployed. Refusing at save names both bindings; nothing here is guessed.
    """
    taken = {}
    for other in SSHCADeployBinding.query.filter_by(target_id=target_id).all():
        if other.ssh_ca_id == ca_id or (binding_id and other.id == binding_id):
            continue
        for field in ('ca_pub_path', 'krl_path', 'host_cert_path'):
            value = getattr(other, field)
            if value:
                taken.setdefault(posixpath.normpath(value), other)
    return {path: taken[posixpath.normpath(path)] for path in paths
            if path and posixpath.normpath(path) in taken}


# -------------------------------------------------------------------- probe


def _ssh_dir(path: str) -> str:
    return posixpath.dirname(posixpath.normpath(path)) or '/'


def read_host_public_keys(client):
    """The host public keys the target publishes, as ``[(line, body)]`` in sshd's
    own preference order.

    Reading them is why no key has to be pasted and no HostKey is edited: the
    key UCM signs is the key the host already runs. exec refused
    (``internal-sftp``, a chroot) arrives as DeploySSHError, which the probe
    reports as "cannot read", not as "no keys". Every line must parse: a host
    publishing a key UCM cannot read is a host this feature cannot serve.
    """
    _, stdout, stderr = deploy_ssh.read_stdout(client, f'cat {_HOST_KEY_GLOB} 2>/dev/null')
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise deploy_ssh.DeploySSHError(
            f"no host public key found at {', '.join(HOST_KEY_FILES)}"
            + (f" ({stderr[:200]})" if stderr else ''))
    keyed = [(_canonical(line), line) for line in lines]
    keyed.sort(key=lambda item: (
        KEY_TYPE_PREFERENCE.index(item[0][0]) if item[0][0] in KEY_TYPE_PREFERENCE
        else len(KEY_TYPE_PREFERENCE), item[1]))
    return [(line, body) for (algorithm, body), line in keyed]


def _canonical(public_key_data):
    """``(algorithm, base64 body)`` of an OpenSSH public key, in whichever form
    it arrived: a bare blob and a commented ``ssh-ed25519 … ucm`` line name the
    same key, and a paste is compared by what it identifies."""
    from cryptography.hazmat.primitives.serialization import ssh as ssh_serialization

    parts = ssh_serialization.serialize_ssh_public_key(
        SSHCertificateUtilsMixin._parse_public_key(public_key_data)).decode().split()
    return parts[0], parts[1]


def probe_binding(target, fields):
    """Check the privileges this binding asks for, in one SSH session.

    Returns ``(host_public_key, learned_host_key, field_errors)``.
    ``field_errors`` non-empty means the binding is not created, and each entry
    names the target account and the right it lacks. A transport failure is
    raised to the caller instead: an unreachable target is not a permissions
    problem.

    The probe is a write into the destination directory of each artefact — the
    only question sshd's reader actually depends on, since a file UCM cannot
    replace in place is an artefact that stops being current. It never writes a
    real artefact path, so a probe cannot blank the file sshd is reading.
    """
    client, learned = deploy_ssh.open_client(
        target.host, target.port, target.username, decrypt_text(target.private_key),
        target.host_key)
    try:
        failures = {}
        for field in ('ca_pub_path', 'krl_path', 'host_cert_path'):
            path = fields.get(field)
            if not path:
                continue
            probe_path = path + PROBE_SUFFIX
            try:
                deploy_ssh.push_files(client, [(probe_path, b'', MODE_ARTIFACT)])
            except deploy_ssh.DeploySSHError as e:
                failures[field] = {
                    'message': (f"Cannot write {path} as {target.username}: the account needs "
                                f"write access to {_ssh_dir(path)} and must own the files UCM "
                                f"places there ({e})"),
                    'i18n_key': 'sshDeploy.errors.pathNotWritable',
                    'values': {'path': path, 'directory': _ssh_dir(path), 'user': target.username},
                }
            else:
                try:
                    sftp = client.open_sftp()
                    try:
                        sftp.remove(probe_path)
                    finally:
                        sftp.close()
                except Exception:  # a probe file the account cannot remove is still a writable dir
                    pass

        reload_command = fields.get('reload_command')
        if reload_command and not failures.get('reload_command'):
            # Checks the grant without running it: reloading sshd at attach time
            # would be UCM acting on a host it has not been told to touch yet.
            # shortcut: this proves a NOPASSWD sudo grant for the account, not
            # that this exact command string is the granted one; upgrade to a
            # per-command check if a stand shows sudo -v passing on a broader
            # grant than the binding needs.
            try:
                exit_status, _, stderr = deploy_ssh.read_stdout(client, 'sudo -k -n -v')
            except deploy_ssh.DeploySSHError as e:
                failures['reload_command'] = {
                    'message': (f"{target.username} cannot run commands on {target.host}, so "
                                f"'{reload_command}' would never run: {e}"),
                    'i18n_key': 'sshDeploy.errors.execRefused',
                    'values': {'user': target.username, 'command': reload_command},
                }
            else:
                if exit_status != 0:
                    failures['reload_command'] = {
                        'message': (f"{target.username} has no NOPASSWD sudo grant on {target.host}: "
                                    f"add '<{target.username} ALL=(root) NOPASSWD: <{reload_command}>' "
                                    f"to sudoers{f' ({stderr[:200]})' if stderr else ''}"),
                        'i18n_key': 'sshDeploy.errors.sudoRequired',
                        'values': {'user': target.username, 'command': reload_command},
                    }

        host_public_key = None
        if fields.get('host_cert_path'):
            pasted = (fields.get('host_public_key') or '').strip()
            try:
                keys = read_host_public_keys(client)
            except deploy_ssh.DeploySSHError as e:
                if pasted:
                    # The documented fallback: the target publishes its key but
                    # will not run cat for UCM. Nothing is invented — the value
                    # is the operator's copy of that host's own key.
                    host_public_key = pasted
                else:
                    failures['host_key'] = {
                        'message': (f"UCM cannot read the host public key of {target.host}: {e}. "
                                    "Paste the contents of its /etc/ssh/ssh_host_<type>_key.pub, or "
                                    "allow exec for this account."),
                        'i18n_key': 'sshDeploy.hostKeyUnread',
                        'values': {'user': target.username, 'host': target.host},
                    }
            else:
                published = ', '.join(line.split()[0] for line, _ in keys)
                chosen = keys[0][0] if not pasted else next(
                    (line for line, body in keys if body == _canonical(pasted)[1]), None)
                if chosen is None:
                    failures['host_key'] = {
                        'message': (f"The public key pasted for {target.host} is not one of the host "
                                    f"keys that host publishes ({published}). Paste the key this host "
                                    "actually runs, or clear the field and let UCM read it"),
                        'i18n_key': 'sshDeploy.errors.hostKeyMismatch',
                        'values': {'host': target.host, 'pasted': _canonical(pasted)[0],
                                   'published': published},
                    }
                else:
                    host_public_key = chosen
        return host_public_key, learned, failures
    finally:
        try:
            client.close()
        except Exception:
            pass


# ------------------------------------------------------------- host certificate


def issue_host_certificate(binding, actor='system') -> SSHCertificate:
    """Sign the host certificate of a binding: the target's own host key, its own
    names, and the CA that owns the binding.

    The key ID is what sshd logs for this host: the CA names it unless the
    binding carries a template and the CA allows custom key IDs.
    """
    from services.ssh_cert import SSHCertificateService

    ca = binding.ssh_ca
    if not ca:
        raise ValueError('SSH CA no longer exists')
    if ca.ca_type != 'host':
        raise ValueError(f"SSH {ca.ca_type} CA cannot sign a host certificate")
    if not binding.host_public_key:
        raise ValueError(
            'This binding has no host public key to sign: UCM could not read one on the '
            'target, so paste the host public key on the binding')
    principals = _validate_principals(ca, binding.get_principals())

    key_id = None
    if binding.key_id_template and ca.allow_custom_key_id:
        target = binding.target
        key_id = deploy_http.render(
            binding.key_id_template,
            key_id_variables(target, ca, principals[0], ca.serial_counter + 1))

    return SSHCertificateService.sign_certificate(
        ca_id=ca.id,
        public_key_data=binding.host_public_key,
        cert_type='host',
        principals=principals,
        validity_seconds=binding.validity,
        key_id=key_id,
        source='deploy',
        username=actor,
        deploy_target_id=binding.target_id,
    )


def current_or_new_host_certificate(binding, actor='system') -> SSHCertificate:
    """The certificate to deliver: the one this binding already issued while it
    is still usable, a fresh signature otherwise.

    Re-signing on every re-push would spend a serial number for nothing; a
    certificate that is revoked or outside its validity period is the case where
    pushing it again has to mean signing it again. Reissuing on a schedule
    (auto-renewal) is not part of this release, so "Deploy now" is what renews
    an expired host certificate today.
    """
    certificate = binding.current_host_certificate()
    if certificate and not certificate.revoked and certificate.valid_to > utc_now():
        return certificate
    return issue_host_certificate(binding, actor=actor)


# --------------------------------------------------------------------- files


def resolve_files(binding, event: str, actor: str = 'system'):
    """``(files, needs_reload)`` of one delivery.

    A revoke or a delete refreshes the KRL and nothing else, which is what makes
    "revoke in UCM, the next login refuses" work without restarting sshd on
    every bound host.

    ``needs_reload`` is what gates the binding's command: only a write that
    changed what sshd trusts — its CA key or its host certificate — deserves one.
    """
    if event not in KRL_ONLY_EVENTS and event not in FULL_EVENTS:
        raise ValueError(f'Unknown SSH CA deployment event: {event}')
    ca = binding.ssh_ca
    if not ca:
        raise ValueError('SSH CA no longer exists')
    full = event in FULL_EVENTS

    files = []
    needs_reload = False
    if full and binding.ca_pub_path:
        files.append((binding.ca_pub_path, (ca.public_key.rstrip('\n') + '\n').encode(),
                      MODE_ARTIFACT))
        needs_reload = True
    if binding.krl_path:
        try:
            krl = SSHKRLService.generate_krl(ca.id)
        except RuntimeError as e:
            raise ValueError(f'KRL generation failed: {e}') from None
        files.append((binding.krl_path, krl, MODE_ARTIFACT))
    if full and binding.host_cert_path:
        certificate = current_or_new_host_certificate(binding, actor=actor)
        files.append((binding.host_cert_path,
                      (certificate.certificate.rstrip('\n') + '\n').encode(), MODE_ARTIFACT))
        needs_reload = True
    if not files:
        raise ValueError('This binding writes no file for this event '
                         '(a revoke or delete only refreshes krl_path)')
    return files, needs_reload


# ------------------------------------------------------------- delete blockers


def binding_blocker(ca) -> str:
    """Why this SSH CA cannot be deleted, or '' when nothing blocks it.

    Deployed artefacts are out there on other hosts right now: deleting the CA
    would leave hosts trusting a key UCM no longer has and revoking nothing.
    """
    count = ca.deploy_bindings.count()
    return (f"Cannot delete SSH CA: {count} deploy target binding(s) use it. "
            "Remove the bindings first." if count else '')
