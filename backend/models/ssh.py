"""
SSH Certificate Authority Models

SSH CAs are separate from X.509 CAs — they use the OpenSSH certificate format
(PROTOCOL.certkeys) rather than X.509v3. Two models:

- SSHCertificateAuthority: stores CA key pair, type (user/host), serial counter
- SSHCertificate: stores issued SSH certificates with principals, extensions, etc.

Uses `cryptography` library's native SSHCertificateBuilder (v46+).
"""

import json
import uuid
from utils.datetime_utils import utc_now, utc_isoformat

try:
    from models import db
except ImportError:
    db = None


class SSHCertificateAuthority(db.Model if db else object):
    """SSH Certificate Authority — manages OpenSSH CA key pairs"""

    __tablename__ = 'ssh_cas'
    # One HSM key backs one SSH CA at most (migration 163); NULLs stay distinct
    __table_args__ = (db.Index('uq_ssh_cas_hsm_key_id', 'hsm_key_id', unique=True),) if db else ()

    id = db.Column(db.Integer, primary_key=True)
    refid = db.Column(db.String(36), unique=True, nullable=False, index=True,
                      default=lambda: str(uuid.uuid4()))
    descr = db.Column(db.String(255), nullable=False)

    # CA type: 'user' or 'host'
    ca_type = db.Column(db.String(10), nullable=False, index=True)

    # Key material — public key in OpenSSH format, private key base64-encoded (optionally encrypted)
    public_key = db.Column(db.Text, nullable=False)
    # An HSM-backed CA stores no private key: the column stays an empty string
    private_key = db.Column(db.Text, nullable=False)
    # 'software' (private_key above) or 'hsm' (the key lives on the token; hsm_key_id points at it)
    key_source = db.Column(db.String(20), nullable=False, default='software', server_default='software')
    hsm_key_id = db.Column(db.Integer, db.ForeignKey('hsm_keys.id'), nullable=True)
    hsm_key = db.relationship('HsmKey', backref='ssh_certificate_authorities')

    # Key metadata
    key_type = db.Column(db.String(20), nullable=False)  # ed25519, rsa, ecdsa-p256, ecdsa-p384, ecdsa-p521
    fingerprint = db.Column(db.String(100), nullable=False, index=True)  # SHA256:base64

    # Serial counter — atomically incremented for each issued cert
    serial_counter = db.Column(db.Integer, default=0, nullable=False)

    # Default validity (seconds) — overridable per cert
    default_ttl = db.Column(db.Integer, default=86400)  # 24h for user, 31536000 for host

    # Max allowed validity (seconds) — 0 means unlimited
    max_ttl = db.Column(db.Integer, default=0)

    # Host-certificate lifecycle (host CAs only, migration 302): TTL of managed
    # host certs, isolated from the day-short user default_ttl, and the percent
    # of remaining validity at which renewal starts.
    host_cert_ttl = db.Column(db.Integer, default=2592000, nullable=False)  # 30 days
    renew_threshold_percent = db.Column(db.Integer, default=30, nullable=False)

    # Bumped on every revoked certificate of this CA; the ETag source of the
    # pull-only /ssh/krl/<refid> endpoint (agents poll, UCM never pushes).
    krl_version = db.Column(db.Integer, default=0, nullable=False)

    # Default extensions for user certs (JSON list of extension names)
    default_extensions = db.Column(db.Text)

    # JSON list of allowed principal patterns (fnmatch)
    allowed_principals = db.Column(db.Text)
    # An empty list signs for nothing unless this says any principal will do
    allow_any_principal = db.Column(db.Boolean, default=False, nullable=False)
    # Off: the CA names every certificate principals@CA, as sshd will log it
    allow_custom_key_id = db.Column(db.Boolean, default=False, nullable=False)

    # Comment / notes
    comment = db.Column(db.Text)

    # Audit
    created_at = db.Column(db.DateTime, default=utc_now)
    created_by = db.Column(db.String(80))

    # Ownership
    # No access control reads it; kept for older databases and backups
    owner_group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=True)
    owner_group = db.relationship('Group', backref='owned_ssh_cas')

    # Relationships
    certificates = db.relationship('SSHCertificate', backref='ca', lazy='dynamic',
                                   cascade='all, delete-orphan')

    VALID_CA_TYPES = ['user', 'host']
    VALID_KEY_TYPES = ['ed25519', 'rsa', 'ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521']

    # Standard OpenSSH user cert extensions
    STANDARD_EXTENSIONS = [
        'permit-pty',
        'permit-user-rc',
        'permit-agent-forwarding',
        'permit-port-forwarding',
        'permit-X11-forwarding',
    ]

    def get_default_extensions(self):
        """Get default extensions list.

        An unset column (NULL — the policy was never configured) serves the
        standard OpenSSH extension set, so pre-existing CAs keep issuing
        unchanged. A stored empty list ('[]') is an explicit "no extensions"
        policy and returns []. Since signing.py enforces this list as the
        allow-list for caller-requested extensions, the distinction is a
        security boundary: without it, clearing the policy re-inflated to the
        full standard set (permit-port-forwarding and permit-agent-forwarding
        included).
        """
        if not self.default_extensions:
            return list(self.STANDARD_EXTENSIONS)
        try:
            return json.loads(self.default_extensions)
        except (json.JSONDecodeError, TypeError):
            return list(self.STANDARD_EXTENSIONS)

    def set_default_extensions(self, extensions):
        """Set default extensions from list.

        ``None`` clears the column back to "unset" (standard set applies).
        An empty list is persisted as ``'[]'`` — an explicit "nothing
        permitted" policy. It used to collapse to ``None`` (``if extensions``
        is falsy for ``[]``), which the getter re-inflated to the full
        standard set: an admin clearing the policy silently got allow-all.
        """
        self.default_extensions = (
            json.dumps(extensions) if extensions is not None else None
        )

    def get_allowed_principals(self):
        """Get allowed principals list"""
        if not self.allowed_principals:
            return []
        try:
            return json.loads(self.allowed_principals)
        except (json.JSONDecodeError, TypeError):
            return []

    def set_allowed_principals(self, principals):
        """Set allowed principals from list"""
        self.allowed_principals = json.dumps(principals) if principals else None

    def to_dict(self):
        """Convert to dict for API response"""
        cert_count = self.certificates.count() if self.certificates else 0
        revoked_count = self.certificates.filter_by(revoked=True).count() if self.certificates else 0

        return {
            'id': self.id,
            'refid': self.refid,
            'descr': self.descr,
            'name': self.descr,
            'ca_type': self.ca_type,
            'public_key': self.public_key,
            'key_type': self.key_type,
            'key_source': self.key_source or 'software',
            'hsm_key_id': self.hsm_key_id,
            'hsm_key_label': self.hsm_key.label if self.hsm_key else None,
            'fingerprint': self.fingerprint,
            'serial_counter': self.serial_counter,
            'default_ttl': self.default_ttl,
            'max_ttl': self.max_ttl,
            'host_cert_ttl': self.host_cert_ttl,
            'renew_threshold_percent': self.renew_threshold_percent,
            'krl_version': self.krl_version or 0,
            'default_extensions': self.get_default_extensions(),
            'allowed_principals': self.get_allowed_principals(),
            'allow_any_principal': bool(self.allow_any_principal),
            'allow_custom_key_id': bool(self.allow_custom_key_id),
            'comment': self.comment,
            'created_at': utc_isoformat(self.created_at),
            'created_by': self.created_by,
            'owner_group_name': self.owner_group.name if self.owner_group else None,
            'cert_count': cert_count,
            'revoked_count': revoked_count,
        }

    def __repr__(self):
        return f'<SSHCertificateAuthority {self.descr} ({self.ca_type})>'


class SSHCertificate(db.Model if db else object):
    """SSH Certificate — issued by an SSH CA"""

    __tablename__ = 'ssh_certificates'
    # A KRL revokes by serial (PROTOCOL.krl): a non-zero serial once per CA; rows issued twice
    # before 3.0 keep their number, marked by upgrade step 168 (utils/ssh_serials.py)
    __table_args__ = (db.Index('uq_ssh_certificates_ca_serial', 'ssh_ca_id', 'serial', unique=True,
                               sqlite_where=db.text('serial <> 0 AND NOT serial_duplicate'),
                               postgresql_where=db.text('serial <> 0 AND NOT serial_duplicate')),) if db else ()

    id = db.Column(db.Integer, primary_key=True)
    refid = db.Column(db.String(36), unique=True, nullable=False, index=True,
                      default=lambda: str(uuid.uuid4()))
    descr = db.Column(db.String(255))

    # FK to SSH CA
    ssh_ca_id = db.Column(db.Integer, db.ForeignKey('ssh_cas.id'), nullable=False, index=True)

    # Certificate type: 'user' (1) or 'host' (2)
    cert_type = db.Column(db.String(10), nullable=False, index=True)

    # OpenSSH certificate key_id field; principals@CA name has no fixed bound
    key_id = db.Column(db.Text, nullable=False)

    # The subject's public key (OpenSSH format)
    public_key = db.Column(db.Text, nullable=False)

    # The signed certificate (OpenSSH format: "ssh-...-cert-v01@openssh.com AAAA...")
    certificate = db.Column(db.Text, nullable=False)

    # Principals (JSON array of strings)
    principals = db.Column(db.Text, nullable=False)

    # Serial number assigned by the CA
    serial = db.Column(db.Integer, nullable=False, index=True)
    # Shares its serial with another certificate of its CA: out of the unique index, shown with its remedy
    serial_duplicate = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())

    # Validity window (stored as UTC datetime for easy querying)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=False, index=True)

    # Key metadata
    key_type = db.Column(db.String(20), nullable=False)  # ed25519, rsa, ecdsa-p256, etc.
    fingerprint = db.Column(db.String(100), nullable=False, index=True)  # Subject key fingerprint

    # Extensions and critical options (JSON dicts)
    extensions = db.Column(db.Text)
    critical_options = db.Column(db.Text)

    # Revocation
    revoked = db.Column(db.Boolean, default=False, index=True)
    revoked_at = db.Column(db.DateTime)
    revoke_reason = db.Column(db.String(255))

    # Source: 'web', 'api', 'auto'
    source = db.Column(db.String(20), default='web')

    # Audit
    created_at = db.Column(db.DateTime, default=utc_now)
    created_by = db.Column(db.String(80))

    # Ownership
    # No access control reads it; kept for older databases and backups
    owner_group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=True)
    owner_group = db.relationship('Group', backref='owned_ssh_certificates')

    VALID_CERT_TYPES = ['user', 'host']

    def get_principals(self):
        """Get principals as list"""
        if not self.principals:
            return []
        try:
            return json.loads(self.principals)
        except (json.JSONDecodeError, TypeError):
            return []

    def set_principals(self, principals):
        """Set principals from list"""
        self.principals = json.dumps(principals)

    def get_extensions(self):
        """Get extensions as dict"""
        if not self.extensions:
            return {}
        try:
            return json.loads(self.extensions)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_extensions(self, extensions):
        """Set extensions from dict"""
        self.extensions = json.dumps(extensions) if extensions else None

    def get_critical_options(self):
        """Get critical options as dict"""
        if not self.critical_options:
            return {}
        try:
            return json.loads(self.critical_options)
        except (json.JSONDecodeError, TypeError):
            return {}

    def set_critical_options(self, options):
        """Set critical options from dict"""
        self.critical_options = json.dumps(options) if options else None

    @property
    def is_expired(self):
        """Check if certificate has expired"""
        if not self.valid_to:
            return False
        return self.valid_to < utc_now()

    @property
    def status(self):
        """Compute certificate status"""
        if self.revoked:
            return 'revoked'
        if self.is_expired:
            return 'expired'
        return 'valid'

    @staticmethod
    def shared_serials():
        """{(ssh_ca_id, serial): ids} of every serial two certificates of one CA hold; one query."""
        marked = (db.session.query(SSHCertificate.ssh_ca_id, SSHCertificate.serial)
                  .filter(SSHCertificate.serial_duplicate.is_(True)).distinct().subquery())
        rows = (db.session.query(SSHCertificate.id, SSHCertificate.ssh_ca_id, SSHCertificate.serial)
                .join(marked, db.and_(SSHCertificate.ssh_ca_id == marked.c.ssh_ca_id,
                                      SSHCertificate.serial == marked.c.serial))
                .order_by(SSHCertificate.id))
        shared = {}
        for row_id, ca_id, serial in rows:
            shared.setdefault((ca_id, serial), []).append(row_id)
        return shared

    def to_dict(self, shared=None):
        """API form; *shared*: ``shared_serials()`` read once for a page of certificates."""
        return {
            'id': self.id,
            'refid': self.refid,
            'descr': self.descr,
            'ssh_ca_id': self.ssh_ca_id,
            'ca_name': self.ca.descr if self.ca else None,
            'cert_type': self.cert_type,
            'key_id': self.key_id,
            'public_key': self.public_key,
            'certificate': self.certificate,
            'principals': self.get_principals(),
            'serial': self.serial,
            # Ids of the other certificates of this CA holding this serial: a KRL revokes them all
            'serial_shared_with': [i for i in (SSHCertificate.shared_serials() if shared is None else shared)
                                   .get((self.ssh_ca_id, self.serial), []) if i != self.id] if self.serial else [],
            'valid_from': utc_isoformat(self.valid_from),
            'valid_to': utc_isoformat(self.valid_to),
            'key_type': self.key_type,
            'fingerprint': self.fingerprint,
            'extensions': self.get_extensions(),
            'critical_options': self.get_critical_options(),
            'revoked': self.revoked,
            'revoked_at': utc_isoformat(self.revoked_at),
            'revoke_reason': self.revoke_reason,
            'source': self.source,
            'status': self.status,
            'created_at': utc_isoformat(self.created_at),
            'created_by': self.created_by,
            'owner_group_name': self.owner_group.name if self.owner_group else None,
        }

    def __repr__(self):
        return f'<SSHCertificate {self.key_id} ({self.cert_type})>'


class SSHManagedHost(db.Model if db else object):
    """A server enrolled in UCM's SSH pull-model (migration 138).

    The host runs ucm-ssh-agent and contacts UCM itself: public KRL download
    (no secret) for its user CA, host-certificate enrollment/renewal with its
    scoped host token. UCM never connects to the server.
    """

    __tablename__ = 'ssh_managed_hosts'

    STATUS_PENDING = 'pending'
    STATUS_ACTIVE = 'active'
    STATUS_REVOKED = 'revoked'
    VALID_STATUSES = [STATUS_PENDING, STATUS_ACTIVE, STATUS_REVOKED]

    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False, index=True)

    host_ca_id = db.Column(db.Integer, db.ForeignKey('ssh_cas.id'), nullable=True, index=True)
    user_ca_id = db.Column(db.Integer, db.ForeignKey('ssh_cas.id'), nullable=True, index=True)
    host_ca = db.relationship('SSHCertificateAuthority', foreign_keys=[host_ca_id])
    user_ca = db.relationship('SSHCertificateAuthority', foreign_keys=[user_ca_id])

    # Host token: SHA-256 hash only in DB; plaintext handed out once at enroll
    token_hash = db.Column(db.String(64), unique=True)
    token_prefix = db.Column(db.String(16))

    # One-time bootstrap token for the install command (hash only)
    bootstrap_hash = db.Column(db.String(64), index=True)
    bootstrap_expires = db.Column(db.DateTime)

    public_key = db.Column(db.Text)
    principals = db.Column(db.Text)  # JSON list, fixed at enroll

    current_cert_id = db.Column(db.Integer, db.ForeignKey('ssh_certificates.id'), nullable=True)
    current_cert = db.relationship('SSHCertificate', foreign_keys=[current_cert_id])

    auto_renew = db.Column(db.Boolean, default=True, nullable=False)
    status = db.Column(db.String(10), default=STATUS_PENDING, nullable=False, index=True)

    # Per-host overrides (NULL = inherit from host_ca)
    host_cert_ttl = db.Column(db.Integer, nullable=True)
    renew_threshold_percent = db.Column(db.Integer, nullable=True)
    # Boolean sync flag: reset to False when CA/cert config changes on an active host,
    # set back to True once the agent applies the new config on check-in.
    config_synced = db.Column(db.Boolean, default=True, nullable=False)

    last_seen_at = db.Column(db.DateTime)
    last_krl_sync_at = db.Column(db.DateTime)
    last_renew_at = db.Column(db.DateTime)
    last_ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=utc_now)

    def get_principals(self):
        try:
            return json.loads(self.principals) if self.principals else []
        except (json.JSONDecodeError, TypeError):
            return []

    def cert_status(self):
        """Lifecycle of the current host certificate for the UI."""
        if not self.current_cert:
            return None
        if self.current_cert.revoked:
            return 'revoked'
        if self.current_cert.valid_to <= utc_now():
            return 'expired'
        total = (self.current_cert.valid_to - self.current_cert.valid_from).total_seconds()
        remaining = (self.current_cert.valid_to - utc_now()).total_seconds()
        threshold = self.renew_threshold_percent or (self.host_ca.renew_threshold_percent if self.host_ca else 30) or 30
        if total > 0 and remaining <= total * threshold / 100:
            return 'expiring'
        return 'valid'

    def to_dict(self):
        cert = self.current_cert
        now = utc_now()
        ca_ttl = self.host_ca.host_cert_ttl if self.host_ca else 2592000
        ca_threshold = self.host_ca.renew_threshold_percent if self.host_ca else 30
        return {
            'id': self.id,
            'hostname': self.hostname,
            'host_ca_id': self.host_ca_id,
            'host_ca_name': self.host_ca.descr if self.host_ca else None,
            'host_ca_default_ttl': ca_ttl,
            'host_ca_default_threshold': ca_threshold,
            'user_ca_id': self.user_ca_id,
            'user_ca_name': self.user_ca.descr if self.user_ca else None,
            'host_cert_ttl': self.host_cert_ttl,
            'renew_threshold_percent': self.renew_threshold_percent,
            'effective_host_cert_ttl': self.host_cert_ttl or ca_ttl,
            'effective_renew_threshold_percent': self.renew_threshold_percent or ca_threshold,
            'config_synced': bool(self.config_synced),
            'token_prefix': self.token_prefix,
            'principals': self.get_principals(),
            'public_key': self.public_key,
            'auto_renew': bool(self.auto_renew),
            'status': self.status,
            'cert_id': cert.id if cert else None,
            'cert_serial': cert.serial if cert else None,
            'cert_valid_to': utc_isoformat(cert.valid_to) if cert else None,
            'cert_status': self.cert_status(),
            'has_token': bool(self.token_hash),
            'bootstrap_active': bool(self.bootstrap_hash and self.bootstrap_expires
                                      and self.bootstrap_expires > now),
            'last_seen_at': utc_isoformat(self.last_seen_at),
            'last_krl_sync_at': utc_isoformat(self.last_krl_sync_at),
            'last_renew_at': utc_isoformat(self.last_renew_at),
            'last_ip': self.last_ip,
            'created_at': utc_isoformat(self.created_at),
        }

    def __repr__(self):
        return f'<SSHManagedHost {self.hostname} ({self.status})>'
