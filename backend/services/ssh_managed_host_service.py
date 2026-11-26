"""
SSH Managed Hosts service — pull-model registry (SPEC_SSH_HOSTS_AND_KRL_AUTOMATION).

Hosts contact UCM themselves; UCM never opens a connection to a server:
- KRL for the host's user CA: public download with ETag, no secret needed.
- Host certificate: enrollment with a one-time bootstrap token, renewal with a
  scoped host token (only this host_id / host_ca_id can be renewed with it).

Guard rails: auto_renew off keeps the current certificate valid until it
expires; revoking the certificate sets status=revoked, auto_renew off and
invalidates both tokens; deleting a host is blocked while auto_renew is on and
the certificate is still valid.
"""

import fnmatch
import hashlib
import json
import logging
import secrets
from datetime import timedelta

from models import db
from models.ssh import SSHCertificate, SSHCertificateAuthority, SSHManagedHost
from services.ssh_cert_service import SSHCertificateService
from utils.datetime_utils import utc_now, utc_isoformat

logger = logging.getLogger(__name__)

BOOTSTRAP_TTL_SECONDS = 4 * 3600  # spec: 1-4 hours
_HOST_TOKEN_PREFIX = 'ucm_sh_'


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def verify_host_token(host_token: str):
    """Resolve a host token to its host, or None."""
    if not host_token or not host_token.startswith(_HOST_TOKEN_PREFIX):
        return None
    return SSHManagedHost.query.filter_by(token_hash=_hash_token(host_token)).first()


def _validate_ca_pair(host_ca_id, user_ca_id):
    if not host_ca_id and not user_ca_id:
        raise ValueError("At least one CA (host CA or user CA) must be specified")
    host_ca = None
    if host_ca_id:
        host_ca = db.session.get(SSHCertificateAuthority, host_ca_id)
        if not host_ca:
            raise ValueError(f"Host CA not found: {host_ca_id}")
        if host_ca.ca_type != 'host':
            raise ValueError(f"CA '{host_ca.descr}' is not a host CA")
    user_ca = None
    if user_ca_id:
        user_ca = db.session.get(SSHCertificateAuthority, user_ca_id)
        if not user_ca:
            raise ValueError(f"User CA not found: {user_ca_id}")
        if user_ca.ca_type != 'user':
            raise ValueError(f"CA '{user_ca.descr}' is not a user CA")
    return host_ca, user_ca


class SSHManagedHostService:

    @staticmethod
    def create_host(hostname, host_ca_id=None, user_ca_id=None,
                    username=None):
        """Register a pending host and mint its one-time bootstrap token.

        Returns (host, bootstrap_token_plaintext). hostname may be empty —
        then the agent supplies it at enroll.
        """
        hostname = (hostname or '').strip()
        if hostname and SSHManagedHost.query.filter_by(hostname=hostname).first():
            raise ValueError(f"A managed host named '{hostname}' already exists")
        _validate_ca_pair(host_ca_id, user_ca_id)

        bootstrap = f"ucm_boot_{secrets.token_urlsafe(24)}"
        host = SSHManagedHost(
            hostname=hostname or f"pending-{secrets.token_hex(4)}",
            host_ca_id=host_ca_id or None,
            user_ca_id=user_ca_id or None,
            bootstrap_hash=_hash_token(bootstrap),
            bootstrap_expires=utc_now() + timedelta(seconds=BOOTSTRAP_TTL_SECONDS),
            status=SSHManagedHost.STATUS_PENDING,
        )
        db.session.add(host)
        db.session.commit()
        logger.info("SSH managed host %r created (pending) by %s", host.hostname, username)
        return host, bootstrap

    @staticmethod
    def issue_bootstrap(host_id):
        """New bootstrap token for an existing host (re-install). Old one dies."""
        host = db.session.get(SSHManagedHost, host_id)
        if not host:
            raise ValueError("Managed host not found")
        if host.status == SSHManagedHost.STATUS_REVOKED:
            raise ValueError("A revoked host cannot be re-enrolled")
        bootstrap = f"ucm_boot_{secrets.token_urlsafe(24)}"
        host.bootstrap_hash = _hash_token(bootstrap)
        host.bootstrap_expires = utc_now() + timedelta(seconds=BOOTSTRAP_TTL_SECONDS)
        db.session.commit()
        return host, bootstrap

    @staticmethod
    def _resolve_bootstrap(bootstrap_token):
        if not bootstrap_token or not bootstrap_token.startswith('ucm_boot_'):
            return None
        host = SSHManagedHost.query.filter_by(
            bootstrap_hash=_hash_token(bootstrap_token)).first()
        if not host or not host.bootstrap_expires or host.bootstrap_expires <= utc_now():
            return None
        if host.status == SSHManagedHost.STATUS_REVOKED:
            return None
        return host

    @staticmethod
    def resolve_bootstrap(bootstrap_token):
        """Public lookup of a live bootstrap token (for /ssh/agent-setup)."""
        return SSHManagedHostService._resolve_bootstrap(bootstrap_token)

    @staticmethod
    def enroll(bootstrap_token, hostname, public_key, principals=None, ip=None):
        """One-time enrollment: validates the bootstrap token, fixes the host
        public key and principals, issues the host token and the first host
        certificate. Consumes the bootstrap token."""
        host = SSHManagedHostService._resolve_bootstrap(bootstrap_token)
        if not host:
            raise ValueError("Invalid or expired bootstrap token")

        hostname = (hostname or '').strip()
        if not hostname:
            raise ValueError("hostname is required")
        # The master may have fixed a hostname already; then it rules.
        if not host.hostname.startswith('pending-') and host.hostname != hostname:
            raise ValueError(
                f"This enrollment is bound to hostname '{host.hostname}'")
        existing = SSHManagedHost.query.filter_by(hostname=hostname).first()
        if existing and existing.id != host.id:
            raise ValueError(f"A managed host named '{hostname}' already exists")

        host.hostname = hostname
        # Security invariant: agent enrollment never dictates arbitrary principals.
        # Principals are fixed to [hostname] (or pre-configured host.get_principals()).
        principals = host.get_principals() or [hostname]
        public_key = (public_key or '').strip()
        if not public_key:
            raise ValueError("public_key is required")
        if host.public_key and SSHManagedHostService._key_material(host.public_key) \
                != SSHManagedHostService._key_material(public_key):
            # The host regenerated its ssh host key: retire every unexpired
            # certificate signed for the old key before replacing it. The
            # comparison is on the key material, not the .pub line: a key file
            # re-generated with a different comment is the same key, and treating
            # it as a rotation would revoke a working host's certificates.
            SSHManagedHostService._revoke_host_certs(
                host, reason='host key replaced at re-enrollment')
            host.public_key = public_key
        if not host.public_key:
            host.public_key = public_key
            host.principals = json.dumps(principals)

        token = f"{_HOST_TOKEN_PREFIX}{secrets.token_urlsafe(24)}"
        host.token_hash = _hash_token(token)
        host.token_prefix = token[:12]
        host.bootstrap_hash = None
        host.bootstrap_expires = None
        host.status = SSHManagedHost.STATUS_ACTIVE
        host.last_seen_at = utc_now()
        host.last_ip = ip

        cert = None
        if host.host_ca_id:
            try:
                cert = SSHManagedHostService._sign_host_cert(host, source='agent', username=hostname)
            except ValueError:
                # Policy refusals (principal rules, CA state) reject the enrollment
                # outright: nothing is persisted, the bootstrap token stays valid.
                db.session.rollback()
                raise
            except Exception as e:
                # Operational signing failure: the enrollment itself stands —
                # the agent retries the certificate through check-in → renew.
                logger.error("SSH managed host %r enrolled but its first certificate failed to sign: %s",
                             hostname, e)

        if cert:
            host.current_cert_id = cert.id
            host.last_renew_at = utc_now()
        db.session.commit()

        logger.info("SSH managed host %r enrolled (host CA %s)", hostname, host.host_ca_id)
        SSHManagedHostService._emit('ssh_host.enrolled', host,
                                    meta={'serial': cert.serial} if cert else None)
        if cert:
            SSHManagedHostService._emit_cert_event('ssh_certificate.issued', host, cert)
        return host, token, cert

    @staticmethod
    def _sign_host_cert(host, source='agent', username=None):
        if not host.host_ca_id:
            raise ValueError("No host CA configured for this managed host")
        return SSHCertificateService.sign_certificate(
            ca_id=host.host_ca_id,
            public_key_data=host.public_key,
            cert_type='host',
            principals=host.get_principals(),
            validity_seconds=host.host_cert_ttl or host.host_ca.host_cert_ttl,
            descr=f"Host certificate for {host.hostname} (managed)",
            source=source,
            username=username or 'ucm-ssh-agent',
        )

    @staticmethod
    def renew(host, ip=None):
        """Agent-initiated renewal with the host token. Guard rails enforced."""
        if host.status != SSHManagedHost.STATUS_ACTIVE:
            raise PermissionError(f"Host status is '{host.status}': renewal refused")
        if not host.host_ca_id:
            raise PermissionError("Host has no host CA configured")
        if not host.auto_renew:
            raise PermissionError("Auto-renewal is paused")
        host.last_seen_at = utc_now()
        host.last_ip = ip
        # Cadence is the agent's (check-in tells it when renewal is due); spam
        # is held by the per-route rate limit, not by a server-side threshold.
        cert = SSHManagedHostService._sign_host_cert(host)
        host.current_cert_id = cert.id
        host.last_renew_at = utc_now()
        db.session.commit()
        SSHManagedHostService._emit('ssh_host.renewed', host, meta={'serial': cert.serial})
        SSHManagedHostService._emit_cert_event('ssh_certificate.issued', host, cert)
        return cert

    @staticmethod
    def force_renew(host_id, username=None):
        """Admin action from the UI: signs a new certificate right now, even
        when auto_renew is off (the operator asked explicitly)."""
        host = db.session.get(SSHManagedHost, host_id)
        if not host:
            raise ValueError("Managed host not found")
        if host.status != SSHManagedHost.STATUS_ACTIVE:
            raise ValueError(f"Host status is '{host.status}': cannot renew")
        if not host.public_key:
            raise ValueError("Host has not enrolled yet: nothing to sign")
        cert = SSHManagedHostService._sign_host_cert(host, source='web', username=username)
        host.current_cert_id = cert.id
        host.last_renew_at = utc_now()
        db.session.commit()
        logger.info("SSH managed host %r force-renewed by %s", host.hostname, username)
        SSHManagedHostService._emit('ssh_host.renewed', host, meta={'serial': cert.serial, 'forced': True})
        SSHManagedHostService._emit_cert_event('ssh_certificate.issued', host, cert)
        return cert

    @staticmethod
    def rotate_token(host_id, username=None):
        host = db.session.get(SSHManagedHost, host_id)
        if not host:
            raise ValueError("Managed host not found")
        if host.status != SSHManagedHost.STATUS_ACTIVE:
            raise ValueError(f"Host status is '{host.status}': only enrolled (active) hosts have a token to rotate")
        token = f"{_HOST_TOKEN_PREFIX}{secrets.token_urlsafe(24)}"
        host.token_hash = _hash_token(token)
        host.token_prefix = token[:12]
        db.session.commit()
        logger.info("SSH managed host %r token rotated by %s", host.hostname, username)
        return host, token

    @staticmethod
    def set_auto_renew(host_id, enabled, username=None):
        host = db.session.get(SSHManagedHost, host_id)
        if not host:
            raise ValueError("Managed host not found")
        host.auto_renew = bool(enabled)
        db.session.commit()
        logger.info("SSH managed host %r auto_renew=%s by %s",
                    host.hostname, host.auto_renew, username)
        return host

    @staticmethod
    def _validate_principals_against_ca(host_ca, principals):
        allowed = host_ca.get_allowed_principals()
        if not allowed and not host_ca.allow_any_principal:
            raise ValueError(
                "Selected Host CA lists no allowed principals: add patterns or allow any principal"
            )
        if allowed:
            for p in principals:
                if not any(fnmatch.fnmatchcase(p, pat) for pat in allowed):
                    raise ValueError(
                        f"Host principal '{p}' is not allowed by Host CA '{host_ca.descr}'"
                    )

    @staticmethod
    def update_host(host_id, data, username=None):
        """Update managed host settings (auto_renew, CA assignments, per-host cert overrides)."""
        host = db.session.get(SSHManagedHost, host_id)
        if not host:
            raise ValueError("Managed host not found")

        ca_keys = {'host_ca_id', 'user_ca_id', 'host_cert_ttl', 'renew_threshold_percent'}
        touching_ca = any(k in data for k in ca_keys)
        if touching_ca and host.status == SSHManagedHost.STATUS_REVOKED:
            raise ValueError("Cannot change CA configuration of a revoked host")

        new_host_ca_id = data.get('host_ca_id', host.host_ca_id) if 'host_ca_id' in data else host.host_ca_id
        new_user_ca_id = data.get('user_ca_id', host.user_ca_id) if 'user_ca_id' in data else host.user_ca_id
        new_host_ca_id = int(new_host_ca_id) if new_host_ca_id else None
        new_user_ca_id = int(new_user_ca_id) if new_user_ca_id else None

        if touching_ca:
            host_ca, _user_ca = _validate_ca_pair(new_host_ca_id, new_user_ca_id)
            if host_ca:
                principals = host.get_principals() or [host.hostname]
                SSHManagedHostService._validate_principals_against_ca(host_ca, principals)

        new_ttl = data.get('host_cert_ttl', host.host_cert_ttl) if 'host_cert_ttl' in data else host.host_cert_ttl
        if new_ttl is not None:
            try:
                new_ttl = int(new_ttl)
            except (TypeError, ValueError):
                raise ValueError("host_cert_ttl must be an integer (seconds)")
            if new_ttl < 3600 or new_ttl > 315360000:
                raise ValueError("host_cert_ttl must be between 3600s (1h) and 315360000s (10y)")

        new_thresh = (
            data.get('renew_threshold_percent', host.renew_threshold_percent)
            if 'renew_threshold_percent' in data else host.renew_threshold_percent
        )
        if new_thresh is not None:
            try:
                new_thresh = int(new_thresh)
            except (TypeError, ValueError):
                raise ValueError("renew_threshold_percent must be an integer (1-90)")
            if new_thresh < 1 or new_thresh > 90:
                raise ValueError("renew_threshold_percent must be between 1 and 90")

        if not new_host_ca_id:
            new_ttl = None
            new_thresh = None

        config_changed = (
            new_host_ca_id != host.host_ca_id
            or new_user_ca_id != host.user_ca_id
            or new_ttl != host.host_cert_ttl
            or new_thresh != host.renew_threshold_percent
        )

        host.host_ca_id = new_host_ca_id
        host.user_ca_id = new_user_ca_id
        host.host_cert_ttl = new_ttl
        host.renew_threshold_percent = new_thresh

        if 'auto_renew' in data:
            if not isinstance(data['auto_renew'], bool):
                raise ValueError("auto_renew must be a boolean")
            host.auto_renew = data['auto_renew']

        if config_changed and host.status == SSHManagedHost.STATUS_ACTIVE:
            host.config_synced = False

        db.session.commit()
        logger.info("SSH managed host %r updated by %s (config_changed=%s)",
                    host.hostname, username, config_changed)
        return host

    @staticmethod
    def _key_material(public_key):
        """An OpenSSH public key line is "<type> <base64> [comment]": the comment
        comes from whoever generated the key file, while the certificate rows keep
        only the key itself. Comparing the raw lines made "revoke this host's
        certificates" match nothing on a real agent, which sends the .pub file
        contents (comment included) — the host went revoked, its certificate stayed
        valid and never reached the KRL."""
        return ' '.join((public_key or '').split()[:2])

    @staticmethod
    def _revoke_host_certs(host, reason, username=None):
        """Revoke every unexpired host certificate signed for this host's key
        (not just the current one — earlier renewals of the same key would
        otherwise stay usable until they expire). Returns the revoked certs."""
        wanted = SSHManagedHostService._key_material(host.public_key)
        if not wanted or not host.host_ca_id:
            return []
        # Keep the selection in the database: an unfiltered "all host certs of
        # this CA" would drag ~1 KB per row into Python (10k certificates is tens
        # of megabytes on every revoke and every re-enroll). Certificate rows
        # store the key alone, so the exact form matches; the "<wanted> %" form
        # covers a row that kept the .pub comment. base64 and the key type
        # contain no % or _, but escape anyway.
        escaped = wanted.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        certs = SSHCertificate.query.filter(
            SSHCertificate.ssh_ca_id == host.host_ca_id,
            SSHCertificate.cert_type == 'host',
            SSHCertificate.revoked.is_(False),
            db.or_(SSHCertificate.public_key == wanted,
                   SSHCertificate.public_key.like(f'{escaped} %', escape='\\')),
        ).all()
        now = utc_now()
        revoked = []
        for cert in certs:
            if cert.valid_to <= now:
                continue
            revoked.append(SSHCertificateService.revoke_certificate(
                cert.id, reason=reason, username=username))
        return revoked

    @staticmethod
    def revoke_cert(host_id, reason='unspecified', username=None, revoke_certificate=False):
        """Host blocked, both tokens invalidated, renewals off.
        If revoke_certificate is True, also revokes active host certificates into KRL."""
        host = db.session.get(SSHManagedHost, host_id)
        if not host:
            raise ValueError("Managed host not found")
        revoked_certs = []
        if revoke_certificate:
            revoked_certs = SSHManagedHostService._revoke_host_certs(
                host, reason=reason, username=username)
        host.status = SSHManagedHost.STATUS_REVOKED
        host.auto_renew = False
        host.token_hash = None
        host.token_prefix = None
        host.bootstrap_hash = None
        host.bootstrap_expires = None
        db.session.commit()
        logger.info("SSH managed host %r revoked by %s (revoke_cert=%s): %s",
                    host.hostname, username, revoke_certificate, reason)
        SSHManagedHostService._emit('ssh_host.revoked', host,
                                    meta={'reason': reason, 'revoke_certificate': revoke_certificate})
        for cert in revoked_certs:
            SSHManagedHostService._emit_cert_event('ssh_certificate.revoked', host, cert)
            SSHManagedHostService._emit_krl_updated(cert.ca, cert.serial)
        return host

    @staticmethod
    def delete_host(host_id, username=None):
        host = db.session.get(SSHManagedHost, host_id)
        if not host:
            raise ValueError("Managed host not found")
        cert = host.current_cert
        if host.auto_renew and cert and cert.status == 'valid':
            raise ValueError(
                "Cannot delete a managed host while auto-renew is on and its "
                "certificate is valid: turn auto-renew off first, or revoke the certificate.")
        db.session.delete(host)
        db.session.commit()
        logger.info("SSH managed host %r deleted by %s", host.hostname, username)
        return host.hostname

    @staticmethod
    def check_in(host, krl_etag=None, krl_written=None, config_applied=None, ip=None):
        """Heartbeat from the agent: records contact, reports whether a renewal,
        fresh KRL, or updated CA configuration is due."""
        now = utc_now()
        host.last_seen_at = now
        host.last_ip = ip
        if config_applied is True:
            host.config_synced = True
        changed = False
        if host.user_ca_id:
            user_ca = host.user_ca
            if krl_written is not False:
                host.last_krl_sync_at = now
            if str(krl_etag or '').strip('"') != str(user_ca.krl_version or 0):
                changed = True
        cert = host.current_cert
        ca_mismatch = bool(host.host_ca_id and cert and cert.ssh_ca_id != host.host_ca_id)
        renew_due = bool(
            host.host_ca_id and host.auto_renew and host.status == SSHManagedHost.STATUS_ACTIVE
            and (not cert or ca_mismatch or host.cert_status() in ('expiring', 'expired'))
        )
        config_pending = not bool(host.config_synced)
        db.session.commit()
        resp = {
            'krl_changed': changed,
            'krl_version': host.user_ca.krl_version if host.user_ca_id else None,
            'renew_required': renew_due,
            'valid_to': utc_isoformat(cert.valid_to) if cert else None,
            'config_changed': config_pending,
        }
        if config_pending:
            resp['config_update'] = {
                'has_host_ca': bool(host.host_ca_id),
                'has_user_ca': bool(host.user_ca_id),
                'host_ca_public_key': host.host_ca.public_key if host.host_ca_id else None,
                'user_ca': {
                    'refid': host.user_ca.refid,
                    'public_key': host.user_ca.public_key,
                    'krl_path': f'/ssh/krl/{host.user_ca.refid}',
                } if host.user_ca_id else None,
            }
        return resp

    # ── events ────────────────────────────────────────────────────────────

    @staticmethod
    def _emit(event, host, meta=None):
        try:
            from services.webhook_service import WebhookService
            WebhookService.send_event(event, {
                'host_id': host.id,
                'hostname': host.hostname,
                'host_ca_id': host.host_ca_id,
                'user_ca_id': host.user_ca_id,
                **(meta or {}),
            }, ca_refid=(host.user_ca.refid if host.user_ca_id else None))
        except Exception as e:
            logger.error(f"SSH host event '{event}' failed: {e}")

    @staticmethod
    def _emit_cert_event(event, host, cert):
        try:
            from services.webhook_service import WebhookService
            WebhookService.send_event(event, {
                'cert_id': cert.id,
                'serial': cert.serial,
                'key_id': cert.key_id,
                'cert_type': cert.cert_type,
                'ca_id': cert.ssh_ca_id,
                'hostname': host.hostname,
            }, ca_refid=cert.ca.refid if cert.ca else None)
        except Exception as e:
            logger.error(f"SSH cert event '{event}' failed: {e}")

    @staticmethod
    def _emit_krl_updated(ca, serial):
        if not ca:
            return
        try:
            from services.webhook_service import WebhookService
            WebhookService.send_event('ssh_ca.krl_updated', {
                'ca_id': ca.id,
                'ca_name': ca.descr,
                'krl_version': ca.krl_version,
                'krl_path': f'/ssh/krl/{ca.refid}',
                'serial': serial,
            }, ca_refid=ca.refid)
        except Exception as e:
            logger.error(f"SSH krl event failed for CA {ca.id}: {e}")
