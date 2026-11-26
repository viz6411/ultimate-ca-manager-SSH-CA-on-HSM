"""
SSH Managed Hosts routes — admin CRUD + token-authenticated agent endpoints.

Admin side (/api/v2/ssh/hosts, scopes read/write/delete:ssh_cas): registry
management, bootstrap tokens, auto-renew switch, rotation, revoke, delete.

Agent side (no UCM auth; host token or bootstrap token): enroll, renew,
check-in — pull-only per issue #451, UCM never reaches out to servers. A host
token only reaches its own host: it can never sign certificates for another
host or a user CA.
"""

from flask import g, request

from auth.unified import require_auth
from models import db
from models.ssh import SSHManagedHost
from services.audit_service import AuditService
from services.ssh_managed_host_service import (
    SSHManagedHostService, verify_host_token)
from utils.datetime_utils import utc_isoformat
from utils.pagination import parse_request_pagination
from utils.public_endpoints import get_admin_base_url, parse_public_url
from utils.response import created_response, error_response, no_content_response, success_response

from .helpers import bp, logger
from .validation import validate_setup_hostname

try:
    from app import limiter
except ImportError:
    limiter = None


def _limit(spec):
    def decorator(fn):
        if limiter:
            return limiter.limit(spec)(fn)
        return fn
    return decorator


def _actor():
    return g.current_user.username if hasattr(g, 'current_user') else 'system'


def _get_base_url():
    admin_base = get_admin_base_url()
    if admin_base:
        return admin_base.rstrip('/')
    parsed = parse_public_url(request.url_root)
    if parsed and parsed.normalized:
        return parsed.normalized.rstrip('/')
    return request.url_root.rstrip('/')


def _agent_host():
    """Resolve the calling agent from its X-Host-Token header."""
    raw_token = request.headers.get('X-Host-Token', '')
    host = verify_host_token(raw_token)
    if not host:
        AuditService.log_action(
            action='ssh_host_auth_failed',
            resource_type='ssh_managed_host',
            resource_id='unknown',
            resource_name='agent',
            details=f'invalid or expired host token from ip={request.remote_addr}',
            success=False,
            username='agent',
        )
        return None, error_response('Invalid host token', 401)
    return host, None


def _audit(action, host, details='', success=True):
    AuditService.log_action(
        action=action,
        resource_type='ssh_managed_host',
        resource_id=str(host.id),
        resource_name=host.hostname,
        details=details,
        success=success,
        username=_actor(),
    )


# ── admin ──────────────────────────────────────────────────────────────────

@bp.route('/api/v2/ssh/hosts', methods=['GET'])
@require_auth(['read:ssh_cas'])
def list_hosts():
    page, per_page = parse_request_pagination(default_per_page=25)
    query = SSHManagedHost.query
    search = request.args.get('search', '').strip()
    if search:
        safe = search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        query = query.filter(SSHManagedHost.hostname.ilike(f'%{safe}%', escape='\\'))
    status = request.args.get('status')
    if status in SSHManagedHost.VALID_STATUSES:
        query = query.filter(SSHManagedHost.status == status)
    query = query.order_by(SSHManagedHost.hostname.asc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return success_response(
        data=[h.to_dict() for h in pagination.items],
        meta={'total': pagination.total, 'page': page, 'per_page': per_page,
              'total_pages': (pagination.total + per_page - 1) // per_page},
    )


@bp.route('/api/v2/ssh/hosts/<int:host_id>', methods=['GET'])
@require_auth(['read:ssh_cas'])
def get_host(host_id):
    host = db.get_or_404(SSHManagedHost, host_id)
    return success_response(data=host.to_dict())


@bp.route('/api/v2/ssh/hosts', methods=['POST'])
@require_auth(['write:ssh_cas'])
def create_host():
    data = request.get_json(silent=True) or {}
    hostname = (data.get('hostname') or '').strip()
    if hostname:
        err = validate_setup_hostname(hostname)
        if err:
            return error_response(err, 400)
    host_ca_id = data.get('host_ca_id') or None
    user_ca_id = data.get('user_ca_id') or None
    if not host_ca_id and not user_ca_id:
        return error_response('At least one CA (host CA or user CA) is required', 400)

    try:
        host, bootstrap = SSHManagedHostService.create_host(
            hostname=hostname, host_ca_id=host_ca_id, user_ca_id=user_ca_id,
            username=_actor())
    except ValueError as e:
        return error_response(str(e), 400)

    _audit('ssh_host_created', host, f'host_ca={host.host_ca_id} user_ca={host.user_ca_id}')
    base_url = _get_base_url()
    install_command = (f'curl -sSL "{base_url}/ssh/agent-setup?token={bootstrap}" | sudo bash')
    return created_response(data={
        'host': host.to_dict(),
        'bootstrap_token': bootstrap,
        'install_command': install_command,
    }, message='Host registered. Run the install command on the server before the token expires.')


@bp.route('/api/v2/ssh/hosts/<int:host_id>/bootstrap', methods=['POST'])
@require_auth(['write:ssh_cas'])
def reissue_bootstrap(host_id):
    try:
        host, bootstrap = SSHManagedHostService.issue_bootstrap(host_id)
    except ValueError as e:
        return error_response(str(e), 400 if 'not found' not in str(e) else 404)
    _audit('ssh_host_bootstrap_issued', host, 'new install token')
    base_url = _get_base_url()
    return success_response(data={
        'host': host.to_dict(),
        'bootstrap_token': bootstrap,
        'install_command': f'curl -sSL "{base_url}/ssh/agent-setup?token={bootstrap}" | sudo bash',
    }, message='New install token issued (the previous one is dead)')


@bp.route('/api/v2/ssh/hosts/<int:host_id>', methods=['PATCH'])
@require_auth(['write:ssh_cas'])
def update_host(host_id):
    data = request.get_json(silent=True) or {}
    allowed_fields = {'auto_renew', 'host_ca_id', 'user_ca_id', 'host_cert_ttl', 'renew_threshold_percent'}
    if not any(k in data for k in allowed_fields):
        return error_response('No valid host fields provided', 400)
    try:
        host = SSHManagedHostService.update_host(host_id, data, username=_actor())
    except ValueError as e:
        return error_response(str(e), 404 if 'not found' in str(e).lower() else 400)
    _audit('ssh_host_updated', host,
           f"host_ca={host.host_ca_id} user_ca={host.user_ca_id} auto_renew={host.auto_renew}")
    return success_response(data=host.to_dict(), message='Host updated')


@bp.route('/api/v2/ssh/hosts/<int:host_id>/rotate-token', methods=['POST'])
@require_auth(['write:ssh_cas'])
def rotate_token(host_id):
    try:
        host, token = SSHManagedHostService.rotate_token(host_id, username=_actor())
    except ValueError as e:
        return error_response(str(e), 404 if 'not found' in str(e) else 400)
    _audit('ssh_host_token_rotated', host, 'host token rotated')
    return success_response(data={'host': host.to_dict(), 'host_token': token},
                            message='Token rotated once; the old token is dead')


@bp.route('/api/v2/ssh/hosts/<int:host_id>/revoke-cert', methods=['POST'])
@require_auth(['write:ssh'])
def revoke_host_cert(host_id):
    data = request.get_json(silent=True) or {}
    reason = (data.get('reason') or 'unspecified')[:255]
    revoke_certificate = bool(data.get('revoke_certificate', False))
    try:
        host = SSHManagedHostService.revoke_cert(
            host_id, reason=reason, username=_actor(), revoke_certificate=revoke_certificate)
    except ValueError as e:
        return error_response(str(e), 404 if 'not found' in str(e) else 400)
    _audit('ssh_host_cert_revoked', host, f'reason={reason}, revoke_certificate={revoke_certificate}')
    return success_response(data=host.to_dict(), message='Host access revoked')


@bp.route('/api/v2/ssh/hosts/<int:host_id>/force-renew', methods=['POST'])
@require_auth(['write:ssh'])
def force_renew(host_id):
    try:
        cert = SSHManagedHostService.force_renew(host_id, username=_actor())
    except ValueError as e:
        return error_response(str(e), 404 if 'not found' in str(e) else 400)
    host = SSHManagedHost.query.filter_by(current_cert_id=cert.id).first()
    if host:
        _audit('ssh_host_force_renew', host, f'new serial {cert.serial}')
    return success_response(data=cert.to_dict(), message='Host certificate reissued')


@bp.route('/api/v2/ssh/hosts/<int:host_id>', methods=['DELETE'])
@require_auth(['delete:ssh_cas'])
def delete_host(host_id):
    try:
        name = SSHManagedHostService.delete_host(host_id, username=_actor())
    except ValueError as e:
        return error_response(str(e), 400)
    AuditService.log_action(
        action='ssh_host_deleted',
        resource_type='ssh_managed_host',
        resource_id=str(host_id),
        resource_name=name,
        details=name,
        success=True,
        username=_actor(),
    )
    return no_content_response()


# ── agent (token-authenticated, no UCM session) ────────────────────────────

@bp.route('/api/v2/ssh/hosts/enroll', methods=['POST'])
@_limit('10 per minute')
def agent_enroll():
    data = request.get_json(silent=True) or {}
    hostname = (data.get('hostname') or '').strip()
    err = validate_setup_hostname(hostname)
    if err:
        return error_response(err, 400)
    public_key = (data.get('public_key') or '').strip()
    if not public_key or len(public_key) > 8192:
        return error_response('public_key is required (OpenSSH format, max 8 KiB)', 400)

    try:
        host, token, cert = SSHManagedHostService.enroll(
            bootstrap_token=data.get('bootstrap_token'),
            hostname=hostname,
            public_key=public_key,
            ip=request.remote_addr,
        )
    except ValueError as e:
        logger.warning(f"SSH host enroll refused ({hostname}): {e}")
        AuditService.log_action(
            action='ssh_host_enroll_refused',
            resource_type='ssh_managed_host',
            resource_id='unknown',
            resource_name=hostname,
            details=f'reason={e} ip={request.remote_addr}',
            success=False,
            username='agent',
        )
        return error_response(str(e), 403)

    user_ca = host.user_ca
    data = {
        'host_token': token,
        'hostname': host.hostname,
        'principals': host.get_principals(),
        'host_ca_public_key': host.host_ca.public_key,
        'user_ca': {
            'refid': user_ca.refid,
            'public_key': user_ca.public_key,
            'krl_path': f'/ssh/krl/{user_ca.refid}',
        } if user_ca else None,
    }
    if cert:
        data['certificate'] = cert.certificate
        # utc_isoformat: valid_to is naive UTC, a bare isoformat() reads as local time in JS
        data['valid_to'] = utc_isoformat(cert.valid_to)
    else:
        # CA signing failed: enrollment itself stands, the agent will retry
        # the certificate through check-in → renew.
        return created_response(data=data, message='Host enrolled, but certificate signing failed; the agent will retry')
    return created_response(data=data, message='Host enrolled')


@bp.route('/api/v2/ssh/hosts/renew', methods=['POST'])
@_limit('10 per minute')
def agent_renew():
    host, err = _agent_host()
    if err:
        return err
    try:
        cert = SSHManagedHostService.renew(host, ip=request.remote_addr)
    except PermissionError as e:
        return error_response(str(e), 403)
    # A CA-side refusal (ValueError) falls to the generic ValueError answer the
    # suite pins (400 'Invalid parameter value'), not a 500: the agent retries on
    # the next tick either way. Making it 403 with the CA's text would read better
    # but is a contract change pinned by tests — follow-up, see the review doc.
    return success_response(data={
        'certificate': cert.certificate,
        'serial': cert.serial,
        'valid_to': utc_isoformat(cert.valid_to),
    }, message='Host certificate renewed')


@bp.route('/api/v2/ssh/hosts/check-in', methods=['POST'])
@_limit('60 per minute')
def agent_check_in():
    host, err = _agent_host()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    info = SSHManagedHostService.check_in(
        host,
        krl_etag=data.get('krl_etag'),
        krl_written=data.get('krl_written'),
        config_applied=data.get('config_applied'),
        ip=request.remote_addr,
    )
    return success_response(data=info)
