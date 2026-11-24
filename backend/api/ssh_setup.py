"""
Public SSH CA Setup Script Endpoint

Serves setup scripts via a public URL using CA refid (UUID).
No authentication required — designed for `curl | sudo bash` usage.

Security:
- Uses refid (UUID) not sequential id — unguessable
- Read-only — only serves public key + shell script
- No sensitive data exposed (private key is never included)
- Rate limiting via CA-level access (same as CDP/OCSP)
"""

import logging
from flask import Blueprint, request, Response

from api.v2.ssh.validation import validate_setup_hostname
from models.ssh import SSHCertificateAuthority
from utils.sanitize import content_disposition
from services.ssh_ca_service import SSHCAService
from utils.public_endpoints import get_admin_base_url, parse_public_url

logger = logging.getLogger(__name__)

bp = Blueprint('ssh_setup_public', __name__)


@bp.route('/ssh/setup/<refid>', methods=['GET'])
def get_public_setup_script(refid):
    """Serve SSH CA setup script publicly (like CDP serves CRLs).

    Usage (Linux/macOS):
        curl -sSL https://ucm.example.com:8443/ssh/setup/<refid> | sudo bash
        curl -sSL https://ucm.example.com:8443/ssh/setup/<refid>?type=host | sudo bash

    Usage (Windows, elevated PowerShell):
        iwr -useb https://ucm.example.com:8443/ssh/setup/<refid>?platform=windows | iex
    """
    try:
        ca = SSHCertificateAuthority.query.filter_by(refid=refid).first()
        if not ca:
            return Response('#!/bin/sh\necho "Error: SSH CA not found"\nexit 1\n',
                            status=404, mimetype='text/x-shellscript')

        pub_key = SSHCAService.get_public_key(ca.id)

        ca_type = request.args.get('type', '').strip().lower()
        if ca_type and ca_type not in ('user', 'host'):
            return Response('#!/bin/sh\necho "Error: Invalid type. Use ?type=user or ?type=host"\nexit 1\n',
                            status=400, mimetype='text/x-shellscript')
        if not ca_type:
            ca_type = ca.ca_type

        hostname = request.args.get('hostname', '').strip()
        hostname_err = validate_setup_hostname(hostname)
        if hostname_err:
            return Response(
                '#!/bin/sh\necho "Error: Invalid hostname format"\nexit 1\n',
                status=400,
                mimetype='text/x-shellscript',
            )

        platform = request.args.get('platform', 'unix').strip().lower()
        if platform not in ('unix', 'linux', 'macos', 'windows'):
            return Response('#!/bin/sh\necho "Error: Invalid platform. Use ?platform=unix or ?platform=windows"\nexit 1\n',
                            status=400, mimetype='text/x-shellscript')

        # Reuse the script generators from the authenticated endpoint
        from api.v2.ssh.setup_scripts import _generate_setup_script
        script = _generate_setup_script(ca, pub_key, ca_type, hostname, platform)

        safe_name = ca.descr.replace(' ', '_').replace('"', '').replace("'", '')

        if platform == 'windows':
            mimetype = 'text/x-powershell'
            ext = '.ps1'
        else:
            mimetype = 'text/x-shellscript'
            ext = '.sh'

        return Response(
            script,
            mimetype=mimetype,
            headers={
                'Content-Disposition': content_disposition(safe_name, ext, fallback=ca.refid, prefix='ssh_ca_setup_'),
                'Cache-Control': 'no-cache, no-store, must-revalidate',
            }
        )
    except ValueError as e:
        logger.warning(f"SSH setup script error for refid {refid}: {e}")
        return Response(f'#!/bin/sh\necho "Error: {e}"\nexit 1\n',
                        status=404, mimetype='text/x-shellscript')
    except Exception as e:
        logger.error(f"Failed to generate public SSH setup script: {e}")
        return Response('#!/bin/sh\necho "Error: Failed to generate setup script"\nexit 1\n',
                        status=500, mimetype='text/x-shellscript')


@bp.route('/ssh/krl/<refid>', methods=['GET'])
def get_public_krl(refid):
    """Serve the SSH KRL of a CA publicly (like CDP serves CRLs).

    Public data (revoked serials). Cached in memory per krl_version so
    ssh-keygen runs only on revocation, not per download; ETag / If-None-Match
    makes polling free (304 without regenerating anything).
    """
    ca = SSHCertificateAuthority.query.filter_by(refid=refid).first()
    if not ca:
        return Response('SSH CA not found\n', status=404, mimetype='text/plain')
    from services.ssh_krl_service import get_cached_krl
    try:
        version, krl_bytes = get_cached_krl(ca)
    except (RuntimeError, ValueError) as e:
        logger.error(f"Public KRL generation failed for {refid}: {e}")
        return Response('KRL generation failed', status=500)
    etag = f'"{version}"'
    if request.headers.get('If-None-Match', '').strip('"') == etag.strip('"'):
        return Response(status=304, headers={'ETag': etag})
    return Response(
        krl_bytes,
        mimetype='application/octet-stream',
        headers={
            'ETag': etag,
            'Cache-Control': 'public, max-age=60',
            'X-KRL-Version': str(version),
        },
    )


@bp.route('/ssh/krl/<refid>/setup', methods=['GET'])
def get_public_krl_sync_setup(refid):
    """Serve a tokenless 15-minute KRL auto-sync setup script for a User CA."""
    ca = SSHCertificateAuthority.query.filter_by(refid=refid).first()
    if not ca:
        return Response('#!/bin/sh\necho "Error: SSH CA not found"\nexit 1\n',
                        status=404, mimetype='text/x-shellscript')
    if ca.ca_type != 'user':
        return Response('#!/bin/sh\necho "Error: KRL auto-sync is only for User CAs"\nexit 1\n',
                        status=400, mimetype='text/x-shellscript')

    platform = request.args.get('platform', 'unix').strip().lower()
    if platform not in ('unix', 'linux', 'macos', 'windows'):
        return Response('#!/bin/sh\necho "Error: Invalid platform"\nexit 1\n',
                        status=400, mimetype='text/x-shellscript')

    admin_base = get_admin_base_url()
    if admin_base:
        base_url = admin_base.rstrip('/')
    else:
        parsed = parse_public_url(request.url_root)
        base_url = (parsed.normalized if parsed and parsed.normalized else request.url_root).rstrip('/')

    pub_key = SSHCAService.get_public_key(ca.id)
    from services.ucm_krl_sync_scripts import build_krl_sync_setup_script
    script = build_krl_sync_setup_script(base_url, ca.refid, pub_key, platform)

    safe_name = ca.descr.replace(' ', '_').replace('"', '').replace("'", '')
    if platform == 'windows':
        mimetype = 'text/x-powershell'
        filename = f'ucm_krl_sync_{safe_name}.ps1'
    else:
        mimetype = 'text/x-shellscript'
        filename = f'ucm_krl_sync_{safe_name}.sh'

    return Response(
        script,
        mimetype=mimetype,
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    )


@bp.route('/ssh/setup/<refid>/public-key', methods=['GET'])
def get_public_key(refid):
    """Serve SSH CA public key publicly (for manual setup)."""
    try:
        ca = SSHCertificateAuthority.query.filter_by(refid=refid).first()
        if not ca:
            return Response('SSH CA not found', status=404, mimetype='text/plain')

        pub_key = SSHCAService.get_public_key(ca.id)

        return Response(
            pub_key + '\n',
            mimetype='text/plain',
            headers={
                'Content-Disposition': content_disposition(ca.descr.replace(' ', '_'), '_ca.pub', fallback=ca.refid, disposition='inline'),
                'Cache-Control': 'no-cache, no-store, must-revalidate',
            }
        )
    except Exception as e:
        logger.error(f"Failed to serve public key for refid {refid}: {e}")
        return Response('Error retrieving public key', status=500, mimetype='text/plain')
