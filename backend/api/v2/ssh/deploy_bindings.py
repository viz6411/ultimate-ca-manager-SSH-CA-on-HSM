"""SSH CA deployment binding routes.

Attaching an SSH CA to a deploy target, listing its bindings, editing them,
deploying on demand. Every route sits behind the admin-only ``deploy`` resource
as the certificate and CRL bindings do: a binding makes UCM write files on a
server with that server's own credentials.

Field-level failures answer RFC 7807 with ``details.fields`` — each entry names
the field, the target account and the right it lacks — because a binding dialog
must show a probe failure under the path or the command it concerns.
"""

from flask import request, g

from auth.unified import require_auth
from fips_mode import FipsRestricted
from sqlalchemy.exc import IntegrityError

from models import db, DeployDelivery, DeployTarget, SSHCADeployBinding
from models.ssh import SSHCertificateAuthority
from services.audit_service import AuditService
from services.deploy import ssh_ca as ssh_ca_deploy
from services.deploy.ssh import DeploySSHError, HostKeyMismatch
from services.deploy.service import DeployService
from utils.db_transaction import safe_commit
from utils.response import created_response, error_response, success_response

from .helpers import bp, logger

_PATH_FIELDS = ('ca_pub_path', 'krl_path', 'host_cert_path')


def _actor():
    return g.current_user.username if hasattr(g, 'current_user') else 'system'


def _field_failure(field, message, i18n_key, **values):
    return {field: {'message': message, 'i18n_key': i18n_key, 'values': values}}


def _refusal(e):
    """422 with the per-field shape the deployment dialog maps back onto inputs."""
    return error_response(str(e), 422,
                          details={'fields': e.fields} if getattr(e, 'fields', None) else None)


def _transport_error(e):
    """A target that cannot be reached or whose host key changed is not a
    permissions problem, and is not reported as one."""
    if isinstance(e, HostKeyMismatch):
        return error_response(str(e), 409)
    if isinstance(e, DeploySSHError):
        return error_response(str(e), 502)
    logger.error(f'SSH CA deploy binding failed unexpectedly: {e}', exc_info=True)
    return error_response('SSH CA deployment failed', 500)


def _get_ca(ca_id):
    ca = db.session.get(SSHCertificateAuthority, ca_id)
    return (ca, None) if ca else (None, error_response('SSH CA not found', 404))


def _get_binding(ca_id, binding_id):
    binding = SSHCADeployBinding.query.filter_by(id=binding_id, ssh_ca_id=ca_id).first()
    return (binding, None) if binding else (None, error_response('SSH CA deploy binding not found',
                                                                 404))


def _with_last_delivery(binding):
    data = binding.to_dict()
    last = (DeployDelivery.query
            .filter_by(binding_id=binding.id,
                       binding_type=DeployDelivery.BINDING_SSH_CA)
            .order_by(DeployDelivery.id.desc()).first())
    data['last_delivery'] = last.to_dict() if last else None
    return data


def _probe_or_refusal(target, fields):
    """Run the privilege probe over the final field values.

    Returns ``(response, host_public_key)``: a response to answer when the probe
    refused, and the host key UCM read (or accepted from the paste) when it did
    not. Runs on save only — a delivery in the queue does not probe again.
    """
    try:
        host_public_key, learned, failures = ssh_ca_deploy.probe_binding(target, fields)
    except FipsRestricted:
        db.session.rollback()
        raise  # the app handler answers 400 with the FIPS problem type
    except (HostKeyMismatch, DeploySSHError) as e:
        db.session.rollback()
        return _transport_error(e), None
    except Exception as e:
        db.session.rollback()
        return _transport_error(e), None
    if failures:
        db.session.rollback()
        message = '; '.join(item['message'] for item in failures.values())
        return error_response(message, 422, details={'fields': failures}), None
    # The host key this probe connected with is the one UCM will keep writing to
    target.host_key = target.host_key or learned
    return None, host_public_key


def _collision_response(target, binding, fields):
    clashes = ssh_ca_deploy.path_collisions(target.id, binding.ssh_ca_id if binding else None,
                                            binding.id if binding else None,
                                            [fields.get(field) for field in _PATH_FIELDS])
    if not clashes:
        return None
    details = {}
    for field in _PATH_FIELDS:
        path = fields.get(field)
        other = clashes.get(path)
        if other is None:
            continue
        details[field] = {
            'message': (f"{path} is already written to {target.name} by SSH CA "
                        f"'{other.ssh_ca.descr if other.ssh_ca else other.ssh_ca_id}': one file "
                        "cannot hold two CAs, the last push would win"),
            'i18n_key': 'sshDeploy.errors.pathTaken',
            'values': {'path': path, 'ca_name': other.ssh_ca.descr if other.ssh_ca else '',
                       'target_name': target.name},
        }
    first = next(iter(details.values()))
    db.session.rollback()
    return error_response(first['message'], 409, details={'fields': details})


# ============================================================ the bindings

@bp.route('/api/v2/ssh/cas/<int:ca_id>/deploy-bindings', methods=['GET'])
@require_auth(['read:deploy', 'read:ssh_cas'])
def list_ssh_ca_bindings(ca_id):
    """The targets this CA is deployed to, each with its last delivery."""
    ca, missing = _get_ca(ca_id)
    if missing:
        return missing
    bindings = (SSHCADeployBinding.query.filter_by(ssh_ca_id=ca.id)
                .order_by(SSHCADeployBinding.id.asc()).all())
    return success_response(data={
        'ca': {'id': ca.id, 'refid': ca.refid, 'descr': ca.descr, 'ca_type': ca.ca_type,
               'deploy_defaults': ssh_ca_deploy.artifact_defaults(ca)},
        'bindings': [_with_last_delivery(binding) for binding in bindings],
    })


@bp.route('/api/v2/ssh/cas/<int:ca_id>/deploy-bindings', methods=['POST'])
@require_auth(['write:deploy', 'write:ssh_cas'])
def create_ssh_ca_binding(ca_id):
    """Attach this CA to a deploy target.

    Save-first: UCM reads the host key off the target in the same request. If it
    cannot (exec refused by sshd), it says so under the host key field and the
    dialog opens the paste box — there is no separate preflight call.
    """
    ca, missing = _get_ca(ca_id)
    if missing:
        return missing
    data = request.get_json() or {}
    target = db.session.get(DeployTarget, data.get('target_id') or 0)
    if not target:
        return error_response('Deploy target not found', 404)
    if SSHCADeployBinding.query.filter_by(target_id=target.id, ssh_ca_id=ca.id).first():
        return error_response('This SSH CA is already bound to this target', 409)

    try:
        fields = ssh_ca_deploy.validate_binding(ca, target, data)
    except FipsRestricted:
        raise  # the app handler answers 400 with the FIPS problem type
    except ssh_ca_deploy.BindingRefusal as e:
        return _refusal(e)

    principals = fields.pop('principals', None)
    binding = SSHCADeployBinding(target_id=target.id, ssh_ca_id=ca.id,
                                 created_by=_actor(), **fields)
    binding.set_principals(principals)
    db.session.add(binding)
    try:
        db.session.flush()
    except IntegrityError:
        db.session.rollback()
        return error_response('This SSH CA is already bound to this target', 409)
    collided = _collision_response(target, binding, fields)
    if collided:
        return collided

    refused, host_public_key = _probe_or_refusal(target, fields)
    if refused:
        return refused
    binding.host_public_key = host_public_key

    delivery = DeployService.enqueue_initial_ssh_ca_push(binding, actor=_actor())
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return error_response('This SSH CA is already bound to this target', 409)
    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to create SSH CA deploy binding: {e}', exc_info=True)
        return error_response('Failed to create SSH CA deploy binding', 500)

    queued = delivery is not None
    AuditService.log_action(
        action='ssh_ca_deploy_binding_create', resource_type='ssh_ca',
        resource_id=str(ca.id), resource_name=ca.descr,
        details=(f"Bound SSH CA {ca.descr} to deploy target {target.name}; "
                 + ('initial artefact deployment queued' if queued else
                    'initial deployment not queued (binding or target disabled)')),
        success=True)
    return created_response(
        data=_with_last_delivery(binding),
        message=('SSH CA deployment binding created: initial deployment queued' if queued
                 else 'SSH CA deployment binding created, no deployment queued '
                      '(binding or target disabled)'))


@bp.route('/api/v2/ssh/cas/<int:ca_id>/deploy-bindings/<int:binding_id>', methods=['PATCH'])
@require_auth(['write:deploy', 'write:ssh_cas'])
def update_ssh_ca_binding(ca_id, binding_id):
    """Edit a binding, then make the change reach the host without waiting for
    the next event or an exhausted retry schedule."""
    ca, missing = _get_ca(ca_id)
    if missing:
        return missing
    binding, missing = _get_binding(ca_id, binding_id)
    if missing:
        return missing
    target = binding.target
    if not target:
        return error_response('Deploy target not found', 404)

    data = request.get_json() or {}
    try:
        fields = ssh_ca_deploy.validate_binding(ca, target, data, current=binding)
    except FipsRestricted:
        raise
    except ssh_ca_deploy.BindingRefusal as e:
        return _refusal(e)

    def stored(key):
        """The binding's current value of a field, in the form the request
        carries it: principals are stored as JSON and travel as a list."""
        return binding.get_principals() if key == 'principals' else getattr(binding, key)

    changed = [key for key, value in fields.items() if stored(key) != value]
    for key, value in fields.items():
        if key == 'principals':
            binding.set_principals(value)
        else:
            setattr(binding, key, value)
    collided = _collision_response(target, binding, {
        field: getattr(binding, field) for field in _PATH_FIELDS})
    if collided:
        return collided

    refused, host_public_key = _probe_or_refusal(
        target, {field: getattr(binding, field) for field in _PATH_FIELDS}
        | {'reload_command': binding.reload_command,
           'host_public_key': binding.host_public_key})
    if refused:
        return refused
    if host_public_key:
        binding.host_public_key = host_public_key

    delivery = DeployService.deploy_binding_update_now(
        binding, DeployDelivery.BINDING_SSH_CA, actor=_actor())
    ok, err = safe_commit(logger, 'Failed to update SSH CA deploy binding')
    if not ok:
        return err

    AuditService.log_action(
        action='ssh_ca_deploy_binding_update', resource_type='ssh_ca',
        resource_id=str(ca.id), resource_name=ca.descr,
        details=(f"Updated SSH CA deploy binding {binding.id} on {target.name}; changed fields: "
                 f"{', '.join(changed) if changed else 'none'}"),
        success=True)
    if not delivery:
        message = 'SSH CA deployment binding updated, no deployment queued'
    elif delivery.status == DeployDelivery.STATUS_DELIVERED:
        message = 'SSH CA deployment binding updated and deployed successfully'
    elif delivery.status == DeployDelivery.STATUS_PENDING:
        message = 'SSH CA deployment binding updated; immediate deployment failed, retry queued'
    else:
        message = 'SSH CA deployment binding updated; deployment failed'
    return success_response(data=_with_last_delivery(binding), message=message)


@bp.route('/api/v2/ssh/cas/<int:ca_id>/deploy-bindings/<int:binding_id>', methods=['DELETE'])
@require_auth(['delete:deploy', 'write:ssh_cas'])
def delete_ssh_ca_binding(ca_id, binding_id):
    """Stop deploying this CA to this target.

    What is already on the host stays there: removing a binding is not an
    undeploy, and UCM deleting a host's CA key behind its back is the kind of
    surprise this feature does not do. The audit entry says which files were
    left, so an operator can remove them deliberately.
    """
    ca, missing = _get_ca(ca_id)
    if missing:
        return missing
    binding, missing = _get_binding(ca_id, binding_id)
    if missing:
        return missing
    target_name = binding.target.name if binding.target else '?'
    left = [path for path in (binding.ca_pub_path, binding.krl_path, binding.host_cert_path)
            if path]
    try:
        from services.delivery_retention import delete_binding_deliveries
        delete_binding_deliveries(binding.id, DeployDelivery.BINDING_SSH_CA)
        db.session.delete(binding)
        ok, err = safe_commit(logger, 'Failed to delete SSH CA deploy binding')
        if not ok:
            return err
        AuditService.log_action(
            action='ssh_ca_deploy_binding_delete', resource_type='ssh_ca',
            resource_id=str(ca.id), resource_name=ca.descr,
            details=(f"Removed SSH CA deploy binding {binding.id} from {target_name}; "
                     f"artefacts left on the host (no undeploy): {', '.join(left) or 'none'}"),
            success=True)
        return success_response(
            message=('SSH CA deployment binding deleted. The files it wrote on '
                     f'{target_name} were not removed: {", ".join(left) or "none"}'))
    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to delete SSH CA deploy binding {binding_id}: {e}')
        return error_response('Failed to delete SSH CA deploy binding', 500)


@bp.route('/api/v2/ssh/cas/<int:ca_id>/deploy-bindings/<int:binding_id>/deploy',
          methods=['POST'])
@require_auth(['write:deploy', 'write:ssh_cas'])
def deploy_ssh_ca_now(ca_id, binding_id):
    """Deploy now: the CA key, the KRL and — for a host CA — the host certificate,
    re-signed when the one on file is expired or revoked."""
    ca, missing = _get_ca(ca_id)
    if missing:
        return missing
    binding, missing = _get_binding(ca_id, binding_id)
    if missing:
        return missing
    delivery = DeployDelivery(
        binding_id=binding.id,
        binding_type=DeployDelivery.BINDING_SSH_CA,
        event_type='manual',
        status=DeployDelivery.STATUS_PENDING,
        attempts=1,
        max_attempts=1,  # manual runs do not retry in the background
        triggered_by=_actor(),
    )
    db.session.add(delivery)
    delivered = DeployService.execute_delivery(delivery)
    ok, err = safe_commit(logger, 'Failed to record SSH CA deploy delivery')
    if not ok:
        return err
    if delivered:
        return success_response(data=delivery.to_dict(),
                                message='SSH CA artefacts deployed successfully')
    return error_response(delivery.last_error or 'SSH CA deployment failed', 502)
