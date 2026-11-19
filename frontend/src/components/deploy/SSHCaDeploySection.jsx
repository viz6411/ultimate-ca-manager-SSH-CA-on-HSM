/**
 * SSHCaDeploySection — the deployment block of an SSH CA.
 *
 * Attaching the CA to a deploy target is what makes UCM act on its own: it writes
 * this CA's public key, its KRL and — for a host CA — the host certificate it
 * signs for that target, and it re-pushes the KRL on every revocation. sshd
 * applies a KRL without a reload, so the reload command belongs only to the
 * writes that change what sshd trusts.
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  ArrowCounterClockwise, CloudArrowUp, PencilSimple, Plus, Trash, UploadSimple, Warning,
} from '@phosphor-icons/react'
import { Badge, Button, CompactSection, Input, Textarea } from '../index'
import { Modal } from '../Modal'
import TagsInput from '../ui/TagsInput'
import { deployService } from '../../services'
import { useNotification } from '../../contexts'
import { usePermission } from '../../hooks'
import { extractData, formatDate } from '../../lib/utils'
import { retryCountdown } from '../../lib/deployRetry'
import { isValidDnsName } from '../../lib/sanValidate'

const STATUS_VARIANT = { delivered: 'success', pending: 'warning', failed: 'danger' }
// The command UCM's own installer detects on a systemd host (setup_scripts.py)
const DEFAULT_RELOAD_COMMAND = 'systemctl reload sshd'
const FIELD_ORDER = ['target_id', 'ca_pub_path', 'krl_path', 'host_cert_path',
  'host_public_key', 'validity', 'principals', 'key_id_template', 'reload_command']

// The CA states a TTL in seconds; the dialog speaks durations ('24h', '7d')
function ttlText(seconds) {
  const value = Number(seconds)
  if (!value) return ''
  for (const [unitSeconds, unit] of [[86400, 'd'], [3600, 'h'], [60, 'm']]) {
    if (value >= unitSeconds && value % unitSeconds === 0) return `${value / unitSeconds}${unit}`
  }
  return `${value}s`
}

// A principal is one exact host name: isValidDnsName also accepts '*.', which a host
// certificate never matches (OpenSSH compares principals with strcmp)
const isExactHost = (name) => !/[*?\s]/.test(name) && isValidDnsName(name)
const shortOf = (host) => String(host || '').split('.')[0]
const fieldId = (field) => `ssh-deploy-${field}`

/**
 * A refusal mapped back onto the fields it concerns. The server answers RFC 7807
 * with details.fields = { field: { message, i18n_key, values } }; a probe failure
 * about the host key concerns the paste box, so it is renamed onto that field.
 */
function refusalFields(error, t) {
  const fields = error?.data?.details?.fields
  if (!fields) return {}
  const out = {}
  for (const [name, entry] of Object.entries(fields)) {
    const key = entry?.i18n_key
    const translated = key ? t(key, entry.values || {}) : ''
    out[name === 'host_key' ? 'host_public_key' : name] =
      (translated && translated !== key) ? translated : (entry?.message || key || '')
  }
  return out
}

export function SSHCaDeploySection({ ca, onChanged }) {
  const { t } = useTranslation()
  const { hasPermission } = usePermission()
  const { showSuccess, showError, showConfirm } = useNotification()
  const canRead = hasPermission('read:deploy') && hasPermission('read:ssh_cas')
  const canEdit = hasPermission('write:deploy') && hasPermission('write:ssh_cas')
  const canRemove = hasPermission('delete:deploy') && hasPermission('write:ssh_cas')

  const [bindings, setBindings] = useState([])
  const [defaults, setDefaults] = useState({})
  const [targets, setTargets] = useState([])
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState(null)
  const [saving, setSaving] = useState(false)
  const [busy, setBusy] = useState(null)
  const [errors, setErrors] = useState({})
  const [form, setForm] = useState(null)
  const [now, setNow] = useState(() => Date.now())
  const sequence = useRef(0)   // only the newest load may fill the section

  const isHostCa = ca?.ca_type === 'host'
  const caName = ca?.descr || ca?.name || `#${ca?.id}`

  const load = useCallback(async (silent = false) => {
    if (!ca?.id || !canRead) return
    const seq = ++sequence.current
    if (!silent) setLoading(true)
    try {
      const [bindingRes, targetRes] = await Promise.all([
        deployService.getSSHBindings(ca.id),
        deployService.getTargets(),
      ])
      if (seq !== sequence.current) return
      const data = extractData(bindingRes) || {}
      setDefaults(data.ca?.deploy_defaults || {})
      setBindings(data.bindings || [])
      // An HTTP target renders a fixed body template: an SSH CA writes files, over SFTP
      setTargets((extractData(targetRes) || []).filter(
        target => target.enabled && target.kind !== 'http'))
    } catch (error) {
      if (!silent) showError(error.message || t('messages.errors.loadFailed.sshCas'))
    } finally {
      if (!silent) setLoading(false)
    }
  }, [ca?.id, canRead, showError, t])

  useEffect(() => { load() }, [load])

  const hasPending = bindings.some(binding =>
    binding.last_delivery?.status === 'pending' && binding.last_delivery?.next_attempt_at)
  useEffect(() => {
    if (!hasPending) return undefined
    setNow(Date.now())
    const countdown = setInterval(() => setNow(Date.now()), 1000)
    const refresh = setInterval(() => load(true), 5000)
    return () => { clearInterval(countdown); clearInterval(refresh) }
  }, [hasPending, load])

  const targetOf = (id) => targets.find(target => String(target.id) === String(id))
  const availableTargets = targets.filter(
    target => !bindings.some(binding => binding.target_id === target.id))

  // Principals come from the target's own names: the FQDN, and its first label too
  const principalsFor = (target, includeShort) => {
    if (!isHostCa || !target) return []
    const names = [target.host]
    const short = shortOf(target.host)
    if (includeShort && short !== target.host) names.push(short)
    return names
  }

  const openAttach = () => {
    setEditing(null)
    setErrors({})
    setForm({
      target_id: '',
      ca_pub_path: defaults.ca_pub_path || '',
      krl_path: defaults.krl_path || '',
      host_cert_path: defaults.host_cert_path || '',
      validity: '', principals: [], include_short: true, key_id_template: '',
      host_public_key: '', paste_host_key: false,
      reload_command: DEFAULT_RELOAD_COMMAND, enabled: true,
    })
    setOpen(true)
  }

  const openEdit = (binding) => {
    setEditing(binding)
    setErrors({})
    const short = shortOf(binding.target_host)
    setForm({
      target_id: String(binding.target_id),
      ca_pub_path: binding.ca_pub_path || '',
      krl_path: binding.krl_path || '',
      host_cert_path: binding.host_cert_path || '',
      validity: binding.validity ? ttlText(binding.validity) : '',
      principals: binding.principals || [],
      include_short: (binding.principals || []).includes(short),
      key_id_template: binding.key_id_template || '',
      host_public_key: binding.host_public_key || '',
      paste_host_key: Boolean(binding.host_public_key),
      reload_command: binding.reload_command || '', enabled: binding.enabled,
    })
  }

  const chooseTarget = (id) => {
    setForm(form => ({
      ...form, target_id: id, principals: principalsFor(targetOf(id), form.include_short),
    }))
  }

  const toggleShort = (checked) => {
    setForm(form => {
      const short = shortOf(targetOf(form.target_id)?.host)
      const rest = form.principals.filter(name => name !== short)
      return {
        ...form, include_short: checked,
        principals: checked ? [...rest, short] : rest,
      }
    })
  }

  const reject = (error) => {
    const mapped = refusalFields(error, t)
    if (Object.keys(mapped).length === 0) {
      // A 409 with no fields names the target: this target is already attached
      if (Number(error?.data?.status) === 409) {
        mapped.target_id = t('sshDeploy.errors.targetTaken')
      } else {
        showError(error.message || t('deploy.saveFailed'))
        return
      }
    }
    setErrors(mapped)
    // A host key UCM could not read is answered by pasting it, so the box opens
    if (mapped.host_public_key) setForm(form => ({ ...form, paste_host_key: true }))
    const first = FIELD_ORDER.find(field => mapped[field])
    if (first) document.getElementById(fieldId(first))?.focus()
  }

  const save = async (event) => {
    event.preventDefault()
    setSaving(true)
    setErrors({})
    const writesCert = isHostCa && Boolean(form.host_cert_path.trim())
    const payload = {
      ca_pub_path: form.ca_pub_path.trim(),
      krl_path: form.krl_path.trim(),
      host_cert_path: isHostCa ? form.host_cert_path.trim() : '',
      reload_command: form.reload_command.trim(),
      enabled: form.enabled,
    }
    if (isHostCa) {
      // Empty is a real answer here: it means "the CA's own default", "the CA
      // names the key ID", "let UCM read the host key". A user CA sends none of
      // these at all: host names in its binding would read as "who may log in".
      payload.validity = form.validity.trim()
      payload.key_id_template = form.key_id_template.trim()
      payload.host_public_key = form.paste_host_key ? form.host_public_key.trim() : ''
      if (writesCert) payload.principals = form.principals
    }
    try {
      if (editing) {
        await deployService.updateSSHBinding(ca.id, editing.id, payload)
        showSuccess(t('common.updated'))
      } else {
        await deployService.createSSHBinding(ca.id, {
          ...payload, target_id: Number(form.target_id),
        })
        showSuccess(t('sshDeploy.created'))
      }
      setOpen(false)
      setEditing(null)
      await load()
      onChanged?.()
    } catch (error) {
      reject(error)
    } finally {
      setSaving(false)
    }
  }

  const deployNow = async (binding) => {
    setBusy(binding.id)
    try {
      await deployService.deploySSHNow(ca.id, binding.id)
      showSuccess(t('deploy.deployed', { name: binding.target_name }))
    } catch (error) {
      showError(error.message || t('deploy.deployFailed'))
    } finally {
      setBusy(null)
      await load()
    }
  }

  // A delivery that exhausted its retries stays failed until someone asks again
  const retry = async (binding) => {
    setBusy(binding.id)
    try {
      await deployService.retryDelivery(binding.last_delivery.id)
      showSuccess(t('sshDeploy.requeued'))
    } catch (error) {
      showError(error.message || t('deploy.deployFailed'))
    } finally {
      setBusy(null)
      await load()
    }
  }

  const remove = async (binding) => {
    const confirmed = await showConfirm(t('sshDeploy.removeConfirm', { name: binding.target_name }),
      { title: t('common.remove'), variant: 'danger', confirmText: t('common.delete') })
    if (!confirmed) return
    try {
      await deployService.deleteSSHBinding(ca.id, binding.id)
      showSuccess(t('sshDeploy.removed'))
      await load()
      onChanged?.()
    } catch (error) {
      showError(error.message || t('deploy.deleteFailed'))
    }
  }

  if (!canRead) return null

  const krlMissing = bindings.filter(binding =>
    binding.krl_path && binding.last_delivery?.status !== 'delivered').length
  const hasPath = form && Boolean(
    (form.ca_pub_path.trim() || form.krl_path.trim() || form.host_cert_path.trim()))
  const writesCert = form && isHostCa && Boolean(form.host_cert_path.trim())

  return (
    <>
      <CompactSection title={t('deploy.certSection')} icon={CloudArrowUp} iconClass="icon-bg-emerald">
        <p className="text-2xs text-text-tertiary mb-2">
          {t(isHostCa ? 'sshDeploy.meaningHost' : 'sshDeploy.meaningUser')}
        </p>
        {loading ? (
          <div className="text-2xs text-text-tertiary">{t('common.loading')}</div>
        ) : (
          <>
            {bindings.length === 0 ? (
              <p className="text-2xs text-text-tertiary italic">{t('sshDeploy.none')}</p>
            ) : (
              <div className="space-y-2">
                {krlMissing > 0 && (
                  <p className="text-2xs text-text-secondary" role="status">
                    {t('sshDeploy.krlUndeliveredSection', { count: krlMissing, total: bindings.length })}
                  </p>
                )}
                {bindings.map(binding => {
                  const cert = binding.host_certificate
                  const delivery = binding.last_delivery
                  return (
                    <div key={binding.id}
                      className="p-2.5 bg-tertiary-50 border border-border rounded-lg space-y-1">
                      <div className="flex items-start justify-between gap-2 flex-wrap">
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-xs font-medium text-text-primary truncate"
                              title={binding.target_name}>
                              {binding.target_name}
                            </span>
                            {!binding.enabled ? (
                              <Badge variant="secondary" size="sm">{t('common.disabled')}</Badge>
                            ) : delivery ? (
                              <Badge variant={STATUS_VARIANT[delivery.status] || 'secondary'} size="sm"
                                title={delivery.last_error || ''}>
                                {t(`deploy.status.${delivery.status}`)}
                              </Badge>
                            ) : (
                              <Badge variant="secondary" size="sm">{t('common.enabled')}</Badge>
                            )}
                            {binding.host_cert_path && !cert && (
                              <Badge variant="secondary" size="sm">{t('sshDeploy.hostCertMissing')}</Badge>
                            )}
                            {cert?.status === 'expired' && (
                              <Badge variant="warning" size="sm" icon={Warning}>
                                {t('sshDeploy.hostCertExpired')}
                              </Badge>
                            )}
                          </div>
                          {binding.host_cert_path && !cert && (
                            <p className="text-2xs text-text-tertiary">{t('sshDeploy.hostCertMissingHint')}</p>
                          )}
                          {cert?.status === 'expired' && (
                            <p className="text-2xs status-warning-text">{t('sshDeploy.hostCertExpiredHint')}</p>
                          )}
                          {!binding.target_enabled && (
                            <p className="text-2xs status-warning-text">{t('sshDeploy.targetDisabled')}</p>
                          )}
                          {[binding.ca_pub_path, binding.krl_path, binding.host_cert_path]
                            .filter(Boolean)
                            .map(path => (
                              <code key={path} className="block text-2xs font-mono text-text-secondary break-all">
                                {path}
                              </code>
                            ))}
                          {!binding.ca_pub_path && !binding.krl_path && !binding.host_cert_path && (
                            <p className="text-2xs text-text-tertiary">{t('sshDeploy.noPaths')}</p>
                          )}
                          {binding.host_cert_path && binding.principals?.length > 0 && (
                            <p className="text-2xs text-text-tertiary">
                              {t('sshCertificates.principals')}: {binding.principals.join(', ')}
                            </p>
                          )}
                          {binding.reload_command && (
                            <p className="text-2xs font-mono text-text-tertiary truncate"
                              title={binding.reload_command}>
                              {t('deploy.reloadCommand')}: {binding.reload_command}
                            </p>
                          )}
                          {delivery?.status === 'delivered' && delivery.delivered_at && (
                            <p className="text-2xs text-text-tertiary">
                              {t('deploy.lastDeployed', { date: formatDate(delivery.delivered_at) })}
                            </p>
                          )}
                          {/* No live role on the countdown line: its text changes every
                              second, and a live region would read those numbers out loud. The
                              delivery status itself is in the badge next to the target name. */}
                          {delivery?.status === 'pending' && delivery.next_attempt_at && (
                            <p className="text-2xs text-text-tertiary">
                              {t('deploy.nextRetry', {
                                date: formatDate(delivery.next_attempt_at),
                                countdown: retryCountdown(delivery.next_attempt_at, now),
                              })}
                            </p>
                          )}
                          {delivery?.status === 'failed' && (
                            <p className="text-2xs text-text-tertiary" role="status">
                              {t('deploy.lastDeployed', { date: formatDate(delivery.created_at) })}
                              {delivery.attempts != null && delivery.max_attempts != null
                                ? ` · ${t('sshDeploy.attempts', {
                                  attempts: delivery.attempts, maxAttempts: delivery.max_attempts })}` : ''}
                            </p>
                          )}
                          {delivery?.last_error && (
                            <p className={`text-2xs ${delivery.status === 'failed' ? 'status-danger-text' : 'status-warning-text'}`}
                              title={delivery.last_error}>
                              {delivery.last_error}
                            </p>
                          )}
                        </div>
                        {(canEdit || canRemove) && (
                          <div className="flex gap-1 shrink-0 flex-wrap">
                            {canEdit && (
                              <Button type="button" size="xs" variant="secondary"
                                onClick={() => openEdit(binding)}
                                title={t('common.edit')}
                                aria-label={`${t('common.edit')}: ${binding.target_name}`}>
                                <PencilSimple size={14} />
                              </Button>
                            )}
                            {canEdit && binding.enabled && (
                              <Button type="button" size="xs" variant="secondary"
                                onClick={() => deployNow(binding)} disabled={busy === binding.id}
                                title={t('deploy.deployNow')}
                                aria-label={`${t('deploy.deployNow')}: ${binding.target_name}`}>
                                <UploadSimple size={14} />
                              </Button>
                            )}
                            {canEdit && delivery?.status === 'failed' && (
                              <Button type="button" size="xs" variant="secondary"
                                onClick={() => retry(binding)} disabled={busy === binding.id}
                                title={t('sshDeploy.retry')}
                                aria-label={`${t('sshDeploy.retry')}: ${binding.target_name}`}>
                                <ArrowCounterClockwise size={14} />
                              </Button>
                            )}
                            {canRemove && (
                              <Button type="button" size="xs" variant="ghost"
                                onClick={() => remove(binding)}
                                title={t('common.remove')}
                                aria-label={`${t('common.remove')}: ${binding.target_name}`}>
                                <Trash size={14} />
                              </Button>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
            {canEdit && (
              <>
                <Button type="button" size="sm" variant="secondary" className="mt-3"
                  onClick={() => openAttach()} disabled={availableTargets.length === 0}>
                  <Plus size={14} /> {t('deploy.attachTarget')}
                </Button>
                {availableTargets.length === 0 && (
                  <p className="text-2xs text-text-tertiary mt-1">{t('deploy.noAvailableTargets')}</p>
                )}
              </>
            )}
          </>
        )}
      </CompactSection>

      {open && form && (
        <Modal open={open}
          onOpenChange={(value) => { if (!saving) setOpen(value) }}
          title={editing ? t('deploy.editDeploymentFor', { name: caName })
            : t('deploy.attachTargetFor', { name: caName })}
          size="md">
          <form onSubmit={save} className="p-4 space-y-3">
            <div className="space-y-1">
              <label htmlFor={fieldId('target_id')} className="block text-xs font-medium text-text-secondary">
                {t('deploy.target')}
              </label>
              <select id={fieldId('target_id')} required disabled={Boolean(editing)}
                value={form.target_id}
                onChange={(event) => chooseTarget(event.target.value)}
                aria-invalid={errors.target_id ? true : undefined}
                aria-describedby={errors.target_id ? `${fieldId('target_id')}-error` : undefined}
                className="w-full px-2.5 py-1.5 bg-bg-tertiary border border-border rounded-md text-sm text-text-primary focus:outline-none focus:border-accent-primary">
                {editing ? (
                  <option value={editing.target_id}>
                    {editing.target_name} ({editing.target_host})
                  </option>
                ) : (
                  <>
                    <option value="">{t('deploy.selectTarget')}</option>
                    {availableTargets.map(target => (
                      <option key={target.id} value={target.id}>
                        {target.name} ({target.username}@{target.host}:{target.port})
                      </option>
                    ))}
                  </>
                )}
              </select>
              {!editing && availableTargets.length === 0 && (
                <p className="text-2xs text-text-tertiary">{t('deploy.noAvailableTargets')}</p>
              )}
              {errors.target_id && (
                <p id={`${fieldId('target_id')}-error`} role="status"
                  className="text-xs status-danger-text">{errors.target_id}</p>
              )}
              {form.target_id && (() => {
                const target = targetOf(form.target_id)
                if (!target) return null
                return (
                  <p className="text-2xs font-mono text-text-tertiary break-all">
                    {`${target.username}@${target.host}:${target.port}`}
                    {' · '}
                    {target.host_key_pinned
                      ? t('deploy.hostKeyPinned', { fingerprint: target.host_key_fingerprint || '' })
                      : t('deploy.hostKeyNotPinned')}
                  </p>
                )
              })()}
            </div>

            {isHostCa && writesCert && (
              form.paste_host_key ? (
                <Textarea label={t('sshDeploy.hostKeyLabel')} mono rows={2}
                  id={fieldId('host_public_key')} value={form.host_public_key}
                  placeholder={t('sshDeploy.hostKeyPlaceholder')}
                  error={errors.host_public_key}
                  helperText={t('sshDeploy.hostKeyPasteHelp')}
                  onChange={(event) => setForm({ ...form, host_public_key: event.target.value })} />
              ) : (
                <div className="text-2xs text-text-tertiary">
                  {form.host_public_key || t('sshDeploy.hostKeyAuto')}
                  {' '}
                  <Button type="button" size="xs" variant="ghost"
                    onClick={() => setForm({ ...form, paste_host_key: true })}>
                    {t('sshDeploy.hostKeyPaste')}
                  </Button>
                </div>
              )
            )}

            <Input mono label={t('sshDeploy.caPubPath')} id={fieldId('ca_pub_path')}
              value={form.ca_pub_path} error={errors.ca_pub_path}
              onChange={(event) => setForm({ ...form, ca_pub_path: event.target.value })} />
            <Input mono label={t('sshDeploy.krlPath')} id={fieldId('krl_path')}
              value={form.krl_path} error={errors.krl_path}
              helperText={t('sshDeploy.pathsHelp')}
              onChange={(event) => setForm({ ...form, krl_path: event.target.value })} />
            {isHostCa && (
              <Input mono label={t('sshDeploy.hostCertPath')} id={fieldId('host_cert_path')}
                value={form.host_cert_path} error={errors.host_cert_path}
                onChange={(event) => setForm({ ...form, host_cert_path: event.target.value })} />
            )}

            {isHostCa && writesCert && (
              <>
                <Input label={t('common.validity')} id={fieldId('validity')}
                  value={form.validity} error={errors.validity}
                  placeholder={t('sshCas.modal.ttlPlaceholder')}
                  helperText={Number(ca.max_ttl)
                    ? t('sshDeploy.validityCaRange', {
                      defaultTtl: ttlText(ca.default_ttl), maxTtl: ttlText(ca.max_ttl) })
                    : t('sshDeploy.validityNoMax', { defaultTtl: ttlText(ca.default_ttl) })}
                  onChange={(event) => setForm({ ...form, validity: event.target.value })} />
                <TagsInput id={fieldId('principals')} label={t('sshCertificates.principals')}
                  value={form.principals} error={errors.principals}
                  validate={(name) => {
                    const exact = isExactHost(name)
                    if (!exact) {
                      // TagsInput itself has no way to say why a value is refused
                      setErrors(current => ({
                        ...current,
                        principals: t('sshDeploy.errors.principalNotExact', { principal: name }),
                      }))
                    }
                    return exact
                  }}
                  helperText={t('sshDeploy.principalsHelp')}
                  onChange={(principals) => setForm({ ...form, principals })} />
                <label className="flex items-start gap-3 p-2.5 bg-bg-tertiary border border-border rounded-md cursor-pointer">
                  <input type="checkbox" className="mt-0.5 w-4 h-4 accent-accent-primary"
                    checked={form.include_short}
                    onChange={(event) => toggleShort(event.target.checked)} />
                  <span className="text-xs text-text-primary">{t('sshDeploy.includeShortName')}</span>
                </label>
                {ca.allow_custom_key_id && (
                  <Input mono label={t('sshDeploy.keyIdTemplate')} id={fieldId('key_id_template')}
                    value={form.key_id_template} error={errors.key_id_template}
                    helperText={t('sshDeploy.keyIdTemplateHelp', {
                      hostname: '{{hostname}}', target_name: '{{target_name}}',
                      ca_name: '{{ca_name}}', principal: '{{principal}}', serial: '{{serial}}',
                    })}
                    onChange={(event) => setForm({ ...form, key_id_template: event.target.value })} />
                )}
              </>
            )}

            <Input mono label={t('deploy.reloadCommand')} id={fieldId('reload_command')}
              maxLength={512} value={form.reload_command} error={errors.reload_command}
              helperText={`${t('sshDeploy.reloadCommandHint')} ${t('sshDeploy.reloadCommandPerms')}`}
              onChange={(event) => setForm({ ...form, reload_command: event.target.value })} />

            <label className="flex items-start gap-3 p-2.5 bg-bg-tertiary border border-border rounded-md cursor-pointer">
              <input type="checkbox" className="mt-0.5 w-4 h-4 accent-accent-primary"
                checked={form.enabled}
                onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />
              <span className="text-xs text-text-primary">{t('common.enabled')}</span>
            </label>

            <div className="flex justify-end gap-2 pt-3 border-t border-border">
              <Button type="button" variant="secondary" disabled={saving}
                onClick={() => { setOpen(false); setEditing(null) }}>
                {t('common.cancel')}
              </Button>
              <Button type="submit" variant="primary" loading={saving}
                disabled={!form.target_id || !hasPath}>
                {editing ? t('common.save') : t('deploy.attachTarget')}
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  )
}
