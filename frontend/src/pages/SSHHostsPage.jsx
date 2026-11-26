/**
 * SSHHostsPage - managed SSH hosts (pull-model KRL + host-cert automation)
 * Built on Atelier primitives: Zone + PageHead + ListView + Modal actions.
 */
import { useState, useEffect, useMemo, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Zone, Btn, Pill, PageHead, Toolbar, SearchField, ListView, Section, Facts,
  EmptyBlock, NoMatch, Modal, Input, Select, Textarea, ToggleSwitch, Notice,
  FormFields, ModalActions, useClientList,
} from '../components/atelier'
import { fact } from '../components/atelier/facts'
import { sshHostsService, sshCasService } from '../services'
import { useNotification } from '../contexts'
import { usePermission, useWebSocket, useClipboard } from '../hooks'
import { formatDate, formatRelativeTime } from '../lib/utils'

function certPill(host, t) {
  const s = host.cert_status
  if (!s) return <Pill tone="neutral" label={t('sshHosts.certNone')} />
  if (s === 'revoked') return <Pill tone="bad" label={t('sshHosts.certRevoked')} />
  if (s === 'expired') return <Pill tone="bad" label={t('sshHosts.certExpired')} />
  if (s === 'expiring') return <Pill tone="warn" label={t('sshHosts.certExpiring')} />
  return <Pill tone="ok" label={t('sshHosts.certValid')} />
}

function agentHealth(host, t) {
  if (host.status === 'revoked') return { tone: 'bad', label: t('sshHosts.agentBlocked') }
  if (!host.last_seen_at) return { tone: 'neutral', label: t('sshHosts.agentNever') }
  const ageMin = (Date.now() - new Date(host.last_seen_at).getTime()) / 60000
  if (ageMin <= 45) return { tone: 'ok', label: t('sshHosts.agentOnline') }
  return { tone: 'warn', label: t('sshHosts.agentOffline') }
}

function InstallCommandModal({ result, onClose, t }) {
  const { copy, isCopied } = useClipboard()
  const [platform, setPlatform] = useState('linux')
  if (!result) return null

  const cmd = platform === 'windows'
    ? `iwr -useb "${result.install_command.match(/https?:\/\/[^" ]+/)?.[0] || ''}&platform=windows" | iex`
    : result.install_command

  return (
    <Modal open={!!result} onClose={onClose} title={t('sshHosts.installTitle')} size="lg">
      <div className="module-detail space-y-4">
        <Notice tone="ok">
          <strong>{t('sshHosts.bootstrapReady')}</strong> — {t('sshHosts.bootstrapTtl')}
        </Notice>

        <div className="flex items-center justify-between gap-2">
          <span className="muted small">{t('sshHosts.installHint')}</span>
          <div className="flex gap-1">
            <Btn size="sm" tone={platform === 'linux' ? 'primary' : 'quiet'} icon="terminal" onClick={() => setPlatform('linux')}>
              {t('sshHosts.platformLinux')}
            </Btn>
            <Btn size="sm" tone={platform === 'windows' ? 'primary' : 'quiet'} icon="monitor" onClick={() => setPlatform('windows')}>
              {t('sshHosts.platformWindows')}
            </Btn>
          </div>
        </div>

        <div className="command-line">
          <code className="mono">{cmd}</code>
          <Btn size="sm" icon={isCopied('install') ? 'check' : 'copy'} onClick={() => copy(cmd, 'install')}>
            {isCopied('install') ? t('sshHosts.copied') : t('common.copy')}
          </Btn>
        </div>

        <Section title={t('sshHosts.stepsTitle')}>
          <ul className="muted small space-y-1">
            <li>• {t('sshHosts.step1')}</li>
            <li>• {t('sshHosts.step2')}</li>
            <li>• {t('sshHosts.step3')}</li>
            <li>• {t('sshHosts.step4')}</li>
          </ul>
        </Section>

        <ModalActions>
          <Btn tone="primary" onClick={onClose}>{t('common.done')}</Btn>
        </ModalActions>
      </div>
    </Modal>
  )
}

function ConnectModal({ open, onClose, hostCAs, userCAs, onCreated, t }) {
  const [hostname, setHostname] = useState('')
  const [hostCaId, setHostCaId] = useState('')
  const [userCaId, setUserCaId] = useState('')
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    if (open) {
      setHostname('')
      setHostCaId(hostCAs[0]?.id ? String(hostCAs[0].id) : '')
      setUserCaId(userCAs[0]?.id ? String(userCAs[0].id) : '')
      setErr('')
    }
  }, [open, hostCAs, userCAs])

  const submit = async (e) => {
    e.preventDefault()
    if (!hostCaId && !userCaId) {
      setErr(t('sshHosts.caRequired'))
      return
    }
    setSaving(true)
    setErr('')
    try {
      const res = await sshHostsService.create({
        hostname: hostname.trim(),
        host_ca_id: hostCaId ? Number(hostCaId) : null,
        user_ca_id: userCaId ? Number(userCaId) : null,
      })
      onCreated(res.data)
      onClose()
    } catch (e2) {
      setErr(e2.message || t('common.error'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={t('sshHosts.connectTitle')} subtitle={t('sshHosts.connectSubtitle')} size="lg">
      <form onSubmit={submit}>
        <FormFields>
          <Input
            label={t('sshHosts.hostnameLabel')}
            placeholder={t('sshHosts.hostnamePlaceholder')}
            hint={t('sshHosts.hostnameHint')}
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            full
          />
          <Select
            label={t('sshHosts.hostCaCol')}
            value={hostCaId}
            error={err && !hostCaId && !userCaId ? err : undefined}
            onChange={(v) => { setHostCaId(v); setErr('') }}
            options={[
              { value: '', label: t('sshHosts.noHostCa') },
              ...hostCAs.map((c) => ({ value: String(c.id), label: c.descr })),
            ]}
          />
          <Select
            label={t('sshHosts.userCaCol')}
            value={userCaId}
            error={err && !hostCaId && !userCaId ? err : undefined}
            onChange={(v) => { setUserCaId(v); setErr('') }}
            options={[
              { value: '', label: t('sshHosts.selectUserCa') },
              ...userCAs.map((c) => ({ value: String(c.id), label: c.descr })),
            ]}
          />
          {err && (hostCaId || userCaId) && <Notice tone="bad">{err}</Notice>}
        </FormFields>
        <ModalActions>
          <Btn tone="quiet" onClick={onClose}>{t('common.cancel')}</Btn>
          <Btn type="submit" tone="primary" disabled={saving}>{t('sshHosts.generateCommand')}</Btn>
        </ModalActions>
      </form>
    </Modal>
  )
}

export default function SSHHostsPage() {
  const { t } = useTranslation()
  const { showSuccess, showError, showConfirm } = useNotification()
  const { canWrite, canDelete } = usePermission()
  useWebSocket()

  const [hosts, setHosts] = useState([])
  const [hostCAs, setHostCAs] = useState([])
  const [userCAs, setUserCAs] = useState([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [connectOpen, setConnectOpen] = useState(false)
  const [commandResult, setCommandResult] = useState(null)
  const [revokeTarget, setRevokeTarget] = useState(null)
  const [revokeReason, setRevokeReason] = useState('')
  const [revokeCertOption, setRevokeCertOption] = useState(false)
  const [selectedHost, setSelectedHost] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [hostsRes, casRes] = await Promise.all([
        sshHostsService.getAll({ per_page: 100 }),
        sshCasService.getAll(),
      ])
      const hostList = hostsRes.data || []
      setHosts(hostList)
      const cas = casRes.data || []
      setHostCAs(cas.filter((c) => c.ca_type === 'host'))
      setUserCAs(cas.filter((c) => c.ca_type === 'user'))
      setSelectedHost((prev) => (prev ? hostList.find((h) => h.id === prev.id) || prev : null))
    } catch (e) {
      showError(e.message || t('common.error'))
    } finally {
      setLoading(false)
    }
  }, [showError, t])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return hosts
    return hosts.filter((h) =>
      [h.hostname, h.host_ca_name, h.user_ca_name, h.last_ip]
        .some((v) => v && String(v).toLowerCase().includes(q))
    )
  }, [hosts, query])

  const list = useClientList(filtered, { defaultSort: { key: 'hostname', dir: 'asc' } })

  const toggleAutoRenew = async (host) => {
    try {
      const res = await sshHostsService.setAutoRenew(host.id, !host.auto_renew)
      setHosts((prev) => prev.map((h) => (h.id === host.id ? res.data : h)))
      if (selectedHost?.id === host.id) setSelectedHost(res.data)
    } catch (e) {
      showError(e.message || t('common.error'))
    }
  }

  const doRevoke = async (e) => {
    e.preventDefault()
    if (!revokeTarget) return
    try {
      const res = await sshHostsService.revokeCert(revokeTarget.id, revokeReason, revokeCertOption)
      setHosts((prev) => prev.map((h) => (h.id === revokeTarget.id ? res.data.host : h)))
      if (selectedHost?.id === revokeTarget.id) setSelectedHost(res.data.host)
      setRevokeTarget(null)
      setRevokeReason('')
      setRevokeCertOption(false)
      showSuccess(t('sshHosts.revokeDone'))
    } catch (e2) {
      showError(e2.message || t('common.error'))
    }
  }

  const doReinstall = async (host) => {
    try {
      const res = await sshHostsService.reissueBootstrap(host.id)
      setCommandResult(res.data)
    } catch (e) {
      showError(e.message || t('common.error'))
    }
  }

  const doDelete = async (host) => {
    const confirmed = await showConfirm(t('sshHosts.deleteConfirm', { hostname: host.hostname }), {
      title: t('common.delete'), confirmText: t('common.delete'), variant: 'danger',
    })
    if (!confirmed) return
    try {
      await sshHostsService.delete(host.id)
      setHosts((prev) => prev.filter((h) => h.id !== host.id))
      if (selectedHost?.id === host.id) setSelectedHost(null)
    } catch (e) {
      showError(e.message || t('common.error'))
    }
  }

  // ============= HOST DETAIL & CA SETTINGS MODAL =============

  const [editHostCaId, setEditHostCaId] = useState('')
  const [editUserCaId, setEditUserCaId] = useState('')
  const [ttlMode, setTtlMode] = useState('default')
  const [customTtlDays, setCustomTtlDays] = useState('30')
  const [threshMode, setThreshMode] = useState('default')
  const [customThreshPct, setCustomThreshPct] = useState('30')
  const [savingConfig, setSavingConfig] = useState(false)
  const [configError, setConfigError] = useState('')

  useEffect(() => {
    if (!selectedHost) return
    setEditHostCaId(selectedHost.host_ca_id ? String(selectedHost.host_ca_id) : '')
    setEditUserCaId(selectedHost.user_ca_id ? String(selectedHost.user_ca_id) : '')
    if (selectedHost.host_cert_ttl) {
      setTtlMode('custom')
      setCustomTtlDays(String(Math.max(1, Math.round(selectedHost.host_cert_ttl / 86400))))
    } else {
      setTtlMode('default')
      setCustomTtlDays(String(Math.max(1, Math.round((selectedHost.host_ca_default_ttl || 2592000) / 86400))))
    }
    if (selectedHost.renew_threshold_percent) {
      setThreshMode('custom')
      setCustomThreshPct(String(selectedHost.renew_threshold_percent))
    } else {
      setThreshMode('default')
      setCustomThreshPct(String(selectedHost.host_ca_default_threshold || 30))
    }
    setConfigError('')
  }, [selectedHost])

  const selectedHostCaObj = useMemo(
    () => hostCAs.find((c) => String(c.id) === editHostCaId) || null,
    [hostCAs, editHostCaId]
  )

  const computedNewTtl = editHostCaId && ttlMode === 'custom'
    ? Math.max(1, parseInt(customTtlDays, 10) || 1) * 86400
    : null
  const computedNewThresh = editHostCaId && threshMode === 'custom'
    ? Math.min(90, Math.max(1, parseInt(customThreshPct, 10) || 30))
    : null

  const isConfigDirty = Boolean(selectedHost) && (
    (editHostCaId || '') !== (selectedHost.host_ca_id ? String(selectedHost.host_ca_id) : '')
    || (editUserCaId || '') !== (selectedHost.user_ca_id ? String(selectedHost.user_ca_id) : '')
    || computedNewTtl !== (selectedHost.host_cert_ttl ?? null)
    || computedNewThresh !== (selectedHost.renew_threshold_percent ?? null)
  )

  const saveHostConfig = async () => {
    if (!selectedHost) return
    if (!editHostCaId && !editUserCaId) {
      setConfigError(t('sshHosts.caRequired'))
      return
    }
    setSavingConfig(true)
    setConfigError('')
    try {
      const res = await sshHostsService.update(selectedHost.id, {
        host_ca_id: editHostCaId ? Number(editHostCaId) : null,
        user_ca_id: editUserCaId ? Number(editUserCaId) : null,
        host_cert_ttl: computedNewTtl,
        renew_threshold_percent: computedNewThresh,
      })
      const updated = res.data
      setHosts((prev) => prev.map((h) => (h.id === updated.id ? updated : h)))
      setSelectedHost(updated)
      showSuccess(t('sshHosts.hostUpdated'))
    } catch (e) {
      setConfigError(e.message || t('common.error'))
    } finally {
      setSavingConfig(false)
    }
  }

  const createAction = canWrite('ssh_cas')
    ? { label: t('sshHosts.connect'), icon: 'plus', onClick: () => setConnectOpen(true), primary: true }
    : undefined

  return (
    <Zone after={<>
      <Modal
        open={!!selectedHost}
        onClose={() => setSelectedHost(null)}
        title={selectedHost?.hostname || t('sshHosts.details')}
        size="lg"
      >
        {selectedHost && (
          <div className="module-detail space-y-4">
            <div className="flex items-center gap-2 flex-wrap">
              {selectedHost.status === 'active' && (
                selectedHost.config_synced === false
                  ? <Pill tone="warn" label={t('sshHosts.pendingSync')} />
                  : <Pill tone="ok" label={t('sshHosts.configSynced')} />
              )}
              <Pill
                tone={selectedHost.status === 'revoked' ? 'bad' : (selectedHost.status === 'active' ? 'ok' : 'neutral')}
                label={selectedHost.status === 'revoked' ? t('common.revoked') : (selectedHost.status === 'active' ? t('common.active') : selectedHost.status)}
              />
              <Pill tone={agentHealth(selectedHost, t).tone} label={agentHealth(selectedHost, t).label} />
            </div>

            {selectedHost.status === 'active' && selectedHost.config_synced === false && (
              <Notice tone="warn">{t('sshHosts.pendingSyncHint')}</Notice>
            )}

            <Section title={t('sshHosts.caSettingsTitle')}>
              {selectedHost.status === 'revoked' && (
                <Notice tone="bad">{t('sshHosts.revokedReadOnly')}</Notice>
              )}
              <FormFields>
                <Select
                  label={t('sshHosts.hostCaCol')}
                  value={editHostCaId}
                  onChange={(v) => { setEditHostCaId(v); setConfigError('') }}
                  disabled={!canWrite('ssh_cas') || selectedHost.status === 'revoked'}
                  options={[
                    { value: '', label: t('sshHosts.noHostCa') },
                    ...hostCAs.map((c) => ({ value: String(c.id), label: c.descr })),
                  ]}
                />
                <Select
                  label={t('sshHosts.userCaCol')}
                  value={editUserCaId}
                  onChange={(v) => { setEditUserCaId(v); setConfigError('') }}
                  disabled={!canWrite('ssh_cas') || selectedHost.status === 'revoked'}
                  options={[
                    { value: '', label: t('sshHosts.selectUserCa') },
                    ...userCAs.map((c) => ({ value: String(c.id), label: c.descr })),
                  ]}
                />
                {editHostCaId && (
                  <>
                    <Select
                      label={t('sshHosts.hostCertTtlDays')}
                      value={ttlMode}
                      onChange={setTtlMode}
                      disabled={!canWrite('ssh_cas') || selectedHost.status === 'revoked'}
                      options={[
                        {
                          value: 'default',
                          label: `${t('sshHosts.useCaDefault')} (${Math.max(1, Math.round((selectedHostCaObj?.host_cert_ttl || 2592000) / 86400))}d)`,
                        },
                        { value: 'custom', label: t('sshHosts.customValue') },
                      ]}
                    />
                    {ttlMode === 'custom' && (
                      <Input
                        type="number"
                        min={1}
                        max={3650}
                        label={t('sshHosts.hostCertTtlDays')}
                        value={customTtlDays}
                        onChange={(e) => setCustomTtlDays(e.target.value)}
                        disabled={!canWrite('ssh_cas') || selectedHost.status === 'revoked'}
                      />
                    )}
                    <Select
                      label={t('sshHosts.renewThresholdPct')}
                      value={threshMode}
                      onChange={setThreshMode}
                      disabled={!canWrite('ssh_cas') || selectedHost.status === 'revoked'}
                      options={[
                        {
                          value: 'default',
                          label: `${t('sshHosts.useCaDefault')} (${selectedHostCaObj?.renew_threshold_percent || 30}%)`,
                        },
                        { value: 'custom', label: t('sshHosts.customValue') },
                      ]}
                    />
                    {threshMode === 'custom' && (
                      <Input
                        type="number"
                        min={1}
                        max={90}
                        label={t('sshHosts.renewThresholdPct')}
                        value={customThreshPct}
                        onChange={(e) => setCustomThreshPct(e.target.value)}
                        disabled={!canWrite('ssh_cas') || selectedHost.status === 'revoked'}
                      />
                    )}
                  </>
                )}
                {configError && <Notice tone="bad">{configError}</Notice>}
              </FormFields>
              {canWrite('ssh_cas') && selectedHost.status !== 'revoked' && (
                <div className="mt-3 flex justify-end">
                  <Btn
                    tone="primary"
                    disabled={!isConfigDirty || savingConfig || (!editHostCaId && !editUserCaId)}
                    onClick={saveHostConfig}
                  >
                    {t('sshHosts.saveChanges')}
                  </Btn>
                </div>
              )}
            </Section>

            <Section title={t('sshHosts.hostIdentity')}>
              <Facts items={[
                [t('sshHosts.certCol'), certPill(selectedHost, t)],
                fact(t('sshHosts.certSerial'), selectedHost.cert_serial),
                fact(t('common.validTo'), selectedHost.cert_valid_to && formatDate(selectedHost.cert_valid_to)),
                fact(t('sshHosts.krlCol'), selectedHost.last_krl_sync_at && formatDate(selectedHost.last_krl_sync_at)),
              ]} />
              <div className="mt-3">
                <ToggleSwitch
                  checked={Boolean(selectedHost.auto_renew)}
                  disabled={!canWrite('ssh_cas') || selectedHost.status === 'revoked'}
                  label={t('sshHosts.autoRenewCol')}
                  description={t('sshHosts.autoRenewDescription')}
                  onChange={() => toggleAutoRenew(selectedHost)}
                />
              </div>
            </Section>

            <Section title={t('sshHosts.agentConnectivity')}>
              <Facts items={[
                fact(t('sshHosts.lastSeen'), selectedHost.last_seen_at ? formatRelativeTime(new Date(selectedHost.last_seen_at), t) : t('sshHosts.neverSeen')),
                fact(t('sshHosts.lastIp'), selectedHost.last_ip),
                fact(t('sshHosts.tokenPrefix'), selectedHost.token_prefix && `${selectedHost.token_prefix}...`),
              ]} />
            </Section>

            <ModalActions>
              {selectedHost.status !== 'revoked' && canWrite('ssh_cas') && (
                <Btn icon="terminal" onClick={() => doReinstall(selectedHost)}>{t('sshHosts.reinstall')}</Btn>
              )}
              {selectedHost.status === 'active' && canWrite('ssh') && (
                <Btn tone="danger" onClick={() => { setRevokeReason(''); setRevokeCertOption(false); setRevokeTarget(selectedHost) }}>
                  {t('sshHosts.revokeHost')}
                </Btn>
              )}
              {selectedHost.status === 'revoked' && canDelete('ssh_cas') && (
                <Btn tone="danger" onClick={() => doDelete(selectedHost)}>{t('common.delete')}</Btn>
              )}
            </ModalActions>
          </div>
        )}
      </Modal>

      <ConnectModal
        open={connectOpen}
        onClose={() => setConnectOpen(false)}
        hostCAs={hostCAs}
        userCAs={userCAs}
        onCreated={(res) => {
          setHosts((prev) => [res.host, ...prev])
          setCommandResult(res)
        }}
        t={t}
      />

      <InstallCommandModal result={commandResult} onClose={() => setCommandResult(null)} t={t} />

      <Modal open={!!revokeTarget} onClose={() => setRevokeTarget(null)} title={t('sshHosts.revokeHost')} size="md">
        {revokeTarget && (
          <form onSubmit={doRevoke}>
            <Notice tone="warn">{t('sshHosts.revokeHostConfirm', { hostname: revokeTarget.hostname })}</Notice>
            <FormFields>
              <Textarea
                label={t('sshHosts.revokeReason')}
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                placeholder={t('sshHosts.revokeReasonPlaceholder')}
                rows={2}
              />
              <label className="flex items-start gap-2 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={revokeCertOption}
                  onChange={(e) => setRevokeCertOption(e.target.checked)}
                />
                <span>
                  <strong>{t('sshHosts.revokeCertAlso')}</strong> — {t('sshHosts.revokeCertAlsoHint')}
                </span>
              </label>
            </FormFields>
            <ModalActions>
              <Btn tone="quiet" onClick={() => setRevokeTarget(null)}>{t('common.cancel')}</Btn>
              <Btn type="submit" tone="danger">{t('sshHosts.revokeHost')}</Btn>
            </ModalActions>
          </form>
        )}
      </Modal>
    </>}>
      <PageHead
        title={t('sshHosts.title')}
        total={t('sshHosts.subtitle', { count: hosts.length })}
        intent={t('sshHosts.connectSubtitle')}
        actions={createAction && (
          <Btn tone="primary" icon="plus" onClick={createAction.onClick}>{createAction.label}</Btn>
        )}
      />

      <ListView
        label={t('sshHosts.title')}
        icon="server"
        list={list}
        nameSort="hostname"
        loading={loading && !hosts.length}
        toolbar={(
          <Toolbar>
            <SearchField
              id="ssh-hosts-search"
              name="q"
              label={t('sshHosts.searchPlaceholder')}
              placeholder={t('sshHosts.searchPlaceholder')}
              value={query}
              onChange={setQuery}
            />
          </Toolbar>
        )}
        title={(row) => (
          <span className="flex items-center gap-2 cursor-pointer" onClick={() => setSelectedHost(row)}>
            <span>{row.hostname}</span>
            {row.status === 'active' && row.config_synced === false && (
              <Pill tone="warn" label={t('sshHosts.pendingSync')} />
            )}
          </span>
        )}
        status={(row) => certPill(row, t)}
        openedId={selectedHost?.id}
        onOpen={setSelectedHost}
        columns={[
          { id: 'host_ca', label: t('sshHosts.hostCaCol'), cell: (r) => r.host_ca_name || '—', kind: 'fit', priority: 3 },
          { id: 'cert', label: t('sshHosts.certCol'), cell: (r) => certPill(r, t), kind: 'fit', priority: 2 },
          {
            id: 'auto_renew',
            label: t('sshHosts.autoRenewCol'),
            cell: (r) => (
              <span onClick={(e) => e.stopPropagation()}>
                <ToggleSwitch
                  role="switch"
                  aria-checked={Boolean(r.auto_renew)}
                  checked={Boolean(r.auto_renew)}
                  disabled={!canWrite('ssh_cas') || r.status === 'revoked'}
                  aria-label={t('sshHosts.autoRenewCol')}
                  onChange={() => toggleAutoRenew(r)}
                />
              </span>
            ),
            kind: 'fit',
            priority: 3,
          },
          { id: 'user_ca', label: t('sshHosts.userCaCol'), cell: (r) => r.user_ca_name || '—', kind: 'fit', priority: 3 },
          { id: 'agent', label: t('sshHosts.agentCol'), cell: (r) => <Pill tone={agentHealth(r, t).tone} label={agentHealth(r, t).label} />, kind: 'fit', priority: 2 },
          { id: 'last_seen', label: t('sshHosts.lastSeen'), cell: (r) => r.last_seen_at ? formatRelativeTime(new Date(r.last_seen_at), t) : t('sshHosts.neverSeen'), kind: 'fit', priority: 4, muted: true },
        ]}
        rowActions={(row) => [
          ...(row.status !== 'revoked' && canWrite('ssh_cas') ? [{ icon: 'terminal', label: t('sshHosts.reinstall'), onClick: () => doReinstall(row) }] : []),
          ...(canDelete('ssh_cas') ? [{ icon: 'close', label: t('common.delete'), danger: true, onClick: () => doDelete(row) }] : []),
        ]}
        empty={query.trim() && hosts.length ? (
          <NoMatch title={t('table.noResults')} text={t('table.adjustFilters')} resetLabel={t('table.clearFilters')} onReset={() => setQuery('')} />
        ) : (
          <EmptyBlock id="ssh-hosts" icon="server" title={t('sshHosts.noData')} text={t('sshHosts.connectSubtitle')} action={createAction} />
        )}
      />
    </Zone>
  )
}
