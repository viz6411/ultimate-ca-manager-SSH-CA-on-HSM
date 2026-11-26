/**
 * SSHHostsPage + ssh-hosts.service — the pull-only contract on the operator side.
 *
 * Issue #451 took the wake-up contract out of the product (`callback_url`, the HMAC
 * wake POST, `GET /api/v2/ssh/hosts/wait`). The table is where an operator would
 * notice if any of it came back: a "wake the host" button, a callback URL field, or
 * a service call aimed at the managed host instead of at UCM. Pinned here so it
 * cannot come back silently:
 *
 * - every action the service can take is a call to UCM's own admin API under
 *   /ssh/hosts — there is no wake / wait / callback method and no host address
 *   parameter anywhere;
 * - the icon-only row actions stay reachable without a mouse: real <button>s with
 *   an accessible name, because these are the destructive actions of the fleet
 *   table and an icon alone is not a name;
 * - nothing on the page asks for a callback or offers a push.
 *
 * The service under test is imported directly; the page is rendered through the
 * service barrel, which is mocked separately so its calls can be counted apart.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const recent = new Date(Date.now() - 60 * 1000).toISOString()

function hostFixture(over = {}) {
  return {
    id: 1,
    hostname: 'web01.test.example.com',
    host_ca_id: 10, host_ca_name: 'Lab Host CA',
    user_ca_id: 20, user_ca_name: 'Lab User CA',
    token_prefix: 'ucm_sh_abcd', principals: ['web01.test.example.com'],
    public_key: 'ssh-ed25519 AAAA...',
    auto_renew: true, status: 'active',
    cert_id: 5, cert_serial: 5, cert_status: 'valid', cert_valid_to: '2026-12-30T00:00:00',
    has_token: true, bootstrap_active: false,
    last_seen_at: recent, last_krl_sync_at: recent, last_renew_at: recent,
    last_ip: '10.0.0.5', created_at: '2026-11-01T00:00:00',
    ...over,
  }
}

const translate = vi.hoisted(() => (key) => key)
const i18nRef = vi.hoisted(() => ({ language: 'en', changeLanguage: vi.fn(), on: vi.fn(), off: vi.fn() }))
const notif = vi.hoisted(() => ({
  showSuccess: vi.fn(), showError: vi.fn(),
  showConfirm: vi.fn().mockResolvedValue(true), showPrompt: vi.fn(),
}))

// What the real service sends where.
const calls = vi.hoisted(() => [])
const apiClient = vi.hoisted(() => ({
  get: vi.fn((url) => { calls.push(['get', url]); return { data: [], meta: { total: 0 } } }),
  post: vi.fn((url, body) => { calls.push(['post', url, body]); return { data: {} } }),
  patch: vi.fn((url, body) => { calls.push(['patch', url, body]); return { data: {} } }),
  delete: vi.fn((url) => { calls.push(['delete', url]); return {} }),
}))

// The barrel the page imports, mocked so the render can be driven separately.
const pageService = vi.hoisted(() => ({
  getAll: vi.fn(), getById: vi.fn(), create: vi.fn(), setAutoRenew: vi.fn(),
  revokeCert: vi.fn(), forceRenew: vi.fn(), rotateToken: vi.fn(),
  reissueBootstrap: vi.fn(), delete: vi.fn(),
}))

vi.mock('../../services/apiClient', () => ({ apiClient }))
vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: translate, i18n: i18nRef }),
  Trans: ({ children }) => children,
  initReactI18next: { type: '3rdParty', init: vi.fn() },
}))
vi.mock('../../contexts', () => ({
  useNotification: () => notif,
  useAuth: () => ({ user: { id: 1, username: 'op' }, permissions: ['*'] }),
  useMobile: () => ({ isMobile: false, isTablet: false, isDesktop: true, isTouch: false, isLargeScreen: true, screenWidth: 1440, sidebarOpen: true, setSidebarOpen: vi.fn() }),
  useTheme: () => ({ theme: 'dark', setTheme: vi.fn(), resolvedTheme: 'dark', themes: ['light', 'dark'] }),
  useWindowManager: () => ({
    openWindow: vi.fn(), closeWindow: vi.fn(), windows: [],
    prefs: { sameWindow: true, closeOnNav: true }, updatePrefs: vi.fn(),
  }),
}))
vi.mock('../../contexts/MobileContext', () => ({ useMobile: () => ({ isMobile: false, isTablet: false }) }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => ({ permissions: ['*'] }) }))
vi.mock('../../hooks/useWebSocket', () => ({
  useWebSocket: () => ({ subscribe: vi.fn(() => vi.fn()), isConnected: false }),
  WebSocketProvider: ({ children }) => children,
  EventType: {}, ConnectionState: { DISCONNECTED: 'disconnected' },
}))
vi.mock('../../services', () => ({
  sshHostsService: pageService,
  sshCasService: {
    getAll: vi.fn().mockResolvedValue({ data: [
      { id: 10, descr: 'Lab Host CA', ca_type: 'host' },
      { id: 20, descr: 'Lab User CA', ca_type: 'user' },
    ] }),
  },
}))

import { sshHostsService } from '../../services/ssh-hosts.service'
import SSHHostsPage from '../SSHHostsPage'

const PUSH_WORDS = ['callback', 'wake', 'wait', 'notify_url', 'push']

async function renderHosts(hosts) {
  pageService.getAll.mockResolvedValue({ data: hosts, meta: { total: hosts.length } })
  render(<MemoryRouter><SSHHostsPage /></MemoryRouter>)
  await screen.findAllByText(/test.example.com/)
}

describe('ssh-hosts.service only ever calls UCM', () => {
  beforeEach(() => { calls.length = 0 })

  it('every method is one call to the admin API under /ssh/hosts', async () => {
    await sshHostsService.getAll({ search: 'web' })
    await sshHostsService.getById(1)
    await sshHostsService.create({ host_ca_id: 10, user_ca_id: 20, hostname: 'a.example.com' })
    await sshHostsService.setAutoRenew(1, false)
    await sshHostsService.revokeCert(1, 'key compromise')
    await sshHostsService.forceRenew(1)
    await sshHostsService.rotateToken(1)
    await sshHostsService.reissueBootstrap(1)
    await sshHostsService.delete(1)

    expect(calls.map(([method, url]) => [method, url])).toEqual([
      ['get', '/ssh/hosts?search=web'],
      ['get', '/ssh/hosts/1'],
      ['post', '/ssh/hosts'],
      ['patch', '/ssh/hosts/1'],
      ['post', '/ssh/hosts/1/revoke-cert'],
      ['post', '/ssh/hosts/1/force-renew'],
      ['post', '/ssh/hosts/1/rotate-token'],
      ['post', '/ssh/hosts/1/bootstrap'],
      ['delete', '/ssh/hosts/1'],
    ])   // apiClient prefixes '/api/v2'; nothing here leaves UCM
    const patched = calls.find(([m]) => m === 'patch')
    expect(patched[2]).toEqual({ auto_renew: false })          // D1: the switch sends the field
    const revoked = calls.find(([, url]) => url.endsWith('/revoke-cert'))
    expect(revoked[2]).toEqual({ reason: 'key compromise', revoke_certificate: false })
  })

  it('there is no wake, wait or callback method to call', () => {
    const names = Object.keys(sshHostsService)
    expect(names.sort()).toEqual(['create', 'delete', 'forceRenew', 'getAll', 'getById',
      'reissueBootstrap', 'revokeCert', 'rotateToken', 'setAutoRenew', 'update'])
    for (const name of names) {
      for (const word of PUSH_WORDS) {
        expect(name.toLowerCase()).not.toContain(word)
      }
    }
  })
})

describe('SSHHostsPage has no push UI', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    notif.showConfirm.mockResolvedValue(true)
  })

  it('no label, heading, placeholder or field asks for a callback URL', async () => {
    await renderHosts([hostFixture()])
    for (const word of PUSH_WORDS) {
      const hits = [...document.querySelectorAll('label, legend, th, button, input, h1, h2, h3, p')]
        .map((el) => `${el.textContent || ''} ${el.getAttribute('placeholder') || ''}`.toLowerCase())
        .filter((text) => text.includes(word))
      expect(hits).toEqual([])
    }
  })

  it('each icon-only row action has an accessible name on a real button', async () => {
    await renderHosts([hostFixture()])
    expect(screen.getByRole('button', { name: 'atelier.openDetail' })).toBeInTheDocument()
    const reinstallBtn = document.querySelector('button[title="sshHosts.reinstall"]')
    expect(reinstallBtn).not.toBeNull()
    expect(reinstallBtn.querySelector('svg')).not.toBeNull()
    const deleteBtn = document.querySelector('button[title="common.delete"]')
    expect(deleteBtn).not.toBeNull()
    expect(deleteBtn.querySelector('svg')).not.toBeNull()
  })

  it('a revoked host keeps delete, loses the actions that need a live certificate', async () => {
    await renderHosts([hostFixture({
      hostname: 'revoked.test.example.com', status: 'revoked', auto_renew: false,
      cert_status: 'revoked', has_token: false,
    })])
    expect(document.querySelector('button[title="sshHosts.reinstall"]')).toBeNull()
    expect(document.querySelector('button[title="common.delete"]')).not.toBeNull()
  })
})

describe('what the operator types is what the field keeps and what UCM receives', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    notif.showConfirm.mockResolvedValue(true)
  })

  it('every control in the connect wizard has an accessible name', async () => {
    await renderHosts([hostFixture()])
    fireEvent.click(screen.getByRole('button', { name: 'sshHosts.connect' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('combobox', { name: 'sshHosts.hostCaCol' })).toBeInTheDocument()
    expect(within(dialog).getByRole('combobox', { name: 'sshHosts.userCaCol' })).toBeInTheDocument()
    expect(within(dialog).getByRole('textbox', { name: 'sshHosts.hostnameLabel' })).toBeInTheDocument()
  })

  it('at least one CA is required and reported on the field, and the modal close is named', async () => {
    await renderHosts([hostFixture()])
    fireEvent.click(screen.getByRole('button', { name: 'sshHosts.connect' }))
    const dialog = await screen.findByRole('dialog')
    const hostCa = within(dialog).getByRole('combobox', { name: 'sshHosts.hostCaCol' })
    const userCa = within(dialog).getByRole('combobox', { name: 'sshHosts.userCaCol' })
    fireEvent.change(hostCa, { target: { value: '' } })
    fireEvent.change(userCa, { target: { value: '' } })
    expect(notif.showError).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'sshHosts.generateCommand' }))
    expect(within(dialog).getAllByText('sshHosts.caRequired').length).toBeGreaterThan(0)
    expect(hostCa).toHaveAttribute('aria-invalid', 'true')
  })

  it('the wizard hostname keeps the typed hostname', async () => {
    await renderHosts([hostFixture()])
    fireEvent.click(screen.getByRole('button', { name: 'sshHosts.connect' }))
    const box = await screen.findByRole('textbox')
    fireEvent.change(box, { target: { value: 'web02.test.example.com' } })
    expect(box.value).toBe('web02.test.example.com')
  })

  it('the revoke modal sends the typed reason', async () => {
    await renderHosts([hostFixture()])
    pageService.revokeCert.mockResolvedValue({ data: { host: hostFixture({ cert_status: 'revoked', status: 'revoked' }) } })
    fireEvent.click(screen.getByText('web01.test.example.com'))
    const detailDialog = await screen.findByRole('dialog')
    fireEvent.click(within(detailDialog).getByRole('button', { name: 'sshHosts.revokeHost' }))
    const dialogs = await screen.findAllByRole('dialog')
    const dialog = dialogs[dialogs.length - 1]
    const reason = within(dialog).getByRole('textbox')
    expect(reason.value).toBe('')
    fireEvent.change(reason, { target: { value: 'lab key rotated' } })
    expect(reason.value).toBe('lab key rotated')
    fireEvent.click(within(dialog).getByRole('button', { name: 'sshHosts.revokeHost' }))
    await waitFor(() => expect(pageService.revokeCert).toHaveBeenCalledWith(1, 'lab key rotated', false))
  })

  it('clicking a row opens the host modal showing CA settings, host identity, and agent sections', async () => {
    await renderHosts([hostFixture()])
    fireEvent.click(screen.getByText('web01.test.example.com'))
    expect(await screen.findByText('sshHosts.caSettingsTitle')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.hostIdentity')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.agentConnectivity')).toBeInTheDocument()
  })
})
