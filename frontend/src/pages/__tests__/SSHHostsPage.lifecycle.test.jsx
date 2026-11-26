/**
 * SSHHostsPage — managed-host table behaviour.
 *
 * The page is the operator's only view of the pull-model fleet (migration 138):
 * certificate badges (valid/expiring/revoked), agent health from last_seen_at,
 * the auto-renew switch (the guard the agent's /renew obeys), and delete —
 * whose guard rail lives server-side, so the refusal must surface verbatim.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const authState = vi.hoisted(() => ({ permissions: ['*'] }))

const recent = new Date(Date.now() - 60 * 1000).toISOString()
const stale = new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString()

function hostFixture(over = {}) {
  return {
    id: 1,
    hostname: 'web01.test.example.com',
    host_ca_id: 10, host_ca_name: 'Lab Host CA',
    user_ca_id: 20, user_ca_name: 'Lab User CA',
    token_prefix: 'ucm_sh_abcd', principals: ['web01.test.example.com'],
    public_key: 'ssh-ed25519 AAAA...',
    auto_renew: true, status: 'active',
    cert_id: 5, cert_serial: 5, cert_status: 'expiring',
    cert_valid_to: '2026-11-30T00:00:00',
    has_token: true, bootstrap_active: false,
    last_seen_at: recent, last_krl_sync_at: recent, last_renew_at: recent,
    last_ip: '10.0.0.5', created_at: '2026-11-01T00:00:00',
    ...over,
  }
}

const notif = vi.hoisted(() => ({
  showSuccess: vi.fn(), showError: vi.fn(),
  showConfirm: vi.fn().mockResolvedValue(true), showPrompt: vi.fn(),
}))

// Stable identity for `t`: SSHHostsPage's load() lists `t` in its deps — a
// fresh function per useTranslation() call re-triggers the effect every
// render and the table stays in Loading forever.
const translate = vi.hoisted(() => (key) => key)
const i18nRef = vi.hoisted(() => ({ language: 'en', changeLanguage: vi.fn(), on: vi.fn(), off: vi.fn() }))

const hostsService = vi.hoisted(() => ({
  getAll: vi.fn(), getById: vi.fn(), create: vi.fn(), setAutoRenew: vi.fn(),
  revokeCert: vi.fn(), forceRenew: vi.fn(), rotateToken: vi.fn(),
  reissueBootstrap: vi.fn(), delete: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: translate, i18n: i18nRef }),
  Trans: ({ children }) => children,
  initReactI18next: { type: '3rdParty', init: vi.fn() },
}))

vi.mock('../../contexts', () => ({
  useNotification: () => notif,
  useAuth: () => ({ user: { id: 1, username: 'op' }, permissions: authState.permissions }),
  useMobile: () => ({ isMobile: false, isTablet: false, isDesktop: true, isTouch: false, isLargeScreen: true, screenWidth: 1440, sidebarOpen: true, setSidebarOpen: vi.fn() }),
  useTheme: () => ({ theme: 'dark', setTheme: vi.fn(), resolvedTheme: 'dark', themes: ['light', 'dark'] }),
  useWindowManager: () => ({
    openWindow: vi.fn(), closeWindow: vi.fn(), windows: [],
    prefs: { sameWindow: true, closeOnNav: true }, updatePrefs: vi.fn(),
  }),
}))

vi.mock('../../contexts/MobileContext', () => ({
  useMobile: () => ({ isMobile: false, isTablet: false }),
}))

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ permissions: authState.permissions }),
}))

vi.mock('../../hooks/useWebSocket', () => ({
  useWebSocket: () => ({ subscribe: vi.fn(() => vi.fn()), isConnected: false }),
  WebSocketProvider: ({ children }) => children,
  EventType: {},
  ConnectionState: { DISCONNECTED: 'disconnected' },
}))

vi.mock('../../services', () => ({
  sshHostsService: hostsService,
  sshCasService: {
    getAll: vi.fn().mockResolvedValue({ data: [
      { id: 10, descr: 'Lab Host CA', ca_type: 'host' },
      { id: 20, descr: 'Lab User CA', ca_type: 'user' },
    ] }),
  },
}))

import SSHHostsPage from '../SSHHostsPage'

async function renderHosts(hosts) {
  hostsService.getAll.mockResolvedValue({ data: hosts, meta: { total: hosts.length } })
  render(<MemoryRouter><SSHHostsPage /></MemoryRouter>)
  await screen.findAllByText(/test.example.com/)
}

describe('SSHHostsPage table', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    notif.showConfirm.mockResolvedValue(true)
    authState.permissions = ['*']
  })

  it('shows the certificate status badges', async () => {
    await renderHosts([
      hostFixture({ id: 1, hostname: 'valid.test.example.com', cert_status: 'valid' }),
      hostFixture({ id: 2, hostname: 'expiring.test.example.com', cert_status: 'expiring' }),
      hostFixture({ id: 3, hostname: 'revoked.test.example.com', cert_status: 'revoked', status: 'revoked', auto_renew: false, has_token: false }),
      hostFixture({ id: 4, hostname: 'pending.test.example.com', cert_status: null, status: 'pending', cert_id: null, cert_serial: null, cert_valid_to: null }),
    ])
    expect(await screen.findByText('sshHosts.certValid')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.certExpiring')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.certRevoked')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.certNone')).toBeInTheDocument()
  })

  it('derives agent health from the last check-in', async () => {
    await renderHosts([
      hostFixture({ id: 1, hostname: 'online.test.example.com', last_seen_at: recent }),
      hostFixture({ id: 2, hostname: 'offline.test.example.com', last_seen_at: stale }),
      hostFixture({ id: 3, hostname: 'never.test.example.com', last_seen_at: null }),
      hostFixture({ id: 4, hostname: 'blocked.test.example.com', status: 'revoked', auto_renew: false, last_seen_at: recent }),
    ])
    expect(await screen.findByText('sshHosts.agentOnline')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.agentOffline')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.agentNever')).toBeInTheDocument()
    expect(screen.getByText('sshHosts.agentBlocked')).toBeInTheDocument()
  })

  it('the auto-renew switch PATCHes the host and flips the row', async () => {
    const host = hostFixture()
    hostsService.setAutoRenew.mockResolvedValue({ data: { ...host, auto_renew: false } })
    await renderHosts([host])

    const toggle = screen.getByRole('switch', { name: 'sshHosts.autoRenewCol' })
    fireEvent.click(toggle)
    await waitFor(() => expect(hostsService.setAutoRenew).toHaveBeenCalledWith(1, false))
    expect(toggle).toHaveAttribute('aria-checked', 'false')
  })

  it('leaves the switch disabled for a revoked host', async () => {
    await renderHosts([hostFixture({
      hostname: 'revoked.test.example.com', status: 'revoked', auto_renew: false,
      cert_status: 'revoked', has_token: false,
    })])
    const toggle = screen.getByRole('switch', { name: 'sshHosts.autoRenewCol' })
    expect(toggle.disabled).toBe(true)
    expect(hostsService.setAutoRenew).not.toHaveBeenCalled()
  })

  it('surfaces the delete guard rail refusal from the backend', async () => {
    const host = hostFixture({ status: 'revoked' })
    const guardMessage = 'Cannot delete a managed host while auto-renew is on and its '
      + 'certificate is valid: turn auto-renew off first, or revoke the certificate.'
    hostsService.delete.mockRejectedValue(new Error(guardMessage))
    await renderHosts([host])

    fireEvent.click(screen.getByTitle('common.delete'))
    await waitFor(() => expect(notif.showConfirm).toHaveBeenCalled())
    await waitFor(() => expect(notif.showError).toHaveBeenCalledWith(guardMessage))
    // the host must stay on the table — a refused delete changes nothing
    expect(screen.getByText('web01.test.example.com')).toBeInTheDocument()
  })

  it('removes the row when the delete is allowed', async () => {
    hostsService.delete.mockResolvedValue({})
    await renderHosts([hostFixture({ status: 'revoked' })])
    fireEvent.click(screen.getByTitle('common.delete'))
    await waitFor(() => expect(hostsService.delete).toHaveBeenCalledWith(1))
    await waitFor(() => expect(screen.queryByText('web01.test.example.com')).not.toBeInTheDocument())
  })
})
