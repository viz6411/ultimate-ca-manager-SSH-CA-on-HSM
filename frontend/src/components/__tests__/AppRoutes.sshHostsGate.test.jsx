/**
 * /ssh/hosts is gated by read:ssh_cas — the same scope as the SSH CA pages.
 * A key that can sign SSH certificates (write:ssh) must not see the managed
 * host registry; holding read:ssh_cas (or the admin wildcard) must mount it.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'

const auth = vi.hoisted(() => ({ value: {} }))

vi.mock('../../contexts', () => ({
  useAuth: () => auth.value,
  AuthProvider: ({ children }) => children,
  ThemeProvider: ({ children }) => children,
  NotificationProvider: ({ children }) => children,
  MobileProvider: ({ children }) => children,
  WindowManagerProvider: ({ children }) => children,
}))
vi.mock('../../hooks/useWebSocket', () => ({ WebSocketProvider: ({ children }) => children }))
vi.mock('../../contexts/InspectorContext', () => ({
  InspectorProvider: ({ children }) => children,
  useInspector: () => ({ close: vi.fn() }),
}))
vi.mock('../../components', async () => {
  const { Outlet } = await vi.importActual('react-router-dom')
  return {
    AppShell: () => <div>app-shell<Outlet /></div>,
    ErrorBoundary: ({ children }) => children,
    LoadingSpinner: () => null,
    SessionWarning: () => null,
    ForcePasswordChange: () => null,
    ForceEnroll2FA: () => null,
    SafeModeOverlay: () => null,
    DetailWindowLayer: () => null,
    InspectorCloseOnNavigate: () => null,
  }
})
vi.mock('../../navigation/pages', async () => {
  const actual = await vi.importActual('../../navigation/pages')
  return {
    ...actual,
    pages: {
      ...actual.pages,
      dashboard: () => <div>dashboard-page</div>,
      'ssh-hosts': () => <div>ssh-hosts-page</div>,
    },
  }
})

import { AppRoutes } from '../../App'

function Where() {
  return <div data-testid="where">{useLocation().pathname}</div>
}

function renderAt(path, permissions) {
  auth.value = {
    isAuthenticated: true, loading: false, sessionChecked: true, permissions,
  }
  return render(<MemoryRouter initialEntries={[path]}><AppRoutes /><Where /></MemoryRouter>)
}

describe('AppRoutes gate for /ssh/hosts', () => {
  it('mounts the page for read:ssh_cas', async () => {
    renderAt('/ssh/hosts', ['read:ssh_cas'])
    expect(await screen.findByText('ssh-hosts-page')).toBeTruthy()
  })

  it('mounts it for the admin wildcard', async () => {
    renderAt('/ssh/hosts', ['*'])
    expect(await screen.findByText('ssh-hosts-page')).toBeTruthy()
  })

  it('bounces a certificate operator (read:ssh only) to the dashboard', async () => {
    renderAt('/ssh/hosts', ['read:ssh', 'write:ssh'])
    expect(await screen.findByText('dashboard-page')).toBeTruthy()
    expect(screen.queryByText('ssh-hosts-page')).toBeNull()
    expect((await screen.findByTestId('where')).textContent).toBe('/')
  })
})
