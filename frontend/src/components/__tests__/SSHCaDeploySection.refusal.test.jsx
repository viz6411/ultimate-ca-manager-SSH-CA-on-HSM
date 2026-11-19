/**
 * What a refusal looks like in the SSH CA deploy dialog.
 *
 * The server answers RFC 7807 with `details.fields`, and the section puts each one back on the
 * field it concerns: `host_key` is renamed onto the paste box it can be answered with, a 409
 * without any fields names the target select, and the first field in the form's own order gets
 * focus. A value UCM has no wording for is shown as the server said it, verbatim.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const mocks = vi.hoisted(() => ({
  getSSHBindings: vi.fn(),
  getTargets: vi.fn(),
  createSSHBinding: vi.fn(),
  updateSSHBinding: vi.fn(),
  t: vi.fn((key) => key),
  hasPermission: vi.fn(() => true),
  showSuccess: vi.fn(),
  showError: vi.fn(),
  showConfirm: vi.fn(),
}))

// Only this one has a wording in the test; the others stay untranslated, which is what the
// fallback to the server's own sentence is for.
const TRANSLATED = { 'sshDeploy.errors.reloadChained': 'one command only' }

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: mocks.t }),
}))

vi.mock('../../contexts', () => ({
  useNotification: () => ({
    showSuccess: mocks.showSuccess,
    showError: mocks.showError,
    showConfirm: mocks.showConfirm,
  }),
}))

vi.mock('../../hooks', () => ({
  usePermission: () => ({ hasPermission: mocks.hasPermission }),
}))

vi.mock('../../services', () => ({ deployService: mocks }))

vi.mock('../index', () => ({
  Badge: ({ children }) => <span>{children}</span>,
  Button: ({ children, loading: _loading, ...props }) => <button {...props}>{children}</button>,
  CompactSection: ({ title, children }) => <section aria-label={title}>{children}</section>,
  Input: ({ id, label, error, mono: _mono, helperText, ...props }) => (
    <div>
      <label htmlFor={id}>{label}</label>
      <input id={id} aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${id}-error` : undefined} {...props} />
      {error && <p id={`${id}-error`} role="status">{error}</p>}
      {helperText && <p>{helperText}</p>}
    </div>
  ),
  Textarea: ({ id, label, error, mono: _mono, helperText, rows: _rows, ...props }) => (
    <div>
      <label htmlFor={id}>{label}</label>
      <textarea id={id} aria-invalid={error ? true : undefined} {...props} />
      {error && <p role="status">{error}</p>}
    </div>
  ),
}))

vi.mock('../ui/TagsInput', () => ({
  __esModule: true,
  default: ({ id, label, error, validate: _validate, helperText: _helper, ...props }) => (
    <div>
      <label htmlFor={id}>{label}</label>
      <input id={id} {...props} />
      {error && <p role="status">{error}</p>}
    </div>
  ),
}))

vi.mock('../Modal', () => ({
  Modal: ({ open, children }) => (open ? <div role="dialog">{children}</div> : null),
}))

import { SSHCaDeploySection } from '../deploy/SSHCaDeploySection'

const HOST_CA = { id: 4, descr: 'host fleet', ca_type: 'host', default_ttl: 86400, max_ttl: 604800 }
const DEFAULTS = {
  ca_pub_path: '/etc/ssh/ucm_hosts.pub',
  krl_path: '/etc/ssh/ucm_hosts.krl',
  host_cert_path: '/etc/ssh/web01_host_cert.pub',
}
const TARGETS = [{
  id: 7, name: 'web01', host: 'web01.example.test', username: 'ucm-deploy', port: 22,
  kind: 'ssh', enabled: true,
}]

const refusal = (fields, status = 422) => Object.assign(new Error('Refused'), {
  data: { status, title: 'Unprocessable Entity', details: { fields } },
})

async function openDialog() {
  render(<SSHCaDeploySection ca={HOST_CA} />)
  fireEvent.click(await screen.findByText('deploy.attachTarget'))
  await screen.findByRole('dialog')
  fireEvent.change(screen.getByRole('combobox'), { target: { value: '7' } })
}

describe('SSHCaDeploySection refusals', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.t.mockImplementation((key) => TRANSLATED[key] ?? key)
    mocks.hasPermission.mockImplementation(() => true)
    mocks.getSSHBindings.mockResolvedValue({ data: { ca: { deploy_defaults: DEFAULTS }, bindings: [] } })
    mocks.getTargets.mockResolvedValue({ data: TARGETS })
    mocks.createSSHBinding.mockResolvedValue({ data: { id: 1 } })
  })

  it('names the reload command field for a chained command, in the CA\'s own words', async () => {
    mocks.createSSHBinding.mockRejectedValue(refusal({
      reload_command: {
        message: 'reload_command is one command; chaining is refused',
        i18n_key: 'sshDeploy.errors.reloadChained',
        values: { command: 'systemctl reload sshd && systemctl status sshd' },
      },
    }))
    await openDialog()
    fireEvent.submit(document.querySelector('form'))

    expect(await screen.findByText('one command only')).toBeInTheDocument()
    expect(mocks.t).toHaveBeenCalledWith(
      'sshDeploy.errors.reloadChained', { command: 'systemctl reload sshd && systemctl status sshd' })
    expect(document.getElementById('ssh-deploy-reload_command')).toHaveAttribute('aria-invalid', 'true')
    expect(document.activeElement).toBe(document.getElementById('ssh-deploy-reload_command'))
    expect(mocks.showError).not.toHaveBeenCalled()
  })

  it('shows the server\'s own sentence when there is no wording for the key', async () => {
    mocks.createSSHBinding.mockRejectedValue(refusal({
      krl_path: { message: 'krl_path must be an absolute path', i18n_key: 'sshDeploy.errors.notAbsolute' },
    }))
    await openDialog()
    fireEvent.submit(document.querySelector('form'))

    expect(await screen.findByText('krl_path must be an absolute path')).toBeInTheDocument()
  })

  it('opens the host key paste box for a probe failure about the host key', async () => {
    mocks.createSSHBinding.mockRejectedValue(refusal({
      host_key: {
        message: 'sshd -g refused to print the host key of web01.example.test',
        i18n_key: 'sshDeploy.errors.hostKeyProbe',
      },
    }))
    await openDialog()
    expect(document.getElementById('ssh-deploy-host_public_key')).toBeNull()

    fireEvent.submit(document.querySelector('form'))
    const box = await screen.findByText(
      'sshd -g refused to print the host key of web01.example.test')
    expect(screen.getByLabelText('sshDeploy.hostKeyLabel')).toBeInTheDocument()
    expect(document.getElementById('ssh-deploy-host_public_key'))
      .toHaveAttribute('aria-invalid', 'true')
    expect(box).toBeInTheDocument()
  })

  it('says the target is already attached when a 409 names no field', async () => {
    mocks.createSSHBinding.mockRejectedValue(Object.assign(new Error('Conflict'), {
      data: { status: 409, title: 'Conflict' },
    }))
    await openDialog()
    fireEvent.submit(document.querySelector('form'))

    expect(await screen.findByText('sshDeploy.errors.targetTaken')).toBeInTheDocument()
    expect(document.getElementById('ssh-deploy-target_id')).toHaveAttribute('aria-invalid', 'true')
    expect(mocks.showError).not.toHaveBeenCalled()
  })

  it('renders nothing for someone who cannot read deployments', async () => {
    mocks.hasPermission.mockImplementation((permission) => permission !== 'read:deploy')
    const { container } = render(<SSHCaDeploySection ca={HOST_CA} />)

    expect(container).toBeEmptyDOMElement()
    expect(mocks.getSSHBindings).not.toHaveBeenCalled()
  })

  it('keeps the retry countdown out of a live region', async () => {
    mocks.getSSHBindings.mockResolvedValue({ data: { ca: { deploy_defaults: DEFAULTS }, bindings: [{
      id: 9, target_id: 7, target_name: 'web01', target_host: 'web01.example.test',
      target_enabled: true, enabled: true, ca_pub_path: DEFAULTS.ca_pub_path,
      krl_path: DEFAULTS.krl_path, host_cert_path: null, principals: [],
      reload_command: 'systemctl reload sshd',
      last_delivery: {
        id: 11, status: 'pending', last_error: 'sshd reload exited 1', attempts: 2, max_attempts: 5,
        next_attempt_at: new Date(Date.now() + 65000).toISOString(),
      },
    }] } })
    render(<SSHCaDeploySection ca={HOST_CA} />)

    expect(await screen.findByText('deploy.status.pending')).toBeInTheDocument()
    const countdown = screen.getByText('deploy.nextRetry')
    expect(countdown).not.toHaveAttribute('role')
    expect(mocks.t).toHaveBeenCalledWith('deploy.nextRetry', expect.objectContaining({
      date: expect.any(String), countdown: expect.stringMatching(/^\d/),
    }))
  })
})
