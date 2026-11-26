/**
 * ssh-hosts.service payload contract.
 *
 * The backend PATCH /api/v2/ssh/hosts/<id> requires the JSON key `auto_renew`
 * (snake_case). Fixed 2026-11-21 (defect D1): the service sent camelCase
 * `autoRenew` and every UI switch answered 400. The payload is pinned here so
 * neither side can drift back silently.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'

const api = vi.hoisted(() => ({
  get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn(),
}))

vi.mock('../apiClient', () => ({ apiClient: api }))

import { sshHostsService } from '../ssh-hosts.service'

describe('sshHostsService request payloads', () => {
  beforeEach(() => vi.clearAllMocks())

  it('lists through GET /ssh/hosts', async () => {
    api.get.mockResolvedValue({ data: [] })
    await sshHostsService.getAll({ search: 'web' })
    expect(api.get).toHaveBeenCalledWith('/ssh/hosts?search=web')
  })

  it('PATCHes the auto-renew switch to /ssh/hosts/<id>', async () => {
    api.patch.mockResolvedValue({ data: {} })
    await sshHostsService.setAutoRenew(7, false)
    expect(api.patch).toHaveBeenCalledWith('/ssh/hosts/7', { auto_renew: false })
  })

  it('revokes through POST /ssh/hosts/<id>/revoke-cert', async () => {
    api.post.mockResolvedValue({ data: {} })
    await sshHostsService.revokeCert(7, 'key compromise', false)
    expect(api.post).toHaveBeenCalledWith('/ssh/hosts/7/revoke-cert', {
      reason: 'key compromise',
      revoke_certificate: false,
    })
  })

  it('revokes host and certificate through POST /ssh/hosts/<id>/revoke-cert with revoke_certificate=true', async () => {
    api.post.mockResolvedValue({ data: {} })
    await sshHostsService.revokeCert(7, 'key compromise', true)
    expect(api.post).toHaveBeenCalledWith('/ssh/hosts/7/revoke-cert', {
      reason: 'key compromise',
      revoke_certificate: true,
    })
  })
})
