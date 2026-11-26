/**
 * SSH Managed Hosts Service (pull-model automation, migration 138)
 */
import { apiClient } from './apiClient'

export const sshHostsService = {
  async getAll(params) {
    const query = new URLSearchParams(params).toString()
    return apiClient.get(`/ssh/hosts${query ? `?${query}` : ''}`)
  },

  async getById(id) {
    return apiClient.get(`/ssh/hosts/${id}`)
  },

  async create(data) {
    return apiClient.post('/ssh/hosts', data)
  },

  async setAutoRenew(id, autoRenew) {
    return apiClient.patch(`/ssh/hosts/${id}`, { auto_renew: autoRenew })
  },

  async update(id, data) {
    return apiClient.patch(`/ssh/hosts/${id}`, data)
  },

  async revokeCert(id, reason, revokeCertificate = false) {
    return apiClient.post(`/ssh/hosts/${id}/revoke-cert`, {
      reason,
      revoke_certificate: revokeCertificate,
    })
  },

  async forceRenew(id) {
    return apiClient.post(`/ssh/hosts/${id}/force-renew`, {})
  },

  async rotateToken(id) {
    return apiClient.post(`/ssh/hosts/${id}/rotate-token`, {})
  },

  async reissueBootstrap(id) {
    return apiClient.post(`/ssh/hosts/${id}/bootstrap`, {})
  },

  async delete(id) {
    return apiClient.delete(`/ssh/hosts/${id}`)
  }
}
