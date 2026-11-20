/**
 * Store a CA's certificate in the token slot that holds its signing key.
 *
 * The server refuses (409) when the slot already holds a different certificate,
 * carrying that certificate's summary in details.existing — the consent question
 * is asked here and the retry answers it with overwriteTokenCert.
 */
import { casService } from '../services'
import { extractData } from './utils'

// Only PKCS#11 tokens hold a certificate next to the key; cloud KMS keys do not.
export const holdsCertOnToken = (ca) => !!(ca?.uses_hsm && ca?.hsm_provider_type === 'pkcs11')

export async function uploadCertToToken({ ca, t, showSuccess, showError, showConfirm, overwrite = false }) {
  try {
    const result = extractData(await casService.uploadTokenCert(ca.id, overwrite ? { overwriteTokenCert: true } : {}))
    showSuccess(t(result?.already ? 'cas.tokenCertAlready' : 'cas.tokenCertUploaded'))
    return true
  } catch (err) {
    const existing = err?.status === 409 ? err.data?.details?.existing : null
    if (!existing) {
      showError(t('cas.tokenCertUploadFailed', { error: err?.message || err }))
      return false
    }
    const replace = await showConfirm(
      t('cas.tokenCertConflictConfirm', {
        subject: existing.subject,
        serial: existing.serial,
        notAfter: existing.not_after,
      }),
      { title: t('cas.updateTokenCert'), variant: 'danger' },
    )
    // overwrite is never refused twice: the retry cannot come back 409.
    return replace && uploadCertToToken({ ca, t, showSuccess, showError, showConfirm, overwrite: true })
  }
}
