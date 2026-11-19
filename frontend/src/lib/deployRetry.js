/**
 * The wait a pending delivery has left, spelled the same way in every deployment
 * block (CRL, SSH CA): "3m 05s" or "42s", empty when the time is not a time.
 */
export function retryCountdown(nextAttemptAt, now) {
  const milliseconds = new Date(nextAttemptAt).getTime() - now
  if (!Number.isFinite(milliseconds)) return ''
  const seconds = Math.max(0, Math.ceil(milliseconds / 1000))
  const minutes = Math.floor(seconds / 60)
  const remainingSeconds = seconds % 60
  return minutes > 0 ? `${minutes}m ${String(remainingSeconds).padStart(2, '0')}s` : `${seconds}s`
}
