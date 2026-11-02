import { FormEvent, useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Shield } from 'lucide-react'
import { supabase } from '../../lib/supabase'

const MIN_PASSWORD_LENGTH = 8

export function ResetPasswordPage() {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [hasRecoverySession, setHasRecoverySession] = useState<boolean | null>(null)
  const navigate = useNavigate()

  useEffect(() => {
    // Supabase exchanges the emailed link for a temporary session on load.
    const { data } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === 'PASSWORD_RECOVERY' || session) setHasRecoverySession(true)
    })
    void supabase.auth.getSession().then(({ data: { session } }) => {
      setHasRecoverySession((current) => current ?? !!session)
    })
    return () => data.subscription.unsubscribe()
  }, [])

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setError(null)
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match')
      return
    }
    setLoading(true)
    try {
      const { error: updateError } = await supabase.auth.updateUser({ password })
      if (updateError) throw updateError
      navigate('/dashboard', { replace: true })
    } catch (err: any) {
      setError(err.message || 'Failed to update password')
    } finally {
      setLoading(false)
    }
  }

  const fields = [
    { id: 'password', label: 'New password', value: password, set: setPassword },
    { id: 'confirm', label: 'Confirm password', value: confirm, set: setConfirm },
  ]

  return (
    <div className="min-h-screen flex flex-col justify-center px-6 bg-[var(--bg)]">
      <div className="w-full max-w-sm mx-auto">
        <Link to="/" className="flex items-center justify-center gap-2.5 mb-10 text-inherit no-underline font-sans font-bold text-2xl tracking-tight text-[var(--text)]">
          <Shield className="w-8 h-8 text-[var(--accent)]" />
          <span>ThreatSentry</span>
        </Link>

        <h1 className="text-2xl font-bold text-[var(--text)] tracking-tight mb-2">Choose a new password</h1>

        {hasRecoverySession === false ? (
          <div role="alert" className="mt-6 p-3 text-sm rounded bg-[var(--danger)]/10 text-[var(--danger)] border border-[var(--danger)]/20">
            This reset link is invalid or has expired.{' '}
            <Link to="/forgot-password" className="underline">Request a new one</Link>.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5 mt-8">
            {fields.map((field) => (
              <div key={field.id}>
                <label className="block text-xs font-semibold uppercase text-[var(--text-secondary)] mb-1.5" htmlFor={field.id}>
                  {field.label}
                </label>
                <input
                  id={field.id}
                  type="password"
                  value={field.value}
                  onChange={(e) => field.set(e.target.value)}
                  required
                  className="w-full bg-[var(--surface-2)] border border-[var(--border)] focus:border-[var(--accent)] rounded-lg p-3 text-sm text-[var(--text)] outline-none transition-colors"
                />
              </div>
            ))}
            {error && (
              <div role="alert" className="p-3 text-sm rounded bg-[var(--danger)]/10 text-[var(--danger)] border border-[var(--danger)]/20">
                {error}
              </div>
            )}
            <button
              type="submit"
              disabled={loading || hasRecoverySession === null}
              className="w-full py-3 px-4 bg-[var(--text)] text-[var(--bg)] hover:bg-[var(--text-secondary)] rounded-lg font-semibold text-sm transition-colors cursor-pointer"
            >
              {loading ? 'Updating...' : 'Update password'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
