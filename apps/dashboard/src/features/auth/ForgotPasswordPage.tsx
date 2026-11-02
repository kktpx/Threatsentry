import { FormEvent, useState } from 'react'
import { Link } from 'react-router'
import { Shield } from 'lucide-react'
import { supabase } from '../../lib/supabase'

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [sent, setSent] = useState(false)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const { error: resetError } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/reset-password`,
      })
      if (resetError) throw resetError
      setSent(true)
    } catch (err: any) {
      setError(err.message || 'Failed to send reset email')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col justify-center px-6 bg-[var(--bg)]">
      <div className="w-full max-w-sm mx-auto">
        <Link to="/" className="flex items-center justify-center gap-2.5 mb-10 text-inherit no-underline font-sans font-bold text-2xl tracking-tight text-[var(--text)]">
          <Shield className="w-8 h-8 text-[var(--accent)]" />
          <span>ThreatSentry</span>
        </Link>

        <h1 className="text-2xl font-bold text-[var(--text)] tracking-tight mb-2">Reset your password</h1>
        <p className="text-sm text-[var(--text-secondary)] mb-8">
          Enter your account email and we will send you a reset link.
        </p>

        {sent ? (
          <div role="status" className="p-3 text-sm rounded bg-[var(--accent)]/10 text-[var(--text)] border border-[var(--accent)]/20">
            If an account exists for {email}, a reset link is on its way.
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-xs font-semibold uppercase text-[var(--text-secondary)] mb-1.5" htmlFor="email">
                Email
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder="you@example.com"
                className="w-full bg-[var(--surface-2)] border border-[var(--border)] focus:border-[var(--accent)] rounded-lg p-3 text-sm text-[var(--text)] outline-none transition-colors"
              />
            </div>
            {error && (
              <div role="alert" className="p-3 text-sm rounded bg-[var(--danger)]/10 text-[var(--danger)] border border-[var(--danger)]/20">
                {error}
              </div>
            )}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-4 bg-[var(--text)] text-[var(--bg)] hover:bg-[var(--text-secondary)] rounded-lg font-semibold text-sm transition-colors cursor-pointer"
            >
              {loading ? 'Sending...' : 'Send reset link'}
            </button>
          </form>
        )}

        <p className="mt-8 text-center text-sm text-[var(--text-secondary)]">
          <Link to="/login" className="font-semibold text-[var(--text)] hover:text-[var(--accent)] transition-colors no-underline">
            Back to sign in
          </Link>
        </p>
      </div>
    </div>
  )
}
