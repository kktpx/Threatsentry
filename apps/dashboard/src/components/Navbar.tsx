import { Shield, Cpu, LogOut, Home } from 'lucide-react'
import { useAuth } from '../features/auth/authState'
import { Link, useLocation } from 'react-router'

export function Navbar() {
  const location = useLocation()
  const currentPath = location.pathname

  let signOut = async () => {}
  let userEmail: string | null = null
  try {
    const auth = useAuth()
    signOut = auth.signOut
    userEmail = auth.session?.user?.email || null
  } catch {
    // Gracefully handle rendering in tests without AuthProvider
  }

  const isActive = (path: string) => currentPath === path

  return (
    <nav className="sticky top-0 z-50 flex items-center justify-between px-6 md:px-12 h-16 bg-[var(--bg)]/80 backdrop-blur-md border-b border-[var(--border)]">
      <div className="flex items-center gap-8">
        <Link to="/dashboard" className="flex items-center gap-2.5 text-inherit no-underline font-sans font-bold text-lg tracking-tight text-[var(--text)]">
          <Shield className="w-5 h-5 text-[var(--accent)]" />
          <span>ThreatSentry</span>
        </Link>

        <div className="hidden md:flex items-center gap-6 list-none m-0 p-0">
          <Link
            to="/"
            className={`text-sm font-medium transition-colors no-underline flex items-center gap-1.5 ${
              isActive('/')
                ? 'text-[var(--text)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text)]'
            }`}
          >
            <Home className="w-3.5 h-3.5" />
            <span>Home</span>
          </Link>
          <Link
            to="/dashboard"
            className={`text-sm font-medium transition-colors no-underline ${
              isActive('/dashboard')
                ? 'text-[var(--text)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text)]'
            }`}
          >
            Dashboard
          </Link>
          <Link
            to="/websites/new"
            className={`text-sm font-medium transition-colors no-underline ${
              isActive('/websites/new')
                ? 'text-[var(--text)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text)]'
            }`}
          >
            <span>Targets</span>
          </Link>
          <Link
            to="/model"
            className={`text-sm font-medium transition-colors no-underline flex items-center gap-1.5 ${
              isActive('/model')
                ? 'text-[var(--text)]'
                : 'text-[var(--text-secondary)] hover:text-[var(--text)]'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>ML Intelligence</span>
          </Link>
        </div>
      </div>

      <div className="flex items-center gap-4">

        {userEmail && (
          <span className="hidden lg:inline-block text-xs font-mono text-[var(--text-muted)] tracking-tight">
            {userEmail}
          </span>
        )}
        <button
          type="button"
          onClick={() => void signOut()}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium text-[var(--text-secondary)] hover:text-[var(--text)] border border-[var(--border)] hover:border-[var(--border-hover)] bg-[var(--surface)] transition-all cursor-pointer font-sans"
        >
          <LogOut className="w-3.5 h-3.5" />
          <span className="hidden sm:inline-block">Sign out</span>
        </button>
      </div>
    </nav>
  )
}
