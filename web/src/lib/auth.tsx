import { createContext, useContext, useEffect, useState } from 'react'

export type AuthUser = {
  id: string
  login: string
  displayName?: string | null
  email?: string | null
  avatarUrl?: string | null
  isAdmin: boolean
}

type AuthStatus = 'loading' | 'authed' | 'anon'

type AuthContextValue = {
  user: AuthUser | null
  status: AuthStatus
  signIn: (returnUrl?: string) => void
  signOut: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [status, setStatus] = useState<AuthStatus>('loading')

  useEffect(() => {
    fetch('/auth/me', { credentials: 'same-origin' })
      .then(r => r.ok ? r.json() : null)
      .then((u: AuthUser | null) => {
        setUser(u)
        setStatus(u ? 'authed' : 'anon')
      })
      .catch(() => {
        setUser(null)
        setStatus('anon')
      })
  }, [])

  const signIn = (returnUrl?: string) => {
    // Full-page nav (not fetch) — OAuth is a redirect dance, not an XHR.
    const ret = returnUrl ?? window.location.pathname + window.location.search
    window.location.href = `/auth/login/github?returnUrl=${encodeURIComponent(ret)}`
  }

  const signOut = async () => {
    await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' })
    setUser(null)
    setStatus('anon')
  }

  return (
    <AuthContext.Provider value={{ user, status, signIn, signOut }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
