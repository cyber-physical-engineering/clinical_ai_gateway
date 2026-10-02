'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'

type Theme = 'light' | 'dark'

interface ThemeContextValue {
  theme: Theme
  toggleTheme: () => void
  mounted: boolean
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined)

export function ThemeProvider({ children }: { children: ReactNode }) {
  // Use consistent default for SSR - actual theme loaded after mount
  const [theme, setTheme] = useState<Theme>('dark')
  const [mounted, setMounted] = useState(false)

  // Read actual theme from localStorage/DOM after mount to avoid hydration mismatch
  useEffect(() => {
    const savedTheme = localStorage.getItem('gateway-theme') as Theme | null
    if (savedTheme) {
      setTheme(savedTheme)
    } else if (document.documentElement.classList.contains('light')) {
      setTheme('light')
    }
    setMounted(true)
  }, [])

  // Sync to DOM and localStorage when theme changes (only after mount)
  useEffect(() => {
    if (!mounted) return
    const root = document.documentElement
    root.classList.remove('light', 'dark')
    root.classList.add(theme)
    localStorage.setItem('gateway-theme', theme)
  }, [theme, mounted])

  const toggleTheme = () => setTheme(t => t === 'dark' ? 'light' : 'dark')

  // ⚠️ CRITICAL: Always render children. Never return null!
  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, mounted }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider')
  return ctx
}

