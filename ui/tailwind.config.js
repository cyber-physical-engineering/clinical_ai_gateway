/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Gateway colors - themeable via CSS variables
        'gateway-bg': 'rgb(var(--gateway-bg) / <alpha-value>)',
        'gateway-panel': 'rgb(var(--gateway-panel) / <alpha-value>)',
        'gateway-border': 'rgb(var(--gateway-border) / <alpha-value>)',
        'gateway-accent': 'rgb(var(--gateway-accent) / <alpha-value>)',
        
        'gateway-fg': 'rgb(var(--gateway-fg) / <alpha-value>)',
        'gateway-muted': 'rgb(var(--gateway-muted) / <alpha-value>)',
        'gateway-muted2': 'rgb(var(--gateway-muted2) / <alpha-value>)',
        'gateway-pre': 'rgb(var(--gateway-pre) / <alpha-value>)',
        
        // Semantic Status Colors (Adaptive)
        'status-warning': 'rgb(var(--status-warning) / <alpha-value>)',
        'status-warning-muted': 'rgb(var(--status-warning-muted) / <alpha-value>)',
        'status-success': 'rgb(var(--status-success) / <alpha-value>)',
        'status-success-muted': 'rgb(var(--status-success-muted) / <alpha-value>)',
        'status-danger': 'rgb(var(--status-danger) / <alpha-value>)',
        'status-info': 'rgb(var(--status-info) / <alpha-value>)',
        
        // Backgrounds (Adaptive)
        'status-warning-bg': 'rgb(var(--status-warning-bg) / <alpha-value>)',
        'status-success-bg': 'rgb(var(--status-success-bg) / <alpha-value>)',
        'status-danger-bg': 'rgb(var(--status-danger-bg) / <alpha-value>)',
        
        // Status colors - fixed (Legacy/Fallback)
        'gateway-green': '#10b981',   // emerald-500
        'gateway-yellow': '#f59e0b',  // amber-500
        'gateway-red': '#ef4444',     // red-500
      },
      fontFamily: {
        sans: ['Geist Sans', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['Geist Mono', 'SF Mono', 'Consolas', 'monospace'],
      },
      spacing: {
        // Consistent spacing scale
        'xs': '0.5rem',   // 8px
        'sm': '0.75rem',  // 12px
        'md': '1rem',     // 16px
        'lg': '1.5rem',   // 24px
        'xl': '2rem',     // 32px
        '2xl': '3rem',    // 48px
      },
      borderRadius: {
        'sm': '0.5rem',   // 8px
        'md': '0.75rem',  // 12px
        'lg': '1rem',     // 16px
      },
      transitionDuration: {
        'fast': '150ms',
        'base': '200ms',
        'slow': '300ms',
      },
    },
  },
  plugins: [],
}


