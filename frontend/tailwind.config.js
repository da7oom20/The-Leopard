/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ['class', '[data-theme="dark"]'],
  content: ['./src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
        serif: ['Fraunces', 'Georgia', 'serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
        display: ['Fraunces', 'Georgia', 'serif']
      },
      colors: {
        // Theme-driven tokens — values come from CSS variables in index.css
        ink: {
          50:  'rgb(var(--ink-50)  / <alpha-value>)',
          100: 'rgb(var(--ink-100) / <alpha-value>)',
          200: 'rgb(var(--ink-200) / <alpha-value>)',
          300: 'rgb(var(--ink-300) / <alpha-value>)',
          400: 'rgb(var(--ink-400) / <alpha-value>)',
          500: 'rgb(var(--ink-500) / <alpha-value>)',
          600: 'rgb(var(--ink-600) / <alpha-value>)',
          700: 'rgb(var(--ink-700) / <alpha-value>)',
          800: 'rgb(var(--ink-800) / <alpha-value>)',
          850: 'rgb(var(--ink-850) / <alpha-value>)',
          900: 'rgb(var(--ink-900) / <alpha-value>)',
          950: 'rgb(var(--ink-950) / <alpha-value>)'
        },
        signal: {
          amber:        'rgb(var(--signal-amber)        / <alpha-value>)',
          'amber-soft': 'rgb(var(--signal-amber-soft)   / <alpha-value>)',
          ember:        'rgb(var(--signal-ember)        / <alpha-value>)',
          jade:         'rgb(var(--signal-jade)         / <alpha-value>)',
          'jade-soft':  'rgb(var(--signal-jade-soft)    / <alpha-value>)',
          rust:         'rgb(var(--signal-rust)         / <alpha-value>)',
          plum:         'rgb(var(--signal-plum)         / <alpha-value>)',
          warning:      'rgb(var(--signal-warning)      / <alpha-value>)'
        }
      },
      fontSize: {
        'micro': ['0.6875rem', { lineHeight: '1rem', letterSpacing: '0.14em' }]
      },
      letterSpacing: {
        'eyebrow': '0.18em',
        'wider-2': '0.06em'
      },
      boxShadow: {
        'editorial':    '0 1px 0 0 rgb(var(--ink-50) / 0.04), 0 24px 48px -24px rgba(0, 0, 0, 0.6)',
        'editorial-lg': '0 1px 0 0 rgb(var(--ink-50) / 0.05), 0 40px 80px -32px rgba(0, 0, 0, 0.7)'
      },
      animation: {
        'fade-up':    'fadeUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) both',
        'fade-in':    'fadeIn 0.6s ease-out both',
        'pulse-slow': 'pulse 3.5s cubic-bezier(0.4, 0, 0.6, 1) infinite'
      },
      keyframes: {
        fadeUp: {
          '0%':   { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        },
        fadeIn: {
          '0%':   { opacity: '0' },
          '100%': { opacity: '1' }
        }
      }
    },
  },
  plugins: [],
};
