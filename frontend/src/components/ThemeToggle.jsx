import React from 'react';
import { useTheme } from '../contexts/ThemeContext';

/**
 * Floating editorial day/night toggle.
 *
 * Renders fixed at the bottom-right of the viewport so it's available on every
 * page without each page header having to render it. The pill itself is two
 * stacked icons — sun and moon — with the active mode lit in the signal-amber
 * accent. Restrained motion: only color and a subtle slide.
 */
export default function ThemeToggle({ className = '' }) {
  const { theme, toggle } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      title={isDark ? 'Switch to light' : 'Switch to dark'}
      className={`fixed bottom-5 right-5 z-50 group inline-flex items-center gap-1 px-1.5 py-1.5 bg-ink-900 border border-hairline-strong shadow-editorial hover:border-signal-amber transition-colors focus:outline-none focus:ring-1 focus:ring-signal-amber ${className}`}
    >
      <span className="sr-only">Toggle theme</span>

      {/* Sun (light) */}
      <span
        className={`inline-flex items-center justify-center w-7 h-7 transition-colors ${
          !isDark ? 'bg-signal-amber text-ink-950' : 'text-ink-500 group-hover:text-ink-200'
        }`}
        aria-hidden="true"
      >
        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="12" cy="12" r="3.5" />
          <path strokeLinecap="round" d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6l1.4 1.4M17 17l1.4 1.4M5.6 18.4L7 17M17 7l1.4-1.4" />
        </svg>
      </span>

      {/* Moon (dark) */}
      <span
        className={`inline-flex items-center justify-center w-7 h-7 transition-colors ${
          isDark ? 'bg-signal-amber text-ink-950' : 'text-ink-500 group-hover:text-ink-200'
        }`}
        aria-hidden="true"
      >
        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" />
        </svg>
      </span>
    </button>
  );
}
