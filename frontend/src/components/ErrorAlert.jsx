import React, { useState, useEffect } from 'react';

/**
 * Error category icons and colors for consistent error display.
 * Categories: connection, auth, timeout, validation, notfound, server
 */
const ERROR_STYLES = {
  connection: {
    icon: (
      <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M18.364 5.636a9 9 0 010 12.728M5.636 18.364a9 9 0 010-12.728m12.728 0L5.636 18.364" />
      </svg>
    ),
    title: 'Connection',
    borderColor: 'border-signal-rust/50',
    bgColor: 'bg-signal-rust/10',
    textColor: 'text-ink-100',
    iconColor: 'text-signal-rust',
  },
  auth: {
    icon: (
      <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    ),
    title: 'Authentication',
    borderColor: 'border-signal-amber/50',
    bgColor: 'bg-signal-amber/10',
    textColor: 'text-ink-100',
    iconColor: 'text-signal-amber',
  },
  timeout: {
    icon: (
      <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    title: 'Timeout',
    borderColor: 'border-signal-amber-soft/50',
    bgColor: 'bg-signal-amber-soft/10',
    textColor: 'text-ink-100',
    iconColor: 'text-signal-amber-soft',
  },
  validation: {
    icon: (
      <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
      </svg>
    ),
    title: 'Validation',
    borderColor: 'border-signal-amber/40',
    bgColor: 'bg-signal-amber/8',
    textColor: 'text-ink-100',
    iconColor: 'text-signal-amber',
  },
  notfound: {
    icon: (
      <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
    ),
    title: 'Not Found',
    borderColor: 'border-ink-700',
    bgColor: 'bg-ink-900',
    textColor: 'text-ink-200',
    iconColor: 'text-ink-400',
  },
  server: {
    icon: (
      <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
      </svg>
    ),
    title: 'Server',
    borderColor: 'border-signal-rust/60',
    bgColor: 'bg-signal-rust/12',
    textColor: 'text-ink-100',
    iconColor: 'text-signal-rust',
  },
};

const DEFAULT_STYLE = {
  icon: (
    <svg className="w-4 h-4 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  title: 'Error',
  borderColor: 'border-signal-rust/50',
  bgColor: 'bg-signal-rust/10',
  textColor: 'text-ink-100',
  iconColor: 'text-signal-rust',
};

/**
 * Reusable error alert component with category-based styling.
 *
 * @param {string} error - The error message to display
 * @param {string} [suggestion] - Optional suggestion text
 * @param {string} [category] - Error category for icon/styling
 * @param {function} [onDismiss] - Callback when dismissed (shows X button)
 * @param {function} [onRetry] - Callback for retry (shows Retry button)
 * @param {number} [autoDismissMs] - Auto-dismiss after this many ms (0 = never)
 * @param {string} [className] - Additional CSS classes
 */
export default function ErrorAlert({
  error,
  suggestion,
  category,
  onDismiss,
  onRetry,
  autoDismissMs = 0,
  className = '',
}) {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    setVisible(true);
  }, [error, suggestion]);

  useEffect(() => {
    if (autoDismissMs > 0 && visible) {
      const timer = setTimeout(() => {
        setVisible(false);
        if (onDismiss) onDismiss();
      }, autoDismissMs);
      return () => clearTimeout(timer);
    }
  }, [autoDismissMs, visible, onDismiss]);

  if (!error || !visible) return null;

  const style = ERROR_STYLES[category] || DEFAULT_STYLE;

  const handleDismiss = () => {
    setVisible(false);
    if (onDismiss) onDismiss();
  };

  return (
    <div
      className={`${style.bgColor} ${style.borderColor} border-l-2 border-y border-r border-y-hairline border-r-hairline px-4 py-3 ${className}`}
      role="alert"
      aria-live="assertive"
    >
      <div className="flex items-start gap-3">
        <span className={style.iconColor}>{style.icon}</span>

        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-2">
            <span className={`font-mono uppercase text-micro tracking-eyebrow ${style.iconColor}`}>
              {style.title}
            </span>
            <span className="font-mono uppercase text-micro tracking-eyebrow text-ink-500">·</span>
            <p className={`text-sm ${style.textColor}`}>{error}</p>
          </div>

          {suggestion && (
            <p className="mt-1.5 text-sm text-ink-400 pl-0 flex items-start gap-2">
              <span className="font-mono uppercase text-micro tracking-eyebrow text-ink-500 mt-0.5 flex-shrink-0">Note</span>
              <span>{suggestion}</span>
            </p>
          )}

          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-2.5 inline-flex items-center gap-1.5 px-3 py-1 text-xs font-mono uppercase tracking-eyebrow text-ink-200 border border-ink-700 hover:border-signal-amber hover:text-signal-amber transition-colors focus:outline-none focus:ring-1 focus:ring-signal-amber"
            >
              Retry
            </button>
          )}
        </div>

        {onDismiss && (
          <button
            onClick={handleDismiss}
            className="flex-shrink-0 text-ink-500 hover:text-ink-200 transition p-0.5 focus:outline-none focus:ring-1 focus:ring-signal-amber"
            aria-label="Dismiss error"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
}

/**
 * Helper to extract error info from an API response or Error object.
 * Returns { error, suggestion, category } suitable for ErrorAlert props.
 */
export function parseApiError(err) {
  // Axios error with response
  if (err?.response?.data) {
    const data = err.response.data;
    return {
      error: data.error || data.message || 'An unexpected error occurred.',
      suggestion: data.suggestion || null,
      category: data.category || null,
    };
  }

  // Fetch response already parsed
  if (err?.error) {
    return {
      error: err.error,
      suggestion: err.suggestion || null,
      category: err.category || null,
    };
  }

  // Plain Error or string
  if (err instanceof Error) {
    return {
      error: err.message || 'An unexpected error occurred.',
      suggestion: null,
      category: null,
    };
  }

  if (typeof err === 'string') {
    return { error: err, suggestion: null, category: null };
  }

  return { error: 'An unexpected error occurred.', suggestion: null, category: null };
}
