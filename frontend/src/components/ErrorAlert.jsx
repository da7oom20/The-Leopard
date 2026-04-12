import React, { useState, useEffect } from 'react';

/**
 * Error category icons and colors for consistent error display.
 * Categories: connection, auth, timeout, validation, notfound, server
 */
const ERROR_STYLES = {
  connection: {
    icon: (
      <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 5.636a9 9 0 010 12.728M5.636 18.364a9 9 0 010-12.728m12.728 0L5.636 18.364" />
      </svg>
    ),
    title: 'Connection Error',
    borderColor: 'border-red-700',
    bgColor: 'bg-red-900/40',
    textColor: 'text-red-200',
    iconColor: 'text-red-400',
  },
  auth: {
    icon: (
      <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    ),
    title: 'Authentication Error',
    borderColor: 'border-amber-700',
    bgColor: 'bg-amber-900/40',
    textColor: 'text-amber-200',
    iconColor: 'text-amber-400',
  },
  timeout: {
    icon: (
      <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    ),
    title: 'Timeout',
    borderColor: 'border-yellow-700',
    bgColor: 'bg-yellow-900/40',
    textColor: 'text-yellow-200',
    iconColor: 'text-yellow-400',
  },
  validation: {
    icon: (
      <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
      </svg>
    ),
    title: 'Validation Error',
    borderColor: 'border-orange-700',
    bgColor: 'bg-orange-900/40',
    textColor: 'text-orange-200',
    iconColor: 'text-orange-400',
  },
  notfound: {
    icon: (
      <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
      </svg>
    ),
    title: 'Not Found',
    borderColor: 'border-zinc-600',
    bgColor: 'bg-zinc-800/80',
    textColor: 'text-zinc-300',
    iconColor: 'text-zinc-400',
  },
  server: {
    icon: (
      <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
      </svg>
    ),
    title: 'Server Error',
    borderColor: 'border-red-800',
    bgColor: 'bg-red-950/60',
    textColor: 'text-red-200',
    iconColor: 'text-red-500',
  },
};

// Default style for unknown categories
const DEFAULT_STYLE = {
  icon: (
    <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  title: 'Error',
  borderColor: 'border-red-700',
  bgColor: 'bg-red-900/40',
  textColor: 'text-red-200',
  iconColor: 'text-red-400',
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
      className={`${style.bgColor} ${style.borderColor} border rounded-lg p-4 ${className}`}
      role="alert"
      aria-live="assertive"
    >
      <div className="flex items-start gap-3">
        {/* Icon */}
        <span className={style.iconColor}>{style.icon}</span>

        {/* Content */}
        <div className="flex-1 min-w-0">
          {/* Error message */}
          <p className={`font-medium ${style.textColor}`}>{error}</p>

          {/* Suggestion */}
          {suggestion && (
            <p className="mt-1.5 text-sm text-zinc-400 flex items-start gap-1.5">
              <span className="text-zinc-500 font-medium flex-shrink-0">Tip:</span>
              <span>{suggestion}</span>
            </p>
          )}

          {/* Retry button */}
          {onRetry && (
            <button
              onClick={onRetry}
              className="mt-2 px-3 py-1 text-sm rounded-md bg-zinc-700 text-zinc-200 hover:bg-zinc-600 transition focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              Retry
            </button>
          )}
        </div>

        {/* Dismiss button */}
        {onDismiss && (
          <button
            onClick={handleDismiss}
            className="flex-shrink-0 text-zinc-500 hover:text-zinc-300 transition p-0.5 rounded hover:bg-zinc-700/50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            aria-label="Dismiss error"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
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
