/**
 * Centralized API client with automatic 401 handling.
 *
 * On any 401 response, dispatches a 'auth:session-expired' custom event
 * so App.jsx can auto-logout the user and redirect to /login.
 */

const SESSION_EXPIRED_EVENT = 'auth:session-expired';

/**
 * Dispatch session-expired event (debounced to avoid multiple triggers)
 */
let expiredFired = false;
function fireSessionExpired() {
  if (expiredFired) return;
  expiredFired = true;
  window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
  // Reset after a short delay so future expirations can fire
  setTimeout(() => { expiredFired = false; }, 3000);
}

/**
 * Auth-failure error messages from the backend middleware.
 * These 403s indicate token/session issues, not permission denials.
 */
const AUTH_FAILURE_MESSAGES = [
  'Invalid or expired token',
  'Account is disabled or no longer exists',
  'Session expired due to password change',
];

/**
 * Wrapper around fetch() that intercepts auth failure responses.
 * Fires session-expired on 401, or on 403 with auth-failure messages.
 * Usage is identical to fetch() — same arguments, same return value.
 */
export async function apiFetch(url, options = {}) {
  const response = await fetch(url, options);

  if (response.status === 401) {
    fireSessionExpired();
  } else if (response.status === 403) {
    // Clone to read body without consuming the original response
    const clone = response.clone();
    try {
      const body = await clone.json();
      if (body.error && AUTH_FAILURE_MESSAGES.some(m => body.error.includes(m))) {
        fireSessionExpired();
      }
    } catch {
      // Not JSON or parse error — ignore
    }
  }

  return response;
}

export { SESSION_EXPIRED_EVENT };
