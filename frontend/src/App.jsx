import React, { useState, useEffect, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from 'react-router-dom';
import jwtDecode from 'jwt-decode';

import LoginPage from './pages/LoginPage';
import AdminPage from './pages/AdminPage';
import UploadPage from './pages/UploadPage';
import RepoPage from './pages/RepoPage';
import ResultsPage from './pages/ResultsPage';
import SetupWizard from './pages/SetupWizard';

import AuthContext from './context/AuthContext';
import { SetupProvider, useSetup } from './contexts/SetupContext';
import { ThemeProvider } from './contexts/ThemeContext';
import ThemeToggle from './components/ThemeToggle';
import { SESSION_EXPIRED_EVENT } from './utils/apiClient';

/* ---- React Error Boundary ---- */
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, info) {
    console.error('ErrorBoundary caught:', error, info);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-ink-950 flex items-center justify-center p-6">
          <div className="card-editorial max-w-md w-full p-10 text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 mb-6 border border-signal-rust/40 text-signal-rust">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
              </svg>
            </div>
            <span className="eyebrow-amber">Unexpected event</span>
            <h1 className="mt-3 font-serif text-3xl text-ink-50 leading-tight" style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>Something went wrong.</h1>
            <p className="mt-3 text-ink-300">An error escaped the boundary. Try again, or refresh the page.</p>
            <div className="mt-8 flex gap-2 justify-center">
              <button onClick={() => this.setState({ hasError: false, error: null })} className="btn-ghost">Try Again</button>
              <button onClick={() => window.location.reload()} className="btn-amber">Refresh Page</button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

/* ---- 404 Not Found Page ---- */
function NotFoundPage() {
  return (
    <div className="min-h-screen bg-ink-950 flex items-center justify-center p-6 grain">
      <div className="max-w-md w-full text-center animate-fade-up">
        <span className="eyebrow-amber">Off the map</span>
        <h1 className="mt-3 font-serif italic text-ink-50 text-8xl leading-none" style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>404</h1>
        <h2 className="mt-4 font-serif text-2xl text-ink-100" style={{ fontVariationSettings: '"opsz" 60' }}>This page is not in the field manual.</h2>
        <p className="mt-3 text-ink-400 text-sm">The location you tried to reach does not exist or has been moved.</p>
        <Link to="/" className="btn-amber mt-8 inline-flex">Return Home</Link>
      </div>
    </div>
  );
}

function decodeToken(token) {
  if (!token) return null;
  try {
    const decoded = jwtDecode(token);
    if (decoded.exp * 1000 < Date.now()) return null;
    return decoded;
  } catch {
    return null;
  }
}

function ProtectedRoute({ children, adminOnly = false }) {
  const { token, user } = useContext(AuthContext);
  if (!token) return <Navigate to="/login" replace />;
  if (adminOnly && !user?.isAdmin) {
    return (
      <div className="min-h-screen bg-ink-950 flex items-center justify-center p-6">
        <div className="text-center max-w-sm">
          <span className="eyebrow-amber" style={{ color: 'rgb(var(--signal-rust))' }}>Restricted</span>
          <h1 className="mt-3 font-serif text-3xl text-ink-50" style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>Access denied.</h1>
          <p className="mt-3 text-ink-400 text-sm">Your operator credentials don't grant access to this section.</p>
          <button onClick={() => window.history.back()} className="btn-ghost mt-6">Go Back</button>
        </div>
      </div>
    );
  }
  return children;
}

function SetupGuard({ children }) {
  const { isComplete } = useSetup();

  // Still loading setup status
  if (isComplete === null) {
    return (
      <div className="min-h-screen bg-ink-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <svg className="animate-spin h-6 w-6 text-signal-amber" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
            <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <span className="font-mono text-micro text-ink-500 tracking-eyebrow uppercase">Initializing field manual</span>
        </div>
      </div>
    );
  }

  // Setup not complete, redirect to wizard
  if (isComplete === false) {
    return <Navigate to="/setup" replace />;
  }

  return children;
}

function AppRoutes() {
  const [token, setToken] = useState(() => localStorage.getItem('token'));
  const [user, setUser] = useState(() => decodeToken(localStorage.getItem('token')));
  const [sessionExpiredMsg, setSessionExpiredMsg] = useState('');

  useEffect(() => {
    if (token) {
      const decoded = decodeToken(token);
      if (!decoded) {
        localStorage.removeItem('token');
        setToken(null);
        setUser(null);
      } else {
        setUser(decoded);
      }
    } else {
      setUser(null);
    }
  }, [token]);

  // Listen for 401 session-expired events from apiClient
  useEffect(() => {
    const handleExpired = () => {
      localStorage.removeItem('token');
      setToken(null);
      setUser(null);
      setSessionExpiredMsg('Your session has expired. Please log in again.');
      setTimeout(() => setSessionExpiredMsg(''), 8000);
    };
    window.addEventListener(SESSION_EXPIRED_EVENT, handleExpired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, handleExpired);
  }, []);

  // Auto-refresh token before expiry; warn user 5 min before
  const [expiryWarning, setExpiryWarning] = useState('');
  useEffect(() => {
    if (!token) { setExpiryWarning(''); return; }
    const API_URL = process.env.REACT_APP_API_URL || '/api';
    const REFRESH_BEFORE_MS = 5 * 60 * 1000; // refresh 5 min before expiry
    const CHECK_INTERVAL_MS = 60 * 1000; // check every 60s

    const interval = setInterval(async () => {
      const decoded = decodeToken(token);
      if (!decoded) {
        // Token already expired
        localStorage.removeItem('token');
        setToken(null);
        setUser(null);
        return;
      }
      const msUntilExpiry = decoded.exp * 1000 - Date.now();
      if (msUntilExpiry <= 0) {
        localStorage.removeItem('token');
        setToken(null);
        setUser(null);
        return;
      }
      if (msUntilExpiry <= REFRESH_BEFORE_MS) {
        // Attempt silent refresh
        try {
          const res = await fetch(`${API_URL}/auth/refresh`, {
            method: 'POST',
            headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          });
          if (res.ok) {
            const data = await res.json();
            if (data.token) {
              localStorage.setItem('token', data.token);
              setToken(data.token);
              setUser(decodeToken(data.token));
              setExpiryWarning('');
              return;
            }
          }
        } catch {
          // Refresh failed — show warning
        }
        const minLeft = Math.ceil(msUntilExpiry / 60000);
        setExpiryWarning(`Session expires in ${minLeft} minute${minLeft === 1 ? '' : 's'}.`);
      }
    }, CHECK_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [token]);

  const login = (newToken) => {
    localStorage.setItem('token', newToken);
    const decoded = decodeToken(newToken);
    setUser(decoded);
    setToken(newToken);
  };

  const logout = async () => {
    // Invalidate server-side session before clearing local state
    const currentToken = localStorage.getItem('token');
    if (currentToken) {
      try {
        const API_URL = process.env.REACT_APP_API_URL || '/api';
        await fetch(`${API_URL}/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${currentToken}`, 'Content-Type': 'application/json' },
        });
      } catch {
        // Best-effort; clear local state regardless
      }
    }
    localStorage.removeItem('token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, login, logout }}>
      <a href="#main-content" className="skip-link">Skip to main content</a>
      {sessionExpiredMsg && (
        <div className="fixed top-0 left-0 right-0 z-[100] bg-signal-amber text-white text-center py-2.5 px-4 text-sm font-mono uppercase tracking-eyebrow shadow-editorial" role="alert">
          <span className="opacity-80 mr-2">Session</span>
          {sessionExpiredMsg}
          <button onClick={() => setSessionExpiredMsg('')} className="ml-4 text-white/70 hover:text-white" aria-label="Dismiss">×</button>
        </div>
      )}
      {expiryWarning && !sessionExpiredMsg && (
        <div className="fixed top-0 left-0 right-0 z-[99] bg-signal-warning text-ink-950 text-center py-2 px-4 text-sm font-mono uppercase tracking-eyebrow shadow-editorial" role="status">
          <span className="opacity-70 mr-2">Notice</span>
          {expiryWarning}
          <button onClick={() => setExpiryWarning('')} className="ml-4 text-ink-950/70 hover:text-ink-950" aria-label="Dismiss">×</button>
        </div>
      )}
      <div id="main-content">
      <Routes>
        {/* Setup route - always accessible */}
        <Route path="/setup" element={<SetupWizard />} />

        {/* Main app routes - protected by setup guard */}
        <Route path="/" element={
          <SetupGuard><UploadPage /></SetupGuard>
        } />
        <Route path="/login" element={
          <SetupGuard><LoginPage /></SetupGuard>
        } />
        <Route path="/upload" element={
          <SetupGuard><UploadPage /></SetupGuard>
        } />
        <Route path="/repo" element={
          <SetupGuard><RepoPage /></SetupGuard>
        } />
        <Route path="/admin" element={
          <SetupGuard>
            <ProtectedRoute adminOnly><AdminPage /></ProtectedRoute>
          </SetupGuard>
        } />
        <Route path="/results/:submissionId" element={
          <SetupGuard>
            <ProtectedRoute><ResultsPage /></ProtectedRoute>
          </SetupGuard>
        } />

        {/* 404 catch-all */}
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
      </div>
    </AuthContext.Provider>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider>
        <SetupProvider>
          <Router>
            <AppRoutes />
            <ThemeToggle />
          </Router>
        </SetupProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
