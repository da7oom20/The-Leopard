import React, { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import AuthContext from '../context/AuthContext';
import Footer from '../components/Footer';
import { LeopardLogoSilhouette } from '../components/Logo';
import ErrorAlert, { parseApiError } from '../components/ErrorAlert';

const API_URL = process.env.REACT_APP_API_URL || '/api';

export default function LoginPage() {
  const [form, setForm] = useState({ username: '', password: '' });
  const [mfaToken, setMfaToken] = useState('');
  const [backupCode, setBackupCode] = useState('');
  const [showMfa, setShowMfa] = useState(false);
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { login } = useContext(AuthContext);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setLoading(true);

    try {
      const payload = {
        username: form.username,
        password: form.password
      };

      // Add MFA token if in MFA mode
      if (showMfa) {
        if (useBackupCode) {
          payload.backupCode = backupCode;
        } else {
          payload.mfaToken = mfaToken;
        }
      }

      const res = await axios.post(`${API_URL}/auth/login`, payload);

      // Check if MFA is required
      if (res.data.mfaRequired) {
        setShowMfa(true);
        return;
      }

      // Login successful
      login(res.data.token);
      navigate('/admin');
    } catch (err) {
      setErrorInfo(parseApiError(err));
    } finally {
      setLoading(false);
    }
  };

  const resetMfa = () => {
    setShowMfa(false);
    setMfaToken('');
    setBackupCode('');
    setUseBackupCode(false);
    setErrorInfo({ error: '', suggestion: '', category: '' });
  };

  return (
    <div className="flex flex-col min-h-screen bg-zinc-950">
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          {/* Logo/Brand */}
          <div className="flex flex-col items-center mb-8">
            <LeopardLogoSilhouette size={80} className="mb-4" />
            <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
              The Leopard
            </h1>
            <p className="text-zinc-400 text-sm mt-1">IOC Search Platform v5.0</p>
          </div>

          <form
            onSubmit={handleSubmit}
            className="bg-zinc-900 p-8 rounded-lg shadow-xl border border-zinc-700"
            aria-label="Login form"
          >
            {!showMfa ? (
              <>
                <h2 className="text-xl font-semibold mb-6 text-center text-zinc-100">Admin Login</h2>
                <ErrorAlert
                  error={errorInfo.error}
                  suggestion={errorInfo.suggestion}
                  category={errorInfo.category}
                  onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
                  className="mb-4"
                />
                <div className="mb-4">
                  <label htmlFor="login-username" className="sr-only">Username</label>
                  <input
                    id="login-username"
                    name="username"
                    value={form.username}
                    onChange={handleChange}
                    placeholder="Enter your username"
                    autoComplete="username"
                    className="w-full p-3 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-colors"
                    disabled={loading}
                    required
                  />
                </div>
                <div className="mb-6">
                  <label htmlFor="login-password" className="sr-only">Password</label>
                  <input
                    id="login-password"
                    type="password"
                    name="password"
                    value={form.password}
                    onChange={handleChange}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    className="w-full p-3 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-colors"
                    disabled={loading}
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-indigo-600 text-white p-3 rounded-md font-medium hover:bg-indigo-700 transition focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-zinc-900 disabled:opacity-50 inline-flex items-center justify-center gap-2"
                >
                  {loading && (
                    <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                  )}
                  {loading ? 'Logging in...' : 'Login'}
                </button>
              </>
            ) : (
              <>
                <h2 className="text-xl font-semibold mb-2 text-center text-zinc-100">Two-Factor Authentication</h2>
                <p className="text-zinc-400 text-sm text-center mb-6">
                  {useBackupCode
                    ? 'Enter one of your backup codes'
                    : 'Enter the 6-digit code from your authenticator app'}
                </p>

                <ErrorAlert
                  error={errorInfo.error}
                  suggestion={errorInfo.suggestion}
                  category={errorInfo.category}
                  onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
                  className="mb-4"
                />

                {!useBackupCode ? (
                  <input
                    type="text"
                    value={mfaToken}
                    onChange={(e) => setMfaToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="000000"
                    maxLength={6}
                    aria-label="6-digit MFA code"
                    className="w-full p-4 mb-4 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 placeholder-zinc-500 text-center text-2xl tracking-widest font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-colors"
                    autoFocus
                    disabled={loading}
                  />
                ) : (
                  <input
                    type="text"
                    value={backupCode}
                    onChange={(e) => setBackupCode(e.target.value.toUpperCase())}
                    placeholder="XXXXXXXX"
                    maxLength={8}
                    aria-label="Backup code"
                    className="w-full p-4 mb-4 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 placeholder-zinc-500 text-center text-xl tracking-widest font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition-colors"
                    autoFocus
                    disabled={loading}
                  />
                )}

                <button
                  type="submit"
                  disabled={loading || (!useBackupCode && mfaToken.length !== 6) || (useBackupCode && backupCode.length < 8)}
                  className="w-full bg-indigo-600 text-white p-3 rounded-md font-medium hover:bg-indigo-700 transition focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-zinc-900 disabled:opacity-50 mb-4 inline-flex items-center justify-center gap-2"
                >
                  {loading && (
                    <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                  )}
                  {loading ? 'Verifying...' : 'Verify'}
                </button>

                <div className="flex flex-col gap-2">
                  <button
                    type="button"
                    onClick={() => { setUseBackupCode(!useBackupCode); setErrorInfo({ error: '', suggestion: '', category: '' }); }}
                    className="text-sm text-indigo-400 hover:text-indigo-300 transition"
                  >
                    {useBackupCode ? 'Use authenticator app instead' : 'Use backup code instead'}
                  </button>
                  <button
                    type="button"
                    onClick={resetMfa}
                    className="text-sm text-zinc-500 hover:text-zinc-400 transition"
                  >
                    Back to login
                  </button>
                </div>
              </>
            )}
          </form>

          <p className="text-center text-zinc-500 text-xs mt-6">
            Community Edition
          </p>
        </div>
      </div>

      <Footer />
    </div>
  );
}
