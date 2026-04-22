import React, { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import AuthContext from '../context/AuthContext';
import Footer from '../components/Footer';
import { LeopardMark } from '../components/Logo';
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
      const payload = { username: form.username, password: form.password };
      if (showMfa) {
        if (useBackupCode) payload.backupCode = backupCode;
        else payload.mfaToken = mfaToken;
      }
      const res = await axios.post(`${API_URL}/auth/login`, payload);
      if (res.data.mfaRequired) { setShowMfa(true); return; }
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
    <div className="flex flex-col min-h-screen bg-ink-950 text-ink-50 grain">
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-[1fr_minmax(420px,520px)] relative">

        {/* Hero panel — left on desktop, hidden on small */}
        <aside className="hidden lg:flex relative overflow-hidden vignette-amber border-r border-hairline-strong">
          <div className="scanlines absolute inset-0 pointer-events-none opacity-60" />
          <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-signal-amber/40 to-transparent" />
          <div className="absolute bottom-0 left-0 right-0 h-px bg-hairline-strong" />

          {/* Top eyebrow row */}
          <div className="absolute top-8 left-12 right-12 flex items-baseline justify-between animate-fade-in">
            <span className="eyebrow-amber">N° 05 — Field Manual</span>
            <span className="eyebrow">Threat Intelligence Division</span>
          </div>

          {/* Decorative coordinates */}
          <div className="absolute bottom-8 left-12 right-12 flex items-baseline justify-between animate-fade-in delay-300">
            <span className="font-mono text-micro text-ink-500 tracking-wider-2">
              34°47′N · 31°36′E
            </span>
            <span className="font-mono text-micro text-ink-500 tracking-wider-2">
              ENTRY · RESTRICTED
            </span>
          </div>

          {/* Centered identity */}
          <div className="m-auto flex flex-col items-center text-center px-12 max-w-xl">
            <div className="relative mb-8 animate-fade-up">
              <div className="absolute -inset-6 rounded-full bg-signal-amber/10 blur-2xl" aria-hidden />
              <LeopardMark size={88} className="relative" />
            </div>

            <h1 className="font-serif italic text-7xl leading-none tracking-tight animate-fade-up delay-150 wordmark-gradient"
                style={{ fontVariationSettings: '"opsz" 144, "wght" 400, "SOFT" 100' }}>
              The Leopard
            </h1>

            <div className="mt-6 mb-8 flex items-center gap-4 w-full max-w-xs animate-fade-up delay-300">
              <span className="h-px flex-1 bg-hairline-strong" />
              <span className="eyebrow">Volume V · Edition Community</span>
              <span className="h-px flex-1 bg-hairline-strong" />
            </div>

            <p className="font-serif italic text-ink-200 text-xl leading-snug max-w-md animate-fade-up delay-300"
               style={{ fontVariationSettings: '"opsz" 60' }}>
              "What the predator sees, the analyst remembers. What the analyst remembers, the network forgets."
            </p>

            <p className="mt-8 font-mono text-xs text-ink-500 leading-relaxed max-w-sm animate-fade-up delay-500">
              A field manual for multi-SIEM indicator hunting. Track, observe,
              and remember — across LogRhythm, Splunk, QRadar, Elastic, Wazuh,
              and ManageEngine.
            </p>
          </div>
        </aside>

        {/* Credentials panel — right */}
        <main className="flex flex-col">
          <div className="flex items-center justify-between px-8 lg:px-12 py-8 border-b border-hairline">
            <div className="flex items-center gap-3 lg:hidden">
              <LeopardMark size={32} />
              <span className="font-serif italic text-2xl wordmark-gradient"
                    style={{ fontVariationSettings: '"opsz" 144' }}>
                Leopard
              </span>
            </div>
            <span className="hidden lg:block eyebrow">Section 01</span>
            <span className="eyebrow">Authentication</span>
          </div>

          <div className="flex-1 flex flex-col justify-center px-8 lg:px-12 py-12">
            <div className="w-full max-w-sm mx-auto lg:mx-0">

              {!showMfa ? (
                <form onSubmit={handleSubmit} aria-label="Login form" className="animate-fade-up">
                  <div className="mb-10">
                    <span className="eyebrow-amber">Operator Sign-in</span>
                    <h2 className="mt-3 font-serif text-4xl text-ink-50 leading-tight"
                        style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                      Enter the field.
                    </h2>
                    <p className="mt-3 text-ink-400 text-sm">
                      Provide credentials to access the threat intelligence console.
                    </p>
                  </div>

                  {errorInfo.error && (
                    <ErrorAlert
                      error={errorInfo.error}
                      suggestion={errorInfo.suggestion}
                      category={errorInfo.category}
                      onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
                      className="mb-6"
                    />
                  )}

                  <div className="space-y-6">
                    <div>
                      <label htmlFor="login-username" className="eyebrow block mb-2">Operator</label>
                      <input
                        id="login-username"
                        name="username"
                        value={form.username}
                        onChange={handleChange}
                        placeholder="username"
                        autoComplete="username"
                        className="field"
                        disabled={loading}
                        required
                      />
                    </div>
                    <div>
                      <label htmlFor="login-password" className="eyebrow block mb-2">Passphrase</label>
                      <input
                        id="login-password"
                        type="password"
                        name="password"
                        value={form.password}
                        onChange={handleChange}
                        placeholder="••••••••••"
                        autoComplete="current-password"
                        className="field"
                        disabled={loading}
                        required
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={loading}
                    className="btn-amber w-full mt-10 py-3"
                  >
                    {loading && (
                      <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                        <circle className="opacity-30" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                        <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                    )}
                    {loading ? 'Authenticating' : 'Sign In'}
                    {!loading && (
                      <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M13.75 6.75L19.25 12l-5.5 5.25M19 12H4.75" />
                      </svg>
                    )}
                  </button>
                </form>
              ) : (
                <form onSubmit={handleSubmit} aria-label="MFA form" className="animate-fade-up">
                  <div className="mb-10">
                    <span className="eyebrow-amber">Second Factor Required</span>
                    <h2 className="mt-3 font-serif text-4xl text-ink-50 leading-tight"
                        style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                      Verify identity.
                    </h2>
                    <p className="mt-3 text-ink-400 text-sm">
                      {useBackupCode
                        ? 'Provide one of your single-use backup codes.'
                        : 'Enter the six-digit code from your authenticator app.'}
                    </p>
                  </div>

                  {errorInfo.error && (
                    <ErrorAlert
                      error={errorInfo.error}
                      suggestion={errorInfo.suggestion}
                      category={errorInfo.category}
                      onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
                      className="mb-6"
                    />
                  )}

                  {!useBackupCode ? (
                    <div>
                      <label htmlFor="mfa-token" className="eyebrow block mb-2">Authenticator Code</label>
                      <input
                        id="mfa-token"
                        type="text"
                        value={mfaToken}
                        onChange={(e) => setMfaToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        placeholder="000000"
                        maxLength={6}
                        aria-label="6-digit MFA code"
                        className="w-full bg-transparent border-0 border-b border-ink-700 focus:border-signal-amber focus:outline-none text-ink-50 placeholder-ink-700 text-center font-mono text-4xl tracking-[0.5em] py-4 transition-colors"
                        autoFocus
                        disabled={loading}
                      />
                    </div>
                  ) : (
                    <div>
                      <label htmlFor="backup-code" className="eyebrow block mb-2">Backup Code</label>
                      <input
                        id="backup-code"
                        type="text"
                        value={backupCode}
                        onChange={(e) => setBackupCode(e.target.value.toUpperCase())}
                        placeholder="XXXXXXXX"
                        maxLength={8}
                        aria-label="Backup code"
                        className="w-full bg-transparent border-0 border-b border-ink-700 focus:border-signal-amber focus:outline-none text-ink-50 placeholder-ink-700 text-center font-mono text-3xl tracking-[0.4em] py-4 transition-colors"
                        autoFocus
                        disabled={loading}
                      />
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={loading || (!useBackupCode && mfaToken.length !== 6) || (useBackupCode && backupCode.length < 8)}
                    className="btn-amber w-full mt-8 py-3"
                  >
                    {loading && (
                      <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                        <circle className="opacity-30" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                        <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                    )}
                    {loading ? 'Verifying' : 'Verify & Enter'}
                  </button>

                  <div className="mt-8 pt-6 border-t border-hairline flex items-center justify-between">
                    <button
                      type="button"
                      onClick={() => { setUseBackupCode(!useBackupCode); setErrorInfo({ error: '', suggestion: '', category: '' }); }}
                      className="text-xs font-mono uppercase tracking-eyebrow text-signal-amber hover:text-signal-amber-soft transition-colors"
                    >
                      {useBackupCode ? 'Use authenticator' : 'Use backup code'}
                    </button>
                    <button
                      type="button"
                      onClick={resetMfa}
                      className="text-xs font-mono uppercase tracking-eyebrow text-ink-500 hover:text-ink-200 transition-colors"
                    >
                      ← Back
                    </button>
                  </div>
                </form>
              )}

              <div className="mt-12 pt-6 border-t border-hairline flex items-center justify-between">
                <span className="font-mono text-micro text-ink-600 tracking-wider-2">
                  ENC · TLS 1.3
                </span>
                <span className="font-mono text-micro text-ink-600 tracking-wider-2">
                  REV · 5.0
                </span>
              </div>
            </div>
          </div>
        </main>
      </div>

      <Footer />
    </div>
  );
}
