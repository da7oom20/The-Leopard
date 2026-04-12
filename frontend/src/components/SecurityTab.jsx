import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import ErrorAlert, { parseApiError } from './ErrorAlert';

export default function SecurityTab({ token, API_URL, onTokenUpdate }) {
  // Change Password State
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [pwLoading, setPwLoading] = useState(false);
  const [pwMessage, setPwMessage] = useState({ type: '', text: '' });

  // MFA State
  const [mfaStatus, setMfaStatus] = useState({ mfaEnabled: false, backupCodesRemaining: 0 });
  const [mfaSetup, setMfaSetup] = useState(null);
  const [mfaToken, setMfaToken] = useState('');
  const [mfaPassword, setMfaPassword] = useState('');
  const [mfaMessage, setMfaMessage] = useState({ type: '', text: '' });
  const [mfaLoading, setMfaLoading] = useState(false);
  const [showBackupCodes, setShowBackupCodes] = useState(null);
  const [qrError, setQrError] = useState(false);

  // SSL State
  const [sslConfig, setSslConfig] = useState(null);
  const [sslFiles, setSslFiles] = useState({ certificate: null, privateKey: null, ca: null });
  const [sslMessage, setSslMessage] = useState({ type: '', text: '' });
  const [sslLoading, setSslLoading] = useState(false);

  // Access Control State
  const [requireSearchAuth, setRequireSearchAuth] = useState(false);
  const [accessMessage, setAccessMessage] = useState({ type: '', text: '' });
  const [accessLoading, setAccessLoading] = useState(false);

  useEffect(() => {
    fetchMfaStatus();
    fetchSslConfig();
    fetchAccessSettings();
  }, [token, API_URL]);

  // MFA Functions
  const fetchMfaStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/auth/mfa/status`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMfaStatus(res.data);
    } catch (err) {
      console.error('Failed to fetch MFA status:', err);
      // If MFA status fails, try to sync database
      if (err.response?.status === 500) {
        setMfaMessage({ type: 'error', text: 'MFA may not be configured.', suggestion: 'Click "Sync Database" below to create the required database columns.', category: 'server' });
      }
    }
  };

  const syncDatabase = async () => {
    setMfaLoading(true);
    try {
      const res = await axios.post(`${API_URL}/admin/sync-db`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMfaMessage({ type: 'success', text: res.data.message });
      // Refresh MFA status after sync
      await fetchMfaStatus();
    } catch (err) {
      const parsed = parseApiError(err);
      setMfaMessage({ type: 'error', text: parsed.error || 'Failed to sync database.', suggestion: parsed.suggestion || 'Check the backend logs for database connection issues.', category: 'server' });
    } finally {
      setMfaLoading(false);
    }
  };

  const setupMfa = async () => {
    setMfaLoading(true);
    setMfaMessage({ type: '', text: '' });
    setQrError(false);
    try {
      const res = await axios.post(`${API_URL}/auth/mfa/setup`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMfaSetup(res.data);
      setMfaMessage({ type: 'success', text: 'MFA setup initiated. Scan the QR code or enter the secret manually.' });
    } catch (err) {
      console.error('MFA setup error:', err);
      const parsed = parseApiError(err);
      setMfaMessage({ type: 'error', text: parsed.error || 'Failed to setup MFA.', suggestion: parsed.suggestion || 'Try clicking "Sync Database" below to ensure MFA columns exist.', category: parsed.category || 'server' });
    } finally {
      setMfaLoading(false);
    }
  };

  const verifyMfa = async () => {
    if (mfaToken.length !== 6) return;
    setMfaLoading(true);
    setMfaMessage({ type: '', text: '' });
    try {
      const res = await axios.post(`${API_URL}/auth/mfa/verify`, { token: mfaToken }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMfaMessage({ type: 'success', text: res.data.message });
      setShowBackupCodes(res.data.backupCodes);
      setMfaSetup(null);
      setMfaToken('');
      fetchMfaStatus();
    } catch (err) {
      const parsed = parseApiError(err);
      setMfaMessage({ type: 'error', text: parsed.error || 'Invalid code.', suggestion: parsed.suggestion || 'Make sure your device clock is synchronized and enter the current 6-digit code from your authenticator app.', category: 'auth' });
    } finally {
      setMfaLoading(false);
    }
  };

  const disableMfa = async () => {
    if (!mfaPassword) {
      setMfaMessage({ type: 'error', text: 'Password is required to disable MFA.', suggestion: 'Enter your current password in the field above.', category: 'validation' });
      return;
    }
    if (!window.confirm('Are you sure you want to disable MFA? This will reduce your account security.')) return;

    setMfaLoading(true);
    setMfaMessage({ type: '', text: '' });
    try {
      const res = await axios.post(`${API_URL}/auth/mfa/disable`, { password: mfaPassword }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMfaMessage({ type: 'success', text: res.data.message });
      setMfaPassword('');
      fetchMfaStatus();
    } catch (err) {
      const parsed = parseApiError(err);
      setMfaMessage({ type: 'error', text: parsed.error || 'Failed to disable MFA.', suggestion: parsed.suggestion || 'Verify your password and try again.', category: 'auth' });
    } finally {
      setMfaLoading(false);
    }
  };

  const regenerateBackupCodes = async () => {
    if (!mfaPassword) {
      setMfaMessage({ type: 'error', text: 'Password is required to regenerate backup codes.', suggestion: 'Enter your current password in the field above.', category: 'validation' });
      return;
    }
    setMfaLoading(true);
    try {
      const res = await axios.post(`${API_URL}/auth/mfa/backup-codes`, { password: mfaPassword }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setShowBackupCodes(res.data.backupCodes);
      setMfaMessage({ type: 'success', text: res.data.message });
      setMfaPassword('');
      fetchMfaStatus();
    } catch (err) {
      const parsed = parseApiError(err);
      setMfaMessage({ type: 'error', text: parsed.error || 'Failed to regenerate backup codes.', suggestion: parsed.suggestion || 'Verify your password and try again.', category: 'auth' });
    } finally {
      setMfaLoading(false);
    }
  };

  // SSL Functions
  const fetchSslConfig = async () => {
    try {
      const res = await axios.get(`${API_URL}/admin/ssl`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSslConfig(res.data);
    } catch (err) {
      console.error('Failed to fetch SSL config:', err);
    }
  };

  // Access Control Functions
  const fetchAccessSettings = async () => {
    try {
      const res = await axios.get(`${API_URL}/admin/settings`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRequireSearchAuth(res.data.requireSearchAuth === 'true');
    } catch (err) {
      console.error('Failed to fetch access settings:', err);
    }
  };

  const toggleSearchAuth = async () => {
    setAccessLoading(true);
    setAccessMessage({ type: '', text: '' });
    try {
      const newValue = !requireSearchAuth;
      await axios.put(`${API_URL}/admin/settings`, {
        key: 'requireSearchAuth',
        value: newValue
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setRequireSearchAuth(newValue);
      setAccessMessage({
        type: 'success',
        text: newValue
          ? 'Search authentication enabled. Users must log in to search, export, and view history.'
          : 'Search authentication disabled. Search, export, and history are publicly accessible.'
      });
    } catch (err) {
      const parsed = parseApiError(err);
      setAccessMessage({ type: 'error', text: parsed.error || 'Failed to update setting' });
    } finally {
      setAccessLoading(false);
    }
  };

  // Change Password
  const changePassword = async () => {
    setPwMessage({ type: '', text: '' });
    if (!currentPassword || !newPassword) {
      setPwMessage({ type: 'error', text: 'Current password and new password are required.' });
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwMessage({ type: 'error', text: 'New password and confirmation do not match.' });
      return;
    }
    setPwLoading(true);
    try {
      const res = await axios.post(`${API_URL}/auth/change-password`, {
        currentPassword,
        newPassword
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setPwMessage({ type: 'success', text: res.data.message || 'Password changed successfully.' });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      // Update token so session stays active
      if (res.data.token && onTokenUpdate) {
        onTokenUpdate(res.data.token);
      }
    } catch (err) {
      const parsed = parseApiError(err);
      setPwMessage({ type: 'error', text: parsed.error || 'Failed to change password.' });
    } finally {
      setPwLoading(false);
    }
  };

  const handleFileChange = (type) => (e) => {
    setSslFiles(prev => ({ ...prev, [type]: e.target.files[0] }));
  };

  const uploadCertificates = async () => {
    if (!sslFiles.certificate || !sslFiles.privateKey) {
      setSslMessage({ type: 'error', text: 'Certificate and private key files are required.', suggestion: 'Select both a certificate file (.crt/.pem) and a private key file (.key).', category: 'validation' });
      return;
    }

    setSslLoading(true);
    setSslMessage({ type: '', text: '' });

    const formData = new FormData();
    formData.append('certificate', sslFiles.certificate);
    formData.append('privateKey', sslFiles.privateKey);
    if (sslFiles.ca) formData.append('ca', sslFiles.ca);

    try {
      const res = await axios.post(`${API_URL}/admin/ssl/upload`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        }
      });
      setSslMessage({ type: 'success', text: res.data.message });
      setSslFiles({ certificate: null, privateKey: null, ca: null });
      fetchSslConfig();
    } catch (err) {
      const parsed = parseApiError(err);
      setSslMessage({ type: 'error', text: parsed.error || 'Failed to upload certificates.', suggestion: parsed.suggestion || 'Ensure the certificate and key files are valid PEM-encoded files.', category: 'validation' });
    } finally {
      setSslLoading(false);
    }
  };

  const toggleSsl = async (enabled) => {
    setSslLoading(true);
    try {
      const res = await axios.post(`${API_URL}/admin/ssl/toggle`, { enabled }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSslMessage({ type: 'success', text: res.data.message });
      fetchSslConfig();
    } catch (err) {
      const parsed = parseApiError(err);
      setSslMessage({ type: 'error', text: parsed.error || 'Failed to toggle SSL.', suggestion: parsed.suggestion || 'Ensure valid certificates are uploaded before enabling HTTPS.', category: 'server' });
    } finally {
      setSslLoading(false);
    }
  };

  const deleteCertificates = async () => {
    if (!window.confirm('Are you sure you want to delete all SSL certificates?')) return;

    setSslLoading(true);
    try {
      const res = await axios.delete(`${API_URL}/admin/ssl`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSslMessage({ type: 'success', text: res.data.message });
      fetchSslConfig();
    } catch (err) {
      const parsed = parseApiError(err);
      setSslMessage({ type: 'error', text: parsed.error || 'Failed to delete certificates.', suggestion: parsed.suggestion || 'Try again or check the backend logs.', category: 'server' });
    } finally {
      setSslLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Change Password Section */}
      <div>
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <svg className="w-6 h-6 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
          </svg>
          Change Password
        </h2>

        {pwMessage.type === 'success' && pwMessage.text && (
          <div className="p-4 rounded-lg mb-4 bg-green-900/30 text-green-400 border border-green-800" role="status">
            {pwMessage.text}
          </div>
        )}
        {pwMessage.type === 'error' && pwMessage.text && (
          <ErrorAlert
            error={pwMessage.text}
            onDismiss={() => setPwMessage({ type: '', text: '' })}
            className="mb-4"
          />
        )}

        <div className="bg-zinc-800/50 border border-zinc-700 rounded-lg p-6">
          <p className="text-sm text-zinc-400 mb-4">
            Password must be at least 8 characters and include uppercase, lowercase, digit, and special character.
            Changing your password will invalidate all other active sessions.
          </p>
          <div className="space-y-4 max-w-sm">
            <div>
              <label htmlFor="current-password" className="block text-sm font-medium text-zinc-300 mb-1">Current Password</label>
              <input
                id="current-password"
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
                autoComplete="current-password"
                className="w-full p-3 bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div>
              <label htmlFor="new-password" className="block text-sm font-medium text-zinc-300 mb-1">New Password</label>
              <input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
                autoComplete="new-password"
                className="w-full p-3 bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <div>
              <label htmlFor="confirm-password" className="block text-sm font-medium text-zinc-300 mb-1">Confirm New Password</label>
              <input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                autoComplete="new-password"
                className="w-full p-3 bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>
            <button
              onClick={changePassword}
              disabled={pwLoading || !currentPassword || !newPassword || !confirmPassword}
              className="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition disabled:opacity-50"
            >
              {pwLoading ? 'Changing...' : 'Change Password'}
            </button>
          </div>
        </div>
      </div>

      {/* MFA Section */}
      <div>
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <svg className="w-6 h-6 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          Two-Factor Authentication (MFA)
        </h2>

        {mfaMessage.type === 'success' && mfaMessage.text && (
          <div className="p-4 rounded-lg mb-4 bg-green-900/30 text-green-400 border border-green-800" role="status">
            {mfaMessage.text}
          </div>
        )}
        {mfaMessage.type === 'error' && mfaMessage.text && (
          <ErrorAlert
            error={mfaMessage.text}
            suggestion={mfaMessage.suggestion || ''}
            category={mfaMessage.category || 'auth'}
            onDismiss={() => setMfaMessage({ type: '', text: '' })}
            className="mb-4"
          />
        )}

        {/* Backup Codes Display */}
        {showBackupCodes && (
          <div className="bg-amber-900/30 border border-amber-700 rounded-lg p-4 mb-4">
            <h4 className="font-semibold text-amber-300 mb-2">Save Your Backup Codes</h4>
            <p className="text-sm text-amber-200 mb-3">Store these codes in a safe place. Each code can only be used once.</p>
            <div className="grid grid-cols-4 gap-2 mb-3">
              {showBackupCodes.map((code, i) => (
                <code key={i} className="bg-zinc-800 px-3 py-2 rounded text-center font-mono text-sm text-zinc-200">{code}</code>
              ))}
            </div>
            <button onClick={() => setShowBackupCodes(null)} className="text-sm text-amber-400 hover:text-amber-300">
              I've saved my codes
            </button>
          </div>
        )}

        <div className="bg-zinc-800/50 border border-zinc-700 rounded-lg p-6">
          {!mfaStatus.mfaEnabled ? (
            <>
              {!mfaSetup ? (
                <div>
                  <p className="text-zinc-300 mb-4">
                    Add an extra layer of security to your account by enabling two-factor authentication.
                    You'll need an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator.
                  </p>
                  <div className="flex gap-3">
                    <button
                      onClick={setupMfa}
                      disabled={mfaLoading}
                      className="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition disabled:opacity-50"
                    >
                      {mfaLoading ? 'Setting up...' : 'Enable MFA'}
                    </button>
                    <button
                      onClick={syncDatabase}
                      disabled={mfaLoading}
                      className="px-4 py-2 border border-zinc-700 text-zinc-400 rounded-lg hover:bg-zinc-800 transition disabled:opacity-50 text-sm"
                      title="Sync database schema if MFA is not working"
                    >
                      Sync Database
                    </button>
                  </div>
                </div>
              ) : (
                <div>
                  <h4 className="font-semibold text-zinc-100 mb-4">Step 1: Scan QR Code</h4>
                  <p className="text-sm text-zinc-400 mb-4">
                    Scan this QR code with your authenticator app, or manually enter the secret key.
                  </p>

                  <div className="flex flex-col md:flex-row items-start gap-6 mb-6">
                    <div className="bg-zinc-100 p-4 rounded-lg">
                      {!qrError && (
                        <img
                          src={mfaSetup.qrCodeUrl}
                          alt="MFA QR Code - scan with your authenticator app"
                          className="w-48 h-48"
                          onError={() => setQrError(true)}
                        />
                      )}
                      {qrError && (
                        <div className="text-center p-8 text-zinc-600 text-sm">
                          QR code failed to load.<br />Use manual entry below.
                        </div>
                      )}
                    </div>
                    <div>
                      <p className="text-sm text-zinc-400 mb-2">Secret Key (manual entry):</p>
                      <code className="block bg-zinc-900 px-4 py-2 rounded font-mono text-sm text-zinc-200 break-all mb-4">
                        {mfaSetup.secret}
                      </code>
                      {mfaSetup.otpauthUri && (
                        <details className="mb-4">
                          <summary className="text-xs text-zinc-500 cursor-pointer hover:text-zinc-400">Show full URI (for some apps)</summary>
                          <code className="block mt-2 bg-zinc-900 px-3 py-2 rounded font-mono text-xs text-zinc-400 break-all">
                            {mfaSetup.otpauthUri}
                          </code>
                        </details>
                      )}
                      <p className="text-xs text-zinc-500">Keep this secret safe. You'll need it if you lose your authenticator app.</p>
                    </div>
                  </div>

                  <h4 className="font-semibold text-zinc-100 mb-2">Step 2: Enter Verification Code</h4>
                  <div className="flex items-center gap-4">
                    <label htmlFor="mfa-verify-code" className="sr-only">6-digit verification code</label>
                    <input
                      id="mfa-verify-code"
                      type="text"
                      value={mfaToken}
                      onChange={(e) => setMfaToken(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      placeholder="000000"
                      maxLength={6}
                      className="w-40 p-3 bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-100 text-center text-xl tracking-widest font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                    <button
                      onClick={verifyMfa}
                      disabled={mfaLoading || mfaToken.length !== 6}
                      className="px-6 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition disabled:opacity-50"
                    >
                      {mfaLoading ? 'Verifying...' : 'Verify & Enable'}
                    </button>
                    <button
                      onClick={() => { setMfaSetup(null); setMfaToken(''); }}
                      className="px-4 py-2 border border-zinc-700 text-zinc-400 rounded-lg hover:bg-zinc-800 transition"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div>
              <div className="flex items-center gap-3 mb-4">
                <span className="flex items-center gap-2 px-3 py-1 bg-green-900/50 text-green-400 rounded-full text-sm border border-green-700">
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                  MFA Enabled
                </span>
                <span className="text-sm text-zinc-400">
                  {mfaStatus.backupCodesRemaining} backup codes remaining
                </span>
              </div>

              <div className="space-y-4">
                <div>
                  <label htmlFor="mfa-manage-password" className="block text-sm font-medium text-zinc-300 mb-2">
                    Enter your password to manage MFA
                  </label>
                  <input
                    id="mfa-manage-password"
                    type="password"
                    value={mfaPassword}
                    onChange={(e) => setMfaPassword(e.target.value)}
                    placeholder="Your current password"
                    autoComplete="current-password"
                    className="w-full max-w-sm p-3 bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={regenerateBackupCodes}
                    disabled={mfaLoading || !mfaPassword}
                    className="px-4 py-2 bg-amber-600 text-white rounded-lg hover:bg-amber-700 transition disabled:opacity-50"
                  >
                    Regenerate Backup Codes
                  </button>
                  <button
                    onClick={disableMfa}
                    disabled={mfaLoading || !mfaPassword}
                    className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition disabled:opacity-50"
                  >
                    Disable MFA
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* SSL/TLS Section */}
      <div>
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <svg className="w-6 h-6 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          SSL/TLS Certificates
        </h2>

        {sslMessage.type === 'success' && sslMessage.text && (
          <div className="p-4 rounded-lg mb-4 bg-green-900/30 text-green-400 border border-green-800" role="status">
            {sslMessage.text}
          </div>
        )}
        {sslMessage.type === 'error' && sslMessage.text && (
          <ErrorAlert
            error={sslMessage.text}
            suggestion={sslMessage.suggestion || ''}
            category={sslMessage.category || 'server'}
            onDismiss={() => setSslMessage({ type: '', text: '' })}
            className="mb-4"
          />
        )}

        <div className="bg-zinc-800/50 border border-zinc-700 rounded-lg p-6">
          {/* Current Status */}
          {sslConfig && (
            <div className="mb-6">
              <div className="flex items-center gap-3 mb-4">
                <span className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm border ${sslConfig.isEnabled ? 'bg-green-900/50 text-green-400 border-green-700' : 'bg-zinc-700 text-zinc-400 border-zinc-600'}`}>
                  {sslConfig.isEnabled ? (
                    <>
                      <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                        <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
                      </svg>
                      HTTPS Enabled
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                        <path d="M10 2a5 5 0 00-5 5v2a2 2 0 00-2 2v5a2 2 0 002 2h10a2 2 0 002-2v-5a2 2 0 00-2-2H7V7a3 3 0 015.905-.75 1 1 0 001.937-.5A5.002 5.002 0 0010 2z" />
                      </svg>
                      HTTP Only
                    </>
                  )}
                </span>
              </div>

              {sslConfig.certificateInfo && (
                <div className="bg-zinc-900 rounded-lg p-4 mb-4">
                  <h4 className="font-medium text-zinc-200 mb-2">Certificate Information</h4>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <span className="text-zinc-500">Common Name:</span>
                    <span className="text-zinc-300">{sslConfig.certificateInfo.commonName}</span>
                    <span className="text-zinc-500">Issuer:</span>
                    <span className="text-zinc-300">{sslConfig.certificateInfo.issuer}</span>
                    <span className="text-zinc-500">Uploaded:</span>
                    <span className="text-zinc-300">{new Date(sslConfig.certificateInfo.uploadedAt).toLocaleDateString()}</span>
                  </div>
                </div>
              )}

              {sslConfig.certificatePath && (
                <div className="flex gap-3 mb-6">
                  <button
                    onClick={() => toggleSsl(!sslConfig.isEnabled)}
                    disabled={sslLoading}
                    className={`px-4 py-2 rounded-lg transition disabled:opacity-50 ${sslConfig.isEnabled ? 'bg-amber-600 hover:bg-amber-700 text-white' : 'bg-green-600 hover:bg-green-700 text-white'}`}
                  >
                    {sslConfig.isEnabled ? 'Disable HTTPS' : 'Enable HTTPS'}
                  </button>
                  <button
                    onClick={deleteCertificates}
                    disabled={sslLoading}
                    className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition disabled:opacity-50"
                  >
                    Delete Certificates
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Upload Form */}
          <div>
            <h4 className="font-medium text-zinc-200 mb-4">
              {sslConfig?.certificatePath ? 'Replace Certificates' : 'Upload SSL Certificates'}
            </h4>
            <p className="text-sm text-zinc-400 mb-4">
              Upload your SSL certificate files to enable HTTPS. You'll need to restart the application after uploading.
            </p>

            <div className="space-y-4">
              <div>
                <label htmlFor="ssl-cert" className="block text-sm font-medium text-zinc-300 mb-2">
                  Certificate (.crt, .pem) <span className="text-red-400">*</span>
                </label>
                <input
                  id="ssl-cert"
                  type="file"
                  accept=".crt,.pem,.cer"
                  onChange={handleFileChange('certificate')}
                  className="w-full text-sm text-zinc-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-indigo-600 file:text-white hover:file:bg-indigo-700 file:cursor-pointer"
                />
              </div>

              <div>
                <label htmlFor="ssl-key" className="block text-sm font-medium text-zinc-300 mb-2">
                  Private Key (.key) <span className="text-red-400">*</span>
                </label>
                <input
                  id="ssl-key"
                  type="file"
                  accept=".key,.pem"
                  onChange={handleFileChange('privateKey')}
                  className="w-full text-sm text-zinc-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-indigo-600 file:text-white hover:file:bg-indigo-700 file:cursor-pointer"
                />
              </div>

              <div>
                <label htmlFor="ssl-ca" className="block text-sm font-medium text-zinc-300 mb-2">
                  CA Bundle (.crt, .pem) - Optional
                </label>
                <input
                  id="ssl-ca"
                  type="file"
                  accept=".crt,.pem,.cer"
                  onChange={handleFileChange('ca')}
                  className="w-full text-sm text-zinc-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-zinc-700 file:text-zinc-300 hover:file:bg-zinc-600 file:cursor-pointer"
                />
              </div>

              <button
                onClick={uploadCertificates}
                disabled={sslLoading || !sslFiles.certificate || !sslFiles.privateKey}
                className="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition disabled:opacity-50"
              >
                {sslLoading ? 'Uploading...' : 'Upload Certificates'}
              </button>
            </div>

            <div className="mt-6 p-4 bg-amber-900/20 border border-amber-800 rounded-lg">
              <h5 className="font-medium text-amber-300 mb-2">Important Notes:</h5>
              <ul className="text-sm text-amber-200 space-y-1 list-disc list-inside">
                <li>After uploading, you must restart the application for changes to take effect</li>
                <li>Update your docker-compose.yml to expose port 443 for HTTPS traffic</li>
                <li>Ensure your certificate chain is complete for browser trust</li>
                <li>Private keys should be kept secure and never shared</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Access Control Section */}
      <div>
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <svg className="w-6 h-6 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          Access Control
        </h2>

        {accessMessage.type === 'success' && accessMessage.text && (
          <div className="p-4 rounded-lg mb-4 bg-green-900/30 text-green-400 border border-green-800" role="status">
            {accessMessage.text}
          </div>
        )}
        {accessMessage.type === 'error' && accessMessage.text && (
          <ErrorAlert
            error={accessMessage.text}
            onDismiss={() => setAccessMessage({ type: '', text: '' })}
            className="mb-4"
          />
        )}

        <div className="bg-zinc-800/50 border border-zinc-700 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <h4 className="font-medium text-zinc-200">Require Authentication for Search & Export</h4>
              <p className="text-sm text-zinc-400 mt-1">
                When enabled, users must log in to search for IOCs, export results, and view search history.
                User permissions (canSearch, canHunt, canExport, canViewRepo) will be enforced server-side.
              </p>
              <p className="text-sm text-zinc-500 mt-1">
                When disabled, search, export, and history endpoints are publicly accessible without authentication.
              </p>
            </div>
            <button
              onClick={toggleSearchAuth}
              disabled={accessLoading}
              className={`relative inline-flex h-7 w-14 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-zinc-900 disabled:opacity-50 ${
                requireSearchAuth ? 'bg-indigo-600' : 'bg-zinc-600'
              }`}
              role="switch"
              aria-checked={requireSearchAuth}
              aria-label="Toggle search authentication requirement"
            >
              <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                requireSearchAuth ? 'translate-x-7' : 'translate-x-0'
              }`} />
            </button>
          </div>

          {requireSearchAuth && (
            <div className="mt-4 p-4 bg-indigo-900/20 border border-indigo-800 rounded-lg">
              <h5 className="font-medium text-indigo-300 mb-2">Authentication is active</h5>
              <ul className="text-sm text-indigo-200 space-y-1 list-disc list-inside">
                <li>Users must log in before searching or exporting</li>
                <li>Permissions (canSearch, canHunt, canExport, canViewRepo) are enforced</li>
                <li>The search page will redirect unauthenticated users to login</li>
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
