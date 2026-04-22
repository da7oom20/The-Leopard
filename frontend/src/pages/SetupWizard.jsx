import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSetup } from '../contexts/SetupContext';
import Footer from '../components/Footer';

const API_URL = process.env.REACT_APP_API_URL || '/api';

const SIEM_TYPES = [
  { value: 'logrhythm', label: 'LogRhythm' },
  { value: 'splunk', label: 'Splunk' },
  { value: 'qradar', label: 'IBM QRadar' },
  { value: 'elastic', label: 'Elastic / ELK' },
  { value: 'wazuh', label: 'Wazuh' },
  { value: 'manageengine', label: 'ManageEngine' }
];

export default function SetupWizard() {
  const navigate = useNavigate();
  const { isComplete, currentStep, nextStep, prevStep, updateSetup, completeSetup, resetSetup, mode } = useSetup();

  // Form states
  const [modeSelection, setModeSelection] = useState('standalone');
  const [showRerunConfirm, setShowRerunConfirm] = useState(false);
  const [dbStatus, setDbStatus] = useState({ testing: false, success: null, message: '' });
  const [siemForm, setSiemFormRaw] = useState({ client: '', siemType: '', apiHost: '', apiKey: '', verifySSL: false });
  const [siemStatus, setSiemStatus] = useState({ testing: false, success: null, message: '' });
  // Separate flag: did the SIEM actually land in the DB (POST /setup/add-siem success)?
  // testSiem() alone does NOT persist — it just hits the adapter with a throwaway client='setup-test'.
  const [siemSaved, setSiemSaved] = useState(false);
  // Editing the form invalidates any prior save, since add-siem uses the current form values.
  const setSiemForm = (next) => {
    setSiemFormRaw(next);
    setSiemSaved(false);
  };
  const [adminForm, setAdminForm] = useState({ username: '', password: '', confirmPassword: '' });
  const [adminStatus, setAdminStatus] = useState({ creating: false, success: null, message: '' });
  const [completing, setCompleting] = useState(false);
  const [requireSearchAuth, setRequireSearchAuth] = useState(true);

  const testDatabase = async () => {
    setDbStatus({ testing: true, success: null, message: 'Testing database connection...' });
    try {
      const res = await fetch(`${API_URL}/setup/test-db`, { method: 'POST' });
      const data = await res.json();
      setDbStatus({ testing: false, success: data.success, message: data.message || (data.success ? 'Database connected!' : 'Connection failed') });
      if (data.success) updateSetup({ dbConnected: true });
    } catch (err) {
      setDbStatus({ testing: false, success: false, message: 'Failed to test database connection' });
    }
  };

  const testSiem = async () => {
    if (!siemForm.siemType || !siemForm.apiHost) {
      setSiemStatus({ testing: false, success: false, message: 'SIEM type and API host are required' });
      return;
    }
    setSiemStatus({ testing: true, success: null, message: 'Testing SIEM connection...' });
    try {
      const res = await fetch(`${API_URL}/setup/test-siem`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(siemForm)
      });
      const data = await res.json();
      setSiemStatus({ testing: false, success: data.success, message: data.message || data.error });
    } catch (err) {
      setSiemStatus({ testing: false, success: false, message: 'Failed to test SIEM connection' });
    }
  };

  const saveSiem = async () => {
    if (siemStatus.testing) return;
    if (!siemForm.client || !siemForm.siemType || !siemForm.apiHost) {
      setSiemStatus({ testing: false, success: false, message: 'Client name, SIEM type, and API host are required' });
      return;
    }
    setSiemStatus({ testing: true, success: null, message: 'Saving SIEM configuration...' });
    try {
      // First create a temporary admin token for API calls during setup
      const res = await fetch(`${API_URL}/setup/add-siem`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(siemForm)
      });
      const data = await res.json();
      if (data.success) {
        setSiemStatus({ testing: false, success: true, message: 'SIEM connection saved!' });
        setSiemSaved(true);
        updateSetup({ siemConfigured: true });
        return true;
      } else {
        setSiemStatus({ testing: false, success: false, message: data.error || 'Failed to save SIEM' });
        return false;
      }
    } catch (err) {
      setSiemStatus({ testing: false, success: false, message: 'Failed to save SIEM configuration' });
      return false;
    }
  };

  // Continue button on the SIEM Setup step.
  //   - empty form           -> advance (user is deferring SIEM setup)
  //   - unsaved but valid    -> auto-save first, only advance if save succeeds
  //   - already saved        -> advance
  // Log-source mapping is not handled in the wizard anymore; the operator
  // configures it post-setup from Admin -> Field Mappings (a reminder shows
  // on the Complete step).
  const continueFromSiem = async () => {
    const hasData = siemForm.client && siemForm.siemType && siemForm.apiHost;
    if (!hasData) {
      nextStep();
      return;
    }
    if (!siemSaved) {
      const ok = await saveSiem();
      if (!ok) return; // stay on this step and show the error
    }
    nextStep();
  };

  const createAdmin = async () => {
    if (!adminForm.username || !adminForm.password) {
      setAdminStatus({ creating: false, success: false, message: 'Username and password are required' });
      return;
    }
    if (adminForm.password !== adminForm.confirmPassword) {
      setAdminStatus({ creating: false, success: false, message: 'Passwords do not match' });
      return;
    }
    if (adminForm.password.length < 6) {
      setAdminStatus({ creating: false, success: false, message: 'Password must be at least 6 characters' });
      return;
    }
    setAdminStatus({ creating: true, success: null, message: 'Creating admin user...' });
    try {
      const res = await fetch(`${API_URL}/setup/create-admin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: adminForm.username, password: adminForm.password })
      });
      const data = await res.json();
      if (data.success) {
        setAdminStatus({ creating: false, success: true, message: 'Admin user created!' });
        updateSetup({ adminCreated: true });
      } else {
        setAdminStatus({ creating: false, success: false, message: data.error || 'Failed to create admin' });
      }
    } catch (err) {
      setAdminStatus({ creating: false, success: false, message: 'Failed to create admin user' });
    }
  };

  const [completeError, setCompleteError] = useState('');
  const handleComplete = async () => {
    if (completing) return;
    setCompleting(true);
    setCompleteError('');
    try {
      // Save the search auth setting AND flip the setup-complete flag.
      // The server enforces that an admin user must already exist, so the
      // Admin User step must have been completed before this call can win.
      const res = await fetch(`${API_URL}/setup/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requireSearchAuth })
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setCompleteError(data.error || 'Failed to finalize setup. Please try again.');
        return;
      }
      await completeSetup();
      navigate('/login');
    } catch (err) {
      setCompleteError('Network error finalizing setup. Check backend connectivity and retry.');
    } finally {
      setCompleting(false);
    }
  };

  // Log Source Mapping intentionally lives outside the wizard now.
  // It's surfaced as a strongly-recommended post-setup task on the
  // Complete step, linking to Admin -> Field Mappings -> Log Source Mapping.
  const steps = [
    { id: 'welcome', title: 'Welcome' },
    { id: 'database', title: 'Database' },
    { id: 'siem', title: 'SIEM Setup' },
    { id: 'admin', title: 'Admin User' },
    { id: 'complete', title: 'Complete' }
  ];

  // If setup is already complete, show options
  if (isComplete && !showRerunConfirm) {
    return (
      <div className="min-h-screen bg-ink-950 text-ink-50 flex flex-col items-center justify-center p-6 grain">
        <div className="card-editorial p-10 max-w-md w-full text-center animate-fade-up">
          <div className="inline-flex items-center justify-center w-12 h-12 mb-6 border border-signal-jade/40 text-signal-jade">
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 12.5l5 5 9-11" />
            </svg>
          </div>
          <span className="eyebrow-amber">Field manual filed</span>
          <h2 className="mt-3 font-serif text-3xl text-ink-50 leading-tight"
              style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
            Setup is already complete.
          </h2>
          <p className="mt-3 text-ink-400 text-sm">
            Your console is configured. Return to the admin panel, or open this manual again to revise it.
          </p>
          <div className="mt-8 flex flex-col gap-2">
            <button onClick={() => navigate('/admin')} className="btn-amber w-full py-3">
              Back to Admin
            </button>
            <button onClick={() => navigate('/')} className="btn-ghost w-full py-3">
              Home
            </button>
            <button onClick={() => setShowRerunConfirm(true)}
                    className="mt-2 text-xs font-mono uppercase tracking-eyebrow text-signal-amber hover:text-signal-amber-soft transition-colors">
              Re-run setup wizard
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Confirm re-run
  if (isComplete && showRerunConfirm) {
    return (
      <div className="min-h-screen bg-ink-950 text-ink-50 flex flex-col items-center justify-center p-6 grain">
        <div className="card-editorial p-10 max-w-md w-full text-center animate-fade-up">
          <div className="inline-flex items-center justify-center w-12 h-12 mb-6 border border-signal-amber/50 text-signal-amber">
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3m0 4h.01M5.07 19h13.86a2 2 0 001.74-3L13.74 4a2 2 0 00-3.48 0L3.33 16a2 2 0 001.74 3z" />
            </svg>
          </div>
          <span className="eyebrow-amber">Confirm</span>
          <h2 className="mt-3 font-serif text-3xl text-ink-50 leading-tight"
              style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
            Re-open the manual?
          </h2>
          <p className="mt-3 text-ink-400 text-sm">
            Resets the setup state so you can reconfigure SIEMs, log sources, and the admin user.
            Existing data in the database is preserved.
          </p>
          <div className="mt-8 flex flex-col gap-2">
            <button onClick={() => { resetSetup(); setShowRerunConfirm(false); }} className="btn-amber w-full py-3">
              Yes, re-run
            </button>
            <button onClick={() => setShowRerunConfirm(false)} className="btn-ghost w-full py-3">
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-ink-950 text-ink-50 flex flex-col grain">
      {/* Editorial header */}
      <div className="border-b border-hairline-strong vignette-deep">
        <div className="max-w-5xl mx-auto px-6 py-10 flex items-baseline justify-between">
          <div>
            <span className="eyebrow-amber">Setup · The Leopard</span>
            <h1 className="mt-2 font-serif italic text-5xl leading-none tracking-tight wordmark-gradient"
                style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
              Field Manual
            </h1>
            <p className="mt-2 font-mono text-micro text-ink-500 tracking-wider-2">
              FIRST-RUN CONFIGURATION · VOLUME V
            </p>
          </div>
          <div className="hidden sm:flex flex-col items-end">
            <span className="font-mono text-micro text-ink-500 tracking-wider-2">
              Step {currentStep + 1} / {steps.length}
            </span>
            <span className="mt-2 font-serif italic text-2xl text-signal-amber"
                  style={{ fontVariationSettings: '"opsz" 60' }}>
              {steps[currentStep]?.title}
            </span>
          </div>
        </div>

        {/* Step rail */}
        <div className="max-w-5xl mx-auto px-6 pb-8">
          <div className="flex items-center w-full">
            {steps.map((step, idx) => {
              const done = idx < currentStep;
              const active = idx === currentStep;
              return (
                <React.Fragment key={step.id}>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <div className={`step-pip ${
                      active
                        ? 'border-signal-amber text-signal-amber bg-signal-amber/10'
                        : done
                          ? 'border-signal-jade text-signal-jade bg-signal-jade/10'
                          : 'border-ink-700 text-ink-500 bg-transparent'
                    }`}>
                      {done ? (
                        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 12.5l5 5 9-11" />
                        </svg>
                      ) : (
                        <span className="font-serif italic text-base"
                              style={{ fontVariationSettings: '"opsz" 60' }}>
                          {String(idx + 1).padStart(2, '0')}
                        </span>
                      )}
                    </div>
                    <span className={`hidden md:inline text-xs font-mono uppercase tracking-eyebrow ${
                      active ? 'text-signal-amber' : done ? 'text-ink-300' : 'text-ink-600'
                    }`}>
                      {step.title}
                    </span>
                  </div>
                  {idx < steps.length - 1 && (
                    <div className={`flex-1 h-px mx-3 ${done ? 'bg-signal-jade/40' : 'bg-hairline'}`} />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 py-12">
        <div className="max-w-3xl mx-auto px-6">
          <div className="card-editorial p-10 animate-fade-up">
            {/* Step 0: Welcome */}
            {currentStep === 0 && (
              <div>
                <span className="eyebrow-amber">Foreword</span>
                <h2 className="mt-3 font-serif text-4xl text-ink-50 leading-tight"
                    style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                  A short orientation, before the hunt.
                </h2>
                <p className="mt-4 text-ink-300 text-base leading-relaxed">
                  This wizard configures the database, your first SIEM connection, the log
                  sources you intend to query, and the admin operator who'll run the console.
                  Five steps, ten minutes — and you're tracking.
                </p>

                <div className="mt-10 mb-8">
                  <span className="eyebrow">Section · Deployment posture</span>
                  <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <button
                      onClick={() => setModeSelection('standalone')}
                      className={`group relative text-left p-6 border transition-colors ${
                        modeSelection === 'standalone'
                          ? 'border-signal-amber bg-signal-amber/5'
                          : 'border-ink-700 hover:border-ink-300 bg-ink-900/40'
                      }`}
                    >
                      <span className={`absolute top-4 right-4 font-serif italic text-3xl leading-none ${
                        modeSelection === 'standalone' ? 'text-signal-amber' : 'text-ink-700 group-hover:text-ink-500'
                      }`} style={{ fontVariationSettings: '"opsz" 144' }}>
                        I
                      </span>
                      <span className="block eyebrow mb-2">Standalone</span>
                      <span className={`block font-serif text-2xl leading-tight ${
                        modeSelection === 'standalone' ? 'text-ink-50' : 'text-ink-100'
                      }`} style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                        Single SIEM
                      </span>
                      <span className="mt-2 block text-sm text-ink-400">
                        One organization, one platform. Direct line, narrow scope.
                      </span>
                    </button>

                    <button
                      onClick={() => setModeSelection('mssp')}
                      className={`group relative text-left p-6 border transition-colors ${
                        modeSelection === 'mssp'
                          ? 'border-signal-amber bg-signal-amber/5'
                          : 'border-ink-700 hover:border-ink-300 bg-ink-900/40'
                      }`}
                    >
                      <span className={`absolute top-4 right-4 font-serif italic text-3xl leading-none ${
                        modeSelection === 'mssp' ? 'text-signal-amber' : 'text-ink-700 group-hover:text-ink-500'
                      }`} style={{ fontVariationSettings: '"opsz" 144' }}>
                        II
                      </span>
                      <span className="block eyebrow mb-2">MSSP</span>
                      <span className={`block font-serif text-2xl leading-tight ${
                        modeSelection === 'mssp' ? 'text-ink-50' : 'text-ink-100'
                      }`} style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                        Multiple SIEMs
                      </span>
                      <span className="mt-2 block text-sm text-ink-400">
                        Many clients, many platforms. Wide field, multiple ranges.
                      </span>
                    </button>
                  </div>
                </div>

                <div className="mt-10 pt-6 border-t border-hairline flex justify-end">
                  <button
                    onClick={() => { updateSetup({ mode: modeSelection }); nextStep(); }}
                    className="btn-amber"
                  >
                    Begin
                    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.75 6.75L19.25 12l-5.5 5.25M19 12H4.75" />
                    </svg>
                  </button>
                </div>
              </div>
            )}

            {/* Step 1: Database */}
            {currentStep === 1 && (
              <div>
                <h2 className="text-2xl font-bold mb-4">Database Connection</h2>
                <p className="text-zinc-400 mb-6">
                  Test your MySQL database connection. The database should already be configured
                  in your docker-compose.yml environment variables.
                </p>

                <div className="bg-zinc-800/50 p-4 rounded-lg mb-6">
                  <p className="text-sm text-zinc-400">
                    Default configuration uses MySQL container with:
                  </p>
                  <ul className="text-sm text-zinc-300 mt-2 space-y-1">
                    <li>Host: mysql-v5</li>
                    <li>Database: iocdb</li>
                    <li>User: root</li>
                  </ul>
                </div>

                {dbStatus.message && (
                  <div className={`p-4 rounded-lg mb-6 ${
                    dbStatus.success === true ? 'bg-green-900/30 text-green-400 border border-green-800' :
                    dbStatus.success === false ? 'bg-red-900/30 text-red-400 border border-red-800' :
                    'bg-yellow-900/30 text-yellow-400 border border-yellow-800'
                  }`} role={dbStatus.success === false ? 'alert' : 'status'}>
                    {dbStatus.message}
                  </div>
                )}

                <div className="flex gap-4">
                  <button
                    onClick={testDatabase}
                    disabled={dbStatus.testing}
                    className="px-6 py-2 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 transition disabled:opacity-50"
                  >
                    {dbStatus.testing ? 'Testing...' : 'Test Connection'}
                  </button>
                </div>

                <div className="flex justify-between mt-8 pt-6 border-t border-zinc-700">
                  <button onClick={prevStep} className="px-6 py-2 border border-zinc-700 rounded-lg text-zinc-300 hover:bg-zinc-800 transition">
                    Back
                  </button>
                  <button
                    onClick={nextStep}
                    disabled={!dbStatus.success}
                    className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition disabled:opacity-50"
                  >
                    Continue
                  </button>
                </div>
              </div>
            )}

            {/* Step 2: SIEM Setup */}
            {currentStep === 2 && (
              <div>
                <h2 className="text-2xl font-bold mb-4">SIEM Configuration</h2>
                <p className="text-zinc-400 mb-6">
                  Configure your first SIEM connection. You can add more SIEMs later in the Admin panel.
                </p>

                <div className="space-y-4 mb-6">
                  <div>
                    <label htmlFor="setup-siem-client" className="block text-sm font-medium text-zinc-300 mb-1">Client Name</label>
                    <input
                      id="setup-siem-client"
                      type="text"
                      value={siemForm.client}
                      onChange={(e) => setSiemForm({ ...siemForm, client: e.target.value })}
                      placeholder="Enter a name to identify this SIEM (e.g., Production, HQ-Security)"
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="setup-siem-type" className="block text-sm font-medium text-zinc-300 mb-1">SIEM Type</label>
                    <select
                      id="setup-siem-type"
                      value={siemForm.siemType}
                      onChange={(e) => setSiemForm({ ...siemForm, siemType: e.target.value })}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded-lg text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    >
                      <option value="">-- Choose your SIEM platform --</option>
                      {SIEM_TYPES.map(s => (
                        <option key={s.value} value={s.value}>{s.label}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="setup-siem-host" className="block text-sm font-medium text-zinc-300 mb-1">API Host URL</label>
                    <input
                      id="setup-siem-host"
                      type="text"
                      value={siemForm.apiHost}
                      onChange={(e) => setSiemForm({ ...siemForm, apiHost: e.target.value })}
                      placeholder="https://siem.yourcompany.com:8501 (include port if required)"
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="setup-siem-apikey" className="block text-sm font-medium text-zinc-300 mb-1">API Key / Token</label>
                    <input
                      id="setup-siem-apikey"
                      type="password"
                      value={siemForm.apiKey}
                      onChange={(e) => setSiemForm({ ...siemForm, apiKey: e.target.value })}
                      placeholder="Paste your SIEM API key or Bearer token here"
                      autoComplete="off"
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                  <div className="flex items-center gap-3">
                    <input
                      id="setup-siem-verifyssl"
                      type="checkbox"
                      checked={!!siemForm.verifySSL}
                      onChange={(e) => setSiemForm({ ...siemForm, verifySSL: e.target.checked })}
                      className="h-4 w-4 rounded border-zinc-600 bg-zinc-800 text-indigo-500 focus:ring-indigo-500"
                    />
                    <label htmlFor="setup-siem-verifyssl" className="text-sm text-zinc-300">
                      Verify SSL certificate
                      <span className="block text-xs text-zinc-500">
                        Uncheck if the SIEM uses a self-signed or internal-CA certificate.
                      </span>
                    </label>
                  </div>
                </div>

                {siemStatus.message && (
                  <div className={`p-4 rounded-lg mb-6 ${
                    siemStatus.success === true ? 'bg-green-900/30 text-green-400 border border-green-800' :
                    siemStatus.success === false ? 'bg-red-900/30 text-red-400 border border-red-800' :
                    'bg-yellow-900/30 text-yellow-400 border border-yellow-800'
                  }`} role={siemStatus.success === false ? 'alert' : 'status'}>
                    {siemStatus.message}
                  </div>
                )}

                <div className="flex gap-4">
                  <button
                    onClick={testSiem}
                    disabled={siemStatus.testing}
                    className="px-6 py-2 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 transition disabled:opacity-50"
                  >
                    {siemStatus.testing ? 'Testing...' : 'Test Connection'}
                  </button>
                  <button
                    onClick={saveSiem}
                    disabled={siemStatus.testing}
                    className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition disabled:opacity-50"
                  >
                    Save SIEM
                  </button>
                </div>

                <div className="flex justify-between mt-8 pt-6 border-t border-zinc-700">
                  <button onClick={prevStep} className="px-6 py-2 border border-zinc-700 rounded-lg text-zinc-300 hover:bg-zinc-800 transition">
                    Back
                  </button>
                  <button
                    onClick={continueFromSiem}
                    disabled={siemStatus.testing}
                    className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition disabled:opacity-50"
                  >
                    {!siemForm.client || !siemForm.siemType || !siemForm.apiHost
                      ? 'Skip for Now'
                      : siemSaved ? 'Continue' : 'Save & Continue'}
                  </button>
                </div>
              </div>
            )}


            {/* Step 3: Admin User */}
            {currentStep === 3 && (
              <div>
                <h2 className="text-2xl font-bold mb-4">Create Admin User</h2>
                <p className="text-zinc-400 mb-6">
                  Create your first admin user to access the Admin panel.
                </p>

                <div className="space-y-4 mb-6">
                  <div>
                    <label htmlFor="setup-admin-username" className="block text-sm font-medium text-zinc-300 mb-1">Username</label>
                    <input
                      id="setup-admin-username"
                      type="text"
                      value={adminForm.username}
                      onChange={(e) => setAdminForm({ ...adminForm, username: e.target.value })}
                      placeholder="Enter admin username (e.g., admin, security_admin)"
                      autoComplete="username"
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="setup-admin-password" className="block text-sm font-medium text-zinc-300 mb-1">Password</label>
                    <input
                      id="setup-admin-password"
                      type="password"
                      value={adminForm.password}
                      onChange={(e) => setAdminForm({ ...adminForm, password: e.target.value })}
                      placeholder="Create a strong password (min. 6 characters)"
                      autoComplete="new-password"
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                  <div>
                    <label htmlFor="setup-admin-confirm" className="block text-sm font-medium text-zinc-300 mb-1">Confirm Password</label>
                    <input
                      id="setup-admin-confirm"
                      type="password"
                      value={adminForm.confirmPassword}
                      onChange={(e) => setAdminForm({ ...adminForm, confirmPassword: e.target.value })}
                      placeholder="Re-enter password to confirm"
                      autoComplete="new-password"
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded-lg text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    />
                  </div>
                </div>

                {adminStatus.message && (
                  <div className={`p-4 rounded-lg mb-6 ${
                    adminStatus.success === true ? 'bg-green-900/30 text-green-400 border border-green-800' :
                    adminStatus.success === false ? 'bg-red-900/30 text-red-400 border border-red-800' :
                    'bg-yellow-900/30 text-yellow-400 border border-yellow-800'
                  }`} role={adminStatus.success === false ? 'alert' : 'status'}>
                    {adminStatus.message}
                  </div>
                )}

                <button
                  onClick={createAdmin}
                  disabled={adminStatus.creating}
                  className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition disabled:opacity-50"
                >
                  {adminStatus.creating ? 'Creating...' : 'Create Admin User'}
                </button>

                <div className="flex justify-between mt-8 pt-6 border-t border-zinc-700">
                  <button onClick={prevStep} className="px-6 py-2 border border-zinc-700 rounded-lg text-zinc-300 hover:bg-zinc-800 transition">
                    Back
                  </button>
                  <button
                    onClick={nextStep}
                    disabled={!adminStatus.success}
                    className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition disabled:opacity-50"
                  >
                    Continue
                  </button>
                </div>
              </div>
            )}

            {/* Step 4: Complete */}
            {currentStep === 4 && (
              <div className="text-center">
                <div className="text-6xl mb-6">🎉</div>
                <h2 className="text-2xl font-bold mb-4">Setup Complete!</h2>
                <p className="text-zinc-400 mb-8">
                  Your IOC Search App is ready to use. You can now log in to the Admin panel
                  to configure additional SIEMs, TI sources, and field mappings.
                </p>

                {/* Access Control Option */}
                <div className="bg-zinc-800/50 p-6 rounded-lg mb-6 text-left">
                  <h3 className="font-semibold mb-3">Access Control</h3>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-zinc-300 text-sm font-medium">Require login for Search & Export</p>
                      <p className="text-zinc-500 text-xs mt-1">
                        {requireSearchAuth
                          ? 'Users must log in to search, export, and view history. Recommended for most deployments.'
                          : 'Search, export, and history are publicly accessible without login.'}
                      </p>
                    </div>
                    <button
                      onClick={() => setRequireSearchAuth(!requireSearchAuth)}
                      className={`relative inline-flex h-7 w-14 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                        requireSearchAuth ? 'bg-indigo-600' : 'bg-zinc-600'
                      }`}
                      role="switch"
                      aria-checked={requireSearchAuth}
                      aria-label="Toggle search authentication"
                    >
                      <span className={`pointer-events-none inline-block h-6 w-6 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out ${
                        requireSearchAuth ? 'translate-x-7' : 'translate-x-0'
                      }`} />
                    </button>
                  </div>
                </div>

                {/* Highly-recommended post-setup task — log source mapping.
                    Without it, every IOC search scans every source in the
                    SIEM and will be dramatically slower (minutes per query
                    on LogRhythm, noticeable load on the SIEM itself). */}
                <div className="p-6 rounded-lg mb-6 text-left border border-amber-700/60 bg-amber-900/20">
                  <div className="flex items-start gap-3">
                    <svg className="w-6 h-6 text-amber-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.5" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456zM16.898 20.572L16.5 21.75l-.398-1.178a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.179-.398a2.25 2.25 0 001.423-1.423l.398-1.178.398 1.178a2.25 2.25 0 001.423 1.423l1.179.398-1.179.398a2.25 2.25 0 00-1.423 1.423z" />
                    </svg>
                    <div className="flex-1">
                      <h3 className="font-semibold text-amber-200 mb-1">
                        Highly recommended: configure Log Source Mapping
                      </h3>
                      <p className="text-sm text-zinc-300 leading-relaxed">
                        Pick which log sources, indexes, or agents each IOC type
                        should be queried against. Without a mapping, every
                        search scans every source in the SIEM — dramatically
                        slower on large deployments and noticeable load on
                        LogRhythm in particular.
                      </p>
                      <button
                        onClick={() => navigate('/admin?tab=mappings#log-source-mapping')}
                        className="mt-3 inline-flex items-center gap-2 px-4 py-2 bg-amber-600 text-white rounded font-medium text-sm hover:bg-amber-700 transition focus:outline-none focus:ring-2 focus:ring-amber-500 focus:ring-offset-2 focus:ring-offset-zinc-900"
                      >
                        Open Log Source Mapping
                        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden="true">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M13.75 6.75L19.25 12l-5.5 5.25M19 12H4.75" />
                        </svg>
                      </button>
                      <p className="text-xs text-zinc-500 mt-2">
                        (You'll be prompted to log in first, then dropped straight into Field Mappings → Log Source Mapping.)
                      </p>
                    </div>
                  </div>
                </div>

                <div className="bg-zinc-800/50 p-6 rounded-lg mb-8 text-left">
                  <h3 className="font-semibold mb-3">Other next steps</h3>
                  <ul className="space-y-2 text-zinc-400 text-sm">
                    <li>• Log in with your admin credentials</li>
                    <li>• Add more SIEM connections if needed</li>
                    <li>• Configure Threat Intelligence sources</li>
                    <li>• Use Field Discovery to discover SIEM fields</li>
                    <li>• Start searching for IOCs</li>
                  </ul>
                </div>

                {completeError && (
                  <div className="mb-4 p-3 border-l-2 border-red-500 bg-red-900/20 border-y border-r border-y-hairline border-r-hairline text-left" role="alert">
                    <p className="font-mono text-micro uppercase tracking-eyebrow text-red-400">Cannot finalize</p>
                    <p className="text-sm text-zinc-200 mt-1">{completeError}</p>
                  </div>
                )}
                <button
                  onClick={handleComplete}
                  disabled={completing}
                  className="px-8 py-3 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 transition disabled:opacity-50"
                >
                  {completing ? 'Completing...' : 'Finish Setup & Go to Login'}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <Footer />
    </div>
  );
}
