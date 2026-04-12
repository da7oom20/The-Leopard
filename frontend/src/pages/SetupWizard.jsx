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
  const [siemForm, setSiemForm] = useState({ client: '', siemType: '', apiHost: '', apiKey: '' });
  const [siemStatus, setSiemStatus] = useState({ testing: false, success: null, message: '' });
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
        updateSetup({ siemConfigured: true });
      } else {
        setSiemStatus({ testing: false, success: false, message: data.error || 'Failed to save SIEM' });
      }
    } catch (err) {
      setSiemStatus({ testing: false, success: false, message: 'Failed to save SIEM configuration' });
    }
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

  const handleComplete = async () => {
    if (completing) return;
    setCompleting(true);
    try {
      // Save the search auth setting during setup completion
      await fetch(`${API_URL}/setup/complete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requireSearchAuth })
      });
      await completeSetup();
      navigate('/login');
    } finally {
      setCompleting(false);
    }
  };

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
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col items-center justify-center p-6">
        <div className="bg-zinc-900 rounded-lg border border-zinc-700 p-8 max-w-md w-full text-center">
          <div className="text-5xl mb-4">✓</div>
          <h2 className="text-2xl font-bold mb-4">Setup Already Complete</h2>
          <p className="text-zinc-400 mb-6">
            Your IOC Search App is already configured. You can go back to the Admin panel or re-run the setup wizard.
          </p>
          <div className="flex flex-col gap-3">
            <button
              onClick={() => navigate('/admin')}
              className="w-full px-6 py-3 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition"
            >
              Back to Admin Panel
            </button>
            <button
              onClick={() => navigate('/')}
              className="w-full px-6 py-3 bg-zinc-700 text-white rounded-lg font-medium hover:bg-zinc-600 transition"
            >
              Go to Home
            </button>
            <button
              onClick={() => setShowRerunConfirm(true)}
              className="w-full px-6 py-3 border border-amber-600 text-amber-400 rounded-lg font-medium hover:bg-amber-900/30 transition"
            >
              Re-run Setup Wizard
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Confirm re-run
  if (isComplete && showRerunConfirm) {
    return (
      <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col items-center justify-center p-6">
        <div className="bg-zinc-900 rounded-lg border border-zinc-700 p-8 max-w-md w-full text-center">
          <div className="text-5xl mb-4">⚠️</div>
          <h2 className="text-2xl font-bold mb-4">Re-run Setup?</h2>
          <p className="text-zinc-400 mb-6">
            This will reset the setup status and allow you to reconfigure your SIEM connections and create a new admin user. Existing configurations will remain in the database.
          </p>
          <div className="flex flex-col gap-3">
            <button
              onClick={() => { resetSetup(); setShowRerunConfirm(false); }}
              className="w-full px-6 py-3 bg-amber-600 text-white rounded-lg font-medium hover:bg-amber-700 transition"
            >
              Yes, Re-run Setup
            </button>
            <button
              onClick={() => setShowRerunConfirm(false)}
              className="w-full px-6 py-3 border border-zinc-700 text-zinc-300 rounded-lg font-medium hover:bg-zinc-800 transition"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col">
      {/* Header */}
      <div className="bg-zinc-900 border-b border-zinc-800 py-6">
        <div className="max-w-3xl mx-auto px-6">
          <h1 className="text-3xl font-bold text-center bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">The Leopard</h1>
          <p className="text-zinc-400 text-center mt-1">Setup Wizard</p>
        </div>
      </div>

      {/* Progress */}
      <div className="bg-zinc-900/50 py-4 border-b border-zinc-800">
        <div className="max-w-3xl mx-auto px-6">
          <div className="flex justify-between">
            {steps.map((step, idx) => (
              <div key={step.id} className="flex items-center">
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
                  idx < currentStep ? 'bg-green-600 text-white' :
                  idx === currentStep ? 'bg-indigo-600 text-white' :
                  'bg-zinc-700 text-zinc-400'
                }`}>
                  {idx < currentStep ? '✓' : idx + 1}
                </div>
                <span className={`ml-2 text-sm hidden sm:inline ${idx === currentStep ? 'text-zinc-100' : 'text-zinc-500'}`}>
                  {step.title}
                </span>
                {idx < steps.length - 1 && (
                  <div className={`w-8 sm:w-16 h-0.5 mx-2 ${idx < currentStep ? 'bg-green-600' : 'bg-zinc-700'}`} />
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 py-8">
        <div className="max-w-2xl mx-auto px-6">
          <div className="bg-zinc-900 rounded-lg border border-zinc-700 p-8">
            {/* Step 0: Welcome */}
            {currentStep === 0 && (
              <div className="text-center">
                <h2 className="text-2xl font-bold mb-4">Welcome to The Leopard</h2>
                <p className="text-zinc-400 mb-8">
                  Let's set up your IOC Search App. This wizard will guide you through configuring
                  your database, SIEM connections, and creating your first admin user.
                </p>

                <div className="mb-8">
                  <h3 className="text-lg font-medium mb-4">Select Deployment Mode</h3>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      onClick={() => setModeSelection('standalone')}
                      className={`p-6 rounded-lg border-2 transition ${
                        modeSelection === 'standalone'
                          ? 'border-indigo-500 bg-indigo-900/30'
                          : 'border-zinc-700 hover:border-zinc-600'
                      }`}
                    >
                      <div className="text-2xl mb-2">🖥️</div>
                      <div className="font-semibold">Single SIEM</div>
                      <div className="text-sm text-zinc-400 mt-1">One organization with a single SIEM platform</div>
                    </button>
                    <button
                      onClick={() => setModeSelection('mssp')}
                      className={`p-6 rounded-lg border-2 transition ${
                        modeSelection === 'mssp'
                          ? 'border-indigo-500 bg-indigo-900/30'
                          : 'border-zinc-700 hover:border-zinc-600'
                      }`}
                    >
                      <div className="text-2xl mb-2">🌐</div>
                      <div className="font-semibold">Multiple SIEMs</div>
                      <div className="text-sm text-zinc-400 mt-1">Multiple SIEM platforms or clients to manage</div>
                    </button>
                  </div>
                </div>

                <button
                  onClick={() => { updateSetup({ mode: modeSelection }); nextStep(); }}
                  className="px-8 py-3 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition"
                >
                  Get Started
                </button>
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
                    onClick={nextStep}
                    className="px-6 py-2 bg-indigo-600 text-white rounded-lg font-medium hover:bg-indigo-700 transition"
                  >
                    {siemStatus.success ? 'Continue' : 'Skip for Now'}
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

                <div className="bg-zinc-800/50 p-6 rounded-lg mb-8 text-left">
                  <h3 className="font-semibold mb-3">Next Steps:</h3>
                  <ul className="space-y-2 text-zinc-400">
                    <li>• Log in with your admin credentials</li>
                    <li>• Add more SIEM connections if needed</li>
                    <li>• Configure Threat Intelligence sources</li>
                    <li>• Use Field Discovery to discover SIEM fields</li>
                    <li>• Start searching for IOCs!</li>
                  </ul>
                </div>

                <button
                  onClick={handleComplete}
                  disabled={completing}
                  className="px-8 py-3 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 transition disabled:opacity-50"
                >
                  {completing ? 'Completing...' : 'Go to Login'}
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
