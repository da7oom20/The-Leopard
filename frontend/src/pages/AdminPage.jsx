import React, { useState, useEffect, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import AuthContext from '../context/AuthContext';
import ReconSection from '../components/ReconSection';
import FieldMappingsTab from '../components/FieldMappingsTab';
import LogSourceMappingsSection from '../components/LogSourceMappingsSection';
import SecurityTab from '../components/SecurityTab';
import AuditLogsTab from '../components/AuditLogsTab';
import Footer from '../components/Footer';
import { LeopardLogoCompact } from '../components/Logo';
import ErrorAlert, { parseApiError } from '../components/ErrorAlert';
import { SESSION_EXPIRED_EVENT } from '../utils/apiClient';

// Axios interceptor: fire session-expired on auth failures (401 or 403 token errors)
axios.interceptors.response.use(
  response => response,
  error => {
    const status = error?.response?.status;
    const msg = error?.response?.data?.error || '';
    if (status === 401 || (status === 403 && (msg.includes('expired') || msg.includes('Invalid') || msg.includes('disabled')))) {
      window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
    }
    return Promise.reject(error);
  }
);

// SIEM type configurations with their required fields
const SIEM_CONFIGS = {
  logrhythm: {
    label: 'LogRhythm',
    fields: [
      { name: 'apiHost', label: 'API Host URL', type: 'text', required: true, placeholder: 'https://lr-api.yourcompany.com:8501' },
      { name: 'apiKey', label: 'API Key (Bearer Token)', type: 'password', required: true, placeholder: 'Paste your LogRhythm Bearer token here' },
      { name: 'verifySSL', label: 'Verify SSL Certificate', type: 'checkbox', required: false, defaultValue: false }
    ]
  },
  splunk: {
    label: 'Splunk',
    fields: [
      { name: 'apiHost', label: 'Splunk API Host', type: 'text', required: true, placeholder: 'https://splunk.yourcompany.com' },
      { name: 'port', label: 'Management Port', type: 'number', required: false, placeholder: '8089 (default)', defaultValue: 8089 },
      { name: 'apiKey', label: 'Auth Token', type: 'password', required: false, placeholder: 'Splunk auth token (leave empty if using username/password)' },
      { name: 'username', label: 'Username', type: 'text', required: false, placeholder: 'Splunk admin username' },
      { name: 'password', label: 'Password', type: 'password', required: false, placeholder: 'Splunk admin password' },
      { name: 'verifySSL', label: 'Verify SSL Certificate', type: 'checkbox', required: false, defaultValue: true }
    ]
  },
  qradar: {
    label: 'IBM QRadar',
    fields: [
      { name: 'apiHost', label: 'QRadar Console URL', type: 'text', required: true, placeholder: 'https://qradar.yourcompany.com' },
      { name: 'apiKey', label: 'SEC Token', type: 'password', required: true, placeholder: 'Paste your QRadar SEC authorization token' },
      { name: 'verifySSL', label: 'Verify SSL Certificate', type: 'checkbox', required: false, defaultValue: true }
    ]
  },
  wazuh: {
    label: 'Wazuh',
    fields: [
      { name: 'apiHost', label: 'Wazuh Manager URL', type: 'text', required: true, placeholder: 'https://wazuh-manager.yourcompany.com' },
      { name: 'port', label: 'API Port', type: 'number', required: false, placeholder: '55000 (default)', defaultValue: 55000 },
      { name: 'username', label: 'API Username', type: 'text', required: true, placeholder: 'wazuh-wui or your API username' },
      { name: 'password', label: 'API Password', type: 'password', required: true, placeholder: 'Enter Wazuh API password' },
      { name: 'extraConfig', label: 'Indexer URL (for log-level search)', type: 'text', required: false, placeholder: 'https://wazuh-indexer:9200 (leave empty for alerts-only mode)', fieldName: 'indexerUrl' },
      { name: 'verifySSL', label: 'Verify SSL Certificate', type: 'checkbox', required: false, defaultValue: false }
    ]
  },
  elastic: {
    label: 'Elastic / ELK',
    fields: [
      { name: 'apiHost', label: 'Elasticsearch URL', type: 'text', required: true, placeholder: 'https://elasticsearch.yourcompany.com:9200' },
      { name: 'apiKey', label: 'API Key (pre-encoded)', type: 'password', required: false, placeholder: 'Base64-encoded API key (leave empty if using username/password)' },
      { name: 'username', label: 'Username', type: 'text', required: false, placeholder: 'Elastic username (e.g., elastic)' },
      { name: 'password', label: 'Password', type: 'password', required: false, placeholder: 'Elastic password' },
      { name: 'extraConfig', label: 'Index Pattern', type: 'text', required: false, placeholder: 'logs-* or your index pattern', fieldName: 'indexPattern' },
      { name: 'verifySSL', label: 'Verify SSL Certificate', type: 'checkbox', required: false, defaultValue: true }
    ]
  },
  manageengine: {
    label: 'ManageEngine EventLog Analyzer',
    fields: [
      { name: 'apiHost', label: 'ManageEngine Server URL', type: 'text', required: true, placeholder: 'https://eventlog.yourcompany.com' },
      { name: 'port', label: 'Server Port', type: 'number', required: false, placeholder: '8400 (default)', defaultValue: 8400 },
      { name: 'apiKey', label: 'API Key', type: 'password', required: true, placeholder: 'Paste your ManageEngine API key' },
      { name: 'verifySSL', label: 'Verify SSL Certificate', type: 'checkbox', required: false, defaultValue: true }
    ]
  }
};

// TI platform configurations grouped by category
const TI_CONFIGS = {
  otx: { label: 'AlienVault OTX', category: 'API Platform', fields: [{ name: 'apiKey', label: 'API Key', type: 'password', required: true, placeholder: 'Get free API key from otx.alienvault.com' }], defaultUrl: 'https://otx.alienvault.com' },
  misp: { label: 'MISP', category: 'API Platform', fields: [{ name: 'apiUrl', label: 'MISP URL', type: 'text', required: true, placeholder: 'https://misp.yourcompany.com' }, { name: 'apiKey', label: 'Auth Key', type: 'password', required: true, placeholder: 'Your MISP automation key (from user profile)' }], defaultUrl: null },
  phishtank: { label: 'PhishTank', category: 'API Platform', fields: [{ name: 'apiKey', label: 'API Key (optional)', type: 'password', required: false, placeholder: 'Optional - provides faster feed updates' }], defaultUrl: 'https://data.phishtank.com' },
  threatfox: { label: 'ThreatFox', category: 'abuse.ch', fields: [], defaultUrl: null },
  urlhaus: { label: 'URLhaus', category: 'abuse.ch', fields: [], defaultUrl: null },
  malwarebazaar: { label: 'MalwareBazaar', category: 'abuse.ch', fields: [], defaultUrl: null },
  feodotracker: { label: 'Feodo Tracker', category: 'abuse.ch', fields: [], defaultUrl: null },
  sslbl: { label: 'SSL Blacklist (SSLBL)', category: 'abuse.ch', fields: [], defaultUrl: null },
  openphish: { label: 'OpenPhish', category: 'Phishing', fields: [], defaultUrl: null },
  blocklist_de: { label: 'Blocklist.de', category: 'IP Blocklist', fields: [], defaultUrl: null },
  emergingthreats: { label: 'Emerging Threats', category: 'IP Blocklist', fields: [], defaultUrl: null },
  spamhaus_drop: { label: 'Spamhaus DROP', category: 'IP Blocklist', fields: [], defaultUrl: null },
  firehol_l1: { label: 'FireHOL Level 1', category: 'IP Blocklist', fields: [], defaultUrl: null },
  talos: { label: 'Cisco Talos', category: 'IP Blocklist', fields: [], defaultUrl: null },
  crowdsec: { label: 'CrowdSec', category: 'IP Blocklist', fields: [], defaultUrl: null },
  c2intelfeeds: { label: 'C2 Intel Feeds', category: 'C2 & Malware', fields: [], defaultUrl: null },
  bambenek_c2: { label: 'Bambenek C2', category: 'C2 & Malware', fields: [], defaultUrl: null },
  digitalside: { label: 'DigitalSide Threat-Intel', category: 'C2 & Malware', fields: [], defaultUrl: null }
};

const TABS = [
  { id: 'siem', label: 'SIEM Clients' },
  { id: 'ti', label: 'TI Sources' },
  { id: 'recon', label: 'Field Discovery' },
  { id: 'mappings', label: 'Field Mappings' },
  { id: 'users', label: 'Users' },
  { id: 'security', label: 'Security' },
  { id: 'audit', label: 'Audit Logs' }
];

const getApiUrl = () => process.env.REACT_APP_API_URL || '/api';

export default function AdminPage() {
  const { token, logout } = useContext(AuthContext);
  const navigate = useNavigate();
  const API_URL = getApiUrl();

  const [activeTab, setActiveTab] = useState('siem');
  const [apiKeys, setApiKeys] = useState([]);
  const [form, setForm] = useState({
    client: '', siemType: '', apiHost: '', apiKey: '', username: '', password: '', port: '', verifySSL: true, extraConfig: {}
  });
  const [newUser, setNewUser] = useState({
    username: '', password: '', role: 'analyst',
    // Default permissions for new users (Feature permissions default true, Admin permissions default false)
    canSearch: true, canHunt: true, canExport: true, canViewRepo: true,
    canRecon: false, canManageSIEM: false, canManageTI: false,
    canManageMappings: false, canManageUsers: false, canManageSecurity: false
  });
  const [userMessage, setUserMessage] = useState('');
  const [siemLoading, setSiemLoading] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });

  // TI Sources state
  const [tiSources, setTiSources] = useState([]);
  const [tiForm, setTiForm] = useState({ name: '', platformType: '', apiUrl: '', apiKey: '' });
  const [tiTestResult, setTiTestResult] = useState(null);
  const [tiErrorInfo, setTiErrorInfo] = useState({ error: '', suggestion: '', category: '' });
  const [tiLoading, setTiLoading] = useState(false);
  const [userLoading, setUserLoading] = useState(false);

  // Back-compat: components that use a single `loading` see the aggregate
  const loading = siemLoading || tiLoading || userLoading;

  // Users state
  const [users, setUsers] = useState([]);
  const [editingUser, setEditingUser] = useState(null);
  const [editUserForm, setEditUserForm] = useState({
    username: '', password: '', role: '', isActive: true,
    canSearch: true, canHunt: true, canExport: true, canViewRepo: true,
    canManageSIEM: false, canManageTI: false, canRecon: false,
    canManageMappings: false, canManageUsers: false, canManageSecurity: false
  });

  // Handle 401 responses by logging out and redirecting to login
  const handleApiError = (err) => {
    if (err?.response?.status === 401) {
      logout();
      navigate('/login');
      return true;
    }
    return false;
  };

  const fetchApiKeys = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_URL}/admin/api-keys`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setApiKeys(res.data);
    } catch (err) {
      if (!handleApiError(err)) {
        setErrorInfo({ error: 'Failed to fetch SIEM connections.', suggestion: 'Check your session and try refreshing the page.', category: 'server' });
      }
    }
  };

  const fetchTiSources = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_URL}/admin/ti-sources`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setTiSources(res.data);
    } catch (err) {
      console.error('Failed to fetch TI sources:', err);
    }
  };

  const fetchUsers = async () => {
    if (!token) return;
    try {
      const res = await axios.get(`${API_URL}/admin/users`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUsers(res.data);
    } catch (err) {
      console.error('Failed to fetch users:', err);
    }
  };

  useEffect(() => {
    fetchApiKeys();
    fetchTiSources();
    fetchUsers();
  }, [token]);

  // Close edit user modal on Escape key, lock body scroll, and trap focus
  const editUserModalRef = React.useRef(null);
  useEffect(() => {
    if (!editingUser) return;
    const original = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKeyDown = (e) => {
      if (e.key === 'Escape') { setEditingUser(null); return; }
      if (e.key === 'Tab' && editUserModalRef.current) {
        const focusable = editUserModalRef.current.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey) {
          if (document.activeElement === first) { e.preventDefault(); last.focus(); }
        } else {
          if (document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.body.style.overflow = original;
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [editingUser]);

  const onChange = (e) => {
    const { name, value, type, checked } = e.target;
    setForm(prev => ({ ...prev, [name]: type === 'checkbox' ? checked : value }));
  };

  const onExtraConfigChange = (fieldName, value) => {
    setForm(prev => ({ ...prev, extraConfig: { ...prev.extraConfig, [fieldName]: value } }));
  };

  const onSiemTypeChange = (e) => {
    const siemType = e.target.value;
    const config = SIEM_CONFIGS[siemType];
    const defaults = { client: form.client, siemType };
    if (config) {
      config.fields.forEach(field => {
        defaults[field.name] = field.defaultValue !== undefined ? field.defaultValue : (field.type === 'checkbox' ? false : '');
      });
    }
    setForm({ ...defaults, extraConfig: {} });
  };

  const addApiKey = async () => {
    setErrorInfo({ error: '', suggestion: '', category: '' }); setTestResult(null);
    if (!form.client || !form.siemType || !form.apiHost) {
      setErrorInfo({ error: 'Client name, SIEM type, and API host are required.', suggestion: 'Fill in all required fields before adding the connection.', category: 'validation' });
      return;
    }
    setSiemLoading(true);
    try {
      await axios.post(`${API_URL}/admin/api-keys`, form, { headers: { Authorization: `Bearer ${token}` } });
      setForm({ client: '', siemType: '', apiHost: '', apiKey: '', username: '', password: '', port: '', verifySSL: true, extraConfig: {} });
      fetchApiKeys();
      setTestResult('SIEM connection added successfully!');
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({ error: parsed.error || 'Failed to add SIEM connection.', suggestion: parsed.suggestion || '', category: parsed.category || 'server' });
    } finally {
      setSiemLoading(false);
    }
  };

  const testApiKey = async () => {
    setErrorInfo({ error: '', suggestion: '', category: '' }); setTestResult(null);
    if (!form.siemType || !form.apiHost) {
      setErrorInfo({ error: 'SIEM type and API host are required for testing.', suggestion: 'Select a SIEM type and enter the API host URL.', category: 'validation' });
      return;
    }
    setSiemLoading(true);
    try {
      const res = await axios.post(`${API_URL}/admin/check-api-key`, form, { headers: { Authorization: `Bearer ${token}` } });
      if (res.data.success) {
        setTestResult(`Success: ${res.data.message}`);
      } else {
        setErrorInfo({
          error: res.data.error || 'Connection test failed.',
          suggestion: res.data.suggestion || '',
          category: res.data.category || 'connection'
        });
      }
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({
        error: parsed.error || 'Connection test failed.',
        suggestion: parsed.suggestion || 'Check the SIEM URL and credentials.',
        category: parsed.category || 'connection'
      });
    } finally {
      setSiemLoading(false);
    }
  };

  const deleteApiKey = async (id) => {
    if (!window.confirm('Are you sure you want to delete this API key?')) return;
    setSiemLoading(true);
    try {
      await axios.delete(`${API_URL}/admin/api-keys/${id}`, { headers: { Authorization: `Bearer ${token}` } });
      fetchApiKeys();
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({ error: parsed.error || 'Failed to delete SIEM connection.', suggestion: parsed.suggestion || '', category: parsed.category || 'server' });
    } finally {
      setSiemLoading(false);
    }
  };

  const createUser = async () => {
    if (userLoading) return;
    setUserMessage('');
    if (!newUser.username || !newUser.password) {
      setUserMessage('Username and password are required.');
      return;
    }
    setUserLoading(true);
    try {
      await axios.post(`${API_URL}/admin/users`, newUser, { headers: { Authorization: `Bearer ${token}` } });
      setUserMessage('User created successfully.');
      setNewUser({
        username: '', password: '', role: 'analyst',
        canSearch: true, canHunt: true, canExport: true, canViewRepo: true,
        canRecon: false, canManageSIEM: false, canManageTI: false,
        canManageMappings: false, canManageUsers: false, canManageSecurity: false
      });
      fetchUsers();
    } catch (err) {
      setUserMessage(err.response?.data?.error || 'Failed to create user.');
    } finally {
      setUserLoading(false);
    }
  };

  const openEditUser = (user) => {
    setEditingUser(user);
    setEditUserForm({
      username: user.username,
      password: '',
      role: user.role || 'analyst',
      isActive: user.isActive !== false,
      // Permissions
      canSearch: user.canSearch !== false,
      canHunt: user.canHunt !== false,
      canExport: user.canExport !== false,
      canViewRepo: user.canViewRepo !== false,
      canManageSIEM: user.canManageSIEM === true,
      canManageTI: user.canManageTI === true,
      canRecon: user.canRecon === true,
      canManageMappings: user.canManageMappings === true,
      canManageUsers: user.canManageUsers === true,
      canManageSecurity: user.canManageSecurity === true
    });
  };

  const updateUser = async () => {
    if (!editingUser || userLoading) return;
    setUserMessage('');
    setUserLoading(true);
    try {
      const payload = {
        username: editUserForm.username,
        role: editUserForm.role,
        isActive: editUserForm.isActive,
        // Permissions
        canSearch: editUserForm.canSearch,
        canHunt: editUserForm.canHunt,
        canExport: editUserForm.canExport,
        canViewRepo: editUserForm.canViewRepo,
        canManageSIEM: editUserForm.canManageSIEM,
        canManageTI: editUserForm.canManageTI,
        canRecon: editUserForm.canRecon,
        canManageMappings: editUserForm.canManageMappings,
        canManageUsers: editUserForm.canManageUsers,
        canManageSecurity: editUserForm.canManageSecurity
      };
      if (editUserForm.password) {
        payload.password = editUserForm.password;
      }
      await axios.put(`${API_URL}/admin/users/${editingUser.id}`, payload, { headers: { Authorization: `Bearer ${token}` } });
      setUserMessage('User updated successfully.');
      setEditingUser(null);
      fetchUsers();
    } catch (err) {
      setUserMessage(err.response?.data?.error || 'Failed to update user.');
    } finally {
      setUserLoading(false);
    }
  };

  const deleteUser = async (id, username) => {
    if (!window.confirm(`Are you sure you want to delete user "${username}"?`)) return;
    setUserMessage('');
    setUserLoading(true);
    try {
      await axios.delete(`${API_URL}/admin/users/${id}`, { headers: { Authorization: `Bearer ${token}` } });
      setUserMessage('User deleted successfully.');
      fetchUsers();
    } catch (err) {
      setUserMessage(err.response?.data?.error || 'Failed to delete user.');
    } finally {
      setUserLoading(false);
    }
  };

  const resetUserMfa = async (id, username) => {
    if (!window.confirm(`Are you sure you want to reset MFA for user "${username}"? They will need to set up MFA again.`)) return;
    setUserMessage('');
    setUserLoading(true);
    try {
      await axios.post(`${API_URL}/admin/users/${id}/mfa/reset`, {}, { headers: { Authorization: `Bearer ${token}` } });
      setUserMessage(`MFA has been reset for user ${username}.`);
      fetchUsers();
    } catch (err) {
      setUserMessage(err.response?.data?.error || 'Failed to reset MFA.');
    } finally {
      setUserLoading(false);
    }
  };

  // TI Source functions
  const onTiFormChange = (e) => {
    const { name, value } = e.target;
    setTiForm(prev => ({ ...prev, [name]: value }));
  };

  const onTiPlatformChange = (e) => {
    const platformType = e.target.value;
    const config = TI_CONFIGS[platformType];
    setTiForm({ name: tiForm.name, platformType, apiUrl: config?.defaultUrl || '', apiKey: '' });
  };

  const addTiSource = async () => {
    setTiErrorInfo({ error: '', suggestion: '', category: '' }); setTiTestResult(null);
    if (!tiForm.name || !tiForm.platformType) {
      setTiErrorInfo({ error: 'Name and platform type are required.', suggestion: 'Enter a name for the TI source and select its platform type.', category: 'validation' });
      return;
    }
    setTiLoading(true);
    try {
      await axios.post(`${API_URL}/admin/ti-sources`, tiForm, { headers: { Authorization: `Bearer ${token}` } });
      setTiForm({ name: '', platformType: '', apiUrl: '', apiKey: '' });
      fetchTiSources();
      setTiTestResult('TI source added successfully!');
    } catch (err) {
      const parsed = parseApiError(err);
      setTiErrorInfo({ error: parsed.error || 'Failed to add TI source.', suggestion: parsed.suggestion || '', category: parsed.category || 'server' });
    } finally {
      setTiLoading(false);
    }
  };

  const testTiSource = async () => {
    setTiErrorInfo({ error: '', suggestion: '', category: '' }); setTiTestResult(null);
    if (!tiForm.platformType) {
      setTiErrorInfo({ error: 'Platform type is required for testing.', suggestion: 'Select a TI platform type first.', category: 'validation' });
      return;
    }
    setTiLoading(true);
    try {
      const res = await axios.post(`${API_URL}/admin/ti-sources/test`, tiForm, { headers: { Authorization: `Bearer ${token}` } });
      if (res.data.success) {
        setTiTestResult(`Success: ${res.data.message}`);
      } else {
        setTiErrorInfo({
          error: res.data.error || 'TI source test failed.',
          suggestion: res.data.suggestion || '',
          category: res.data.category || 'connection'
        });
      }
    } catch (err) {
      const parsed = parseApiError(err);
      setTiErrorInfo({
        error: parsed.error || 'TI source test failed.',
        suggestion: parsed.suggestion || 'Check the TI source URL and API key.',
        category: parsed.category || 'connection'
      });
    } finally {
      setTiLoading(false);
    }
  };

  const deleteTiSource = async (id) => {
    if (!window.confirm('Are you sure you want to delete this TI source?')) return;
    setTiLoading(true);
    try {
      await axios.delete(`${API_URL}/admin/ti-sources/${id}`, { headers: { Authorization: `Bearer ${token}` } });
      fetchTiSources();
    } catch (err) {
      setTiErrorInfo({ error: 'Failed to delete TI source.', suggestion: 'Try again or check the backend logs.', category: 'server' });
    } finally {
      setTiLoading(false);
    }
  };

  const renderTiFields = () => {
    const config = TI_CONFIGS[tiForm.platformType];
    if (!config || config.fields.length === 0) {
      return <p className="col-span-2 text-sm text-zinc-500 italic">No additional configuration needed for this platform.</p>;
    }
    return config.fields.map((field) => (
      <div key={field.name}>
        <label htmlFor={`ti-${field.name}`} className="sr-only">{field.label}</label>
        <input
          id={`ti-${field.name}`}
          name={field.name}
          type={field.type}
          placeholder={field.placeholder || field.label}
          value={tiForm[field.name] || ''}
          onChange={onTiFormChange}
          autoComplete={field.type === 'password' ? 'off' : undefined}
          className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
      </div>
    ));
  };

  const renderSiemFields = () => {
    const config = SIEM_CONFIGS[form.siemType];
    if (!config) return null;
    return config.fields.map((field) => {
      if (field.type === 'checkbox') {
        return (
          <label key={field.name} className="flex items-center gap-2 col-span-2">
            <input type="checkbox" name={field.name} checked={form[field.name] || false} onChange={onChange} className="h-4 w-4 rounded border-zinc-600 bg-zinc-700 text-indigo-600" />
            <span className="text-sm text-zinc-300">{field.label}</span>
          </label>
        );
      }
      if (field.fieldName) {
        return (
          <div key={field.name}>
            <label htmlFor={`siem-${field.name}`} className="sr-only">{field.label}</label>
            <input id={`siem-${field.name}`} type={field.type} placeholder={field.placeholder || field.label} value={form.extraConfig?.[field.fieldName] || ''} onChange={(e) => onExtraConfigChange(field.fieldName, e.target.value)}
              className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
          </div>
        );
      }
      return (
        <div key={field.name}>
          <label htmlFor={`siem-${field.name}`} className="sr-only">{field.label}</label>
          <input id={`siem-${field.name}`} name={field.name} type={field.type} placeholder={field.placeholder || field.label} value={form[field.name] || ''} onChange={onChange}
            autoComplete={field.type === 'password' ? 'off' : undefined}
            className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
        </div>
      );
    });
  };

  return (
    <div className="flex flex-col min-h-screen bg-ink-950 text-ink-50 grain">
      {/* Editorial header band */}
      <header className="border-b border-hairline-strong vignette-deep">
        <div className="max-w-7xl mx-auto px-6 pt-8 pb-6 flex flex-col sm:flex-row justify-between items-start sm:items-end gap-6">
          <div>
            <span className="eyebrow-amber">The Leopard · Admin</span>
            <h1 className="mt-2 font-serif italic text-5xl leading-none tracking-tight wordmark-gradient"
                style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
              Console
            </h1>
            <p className="mt-2 font-mono text-micro text-ink-500 tracking-wider-2">
              CONFIGURATION · CLIENTS · MAPPINGS
            </p>
          </div>
          <nav className="flex items-center gap-2 flex-wrap" aria-label="Admin actions">
            <button onClick={() => navigate('/setup')} className="btn-ghost py-2">
              Setup
            </button>
            <button onClick={() => navigate('/')} className="btn-ghost py-2">
              Home
            </button>
            <button onClick={() => { logout(); navigate('/login'); }}
                    className="inline-flex items-center justify-center gap-2 px-4 py-2 bg-transparent text-signal-rust font-medium tracking-wider-2 uppercase text-sm border border-signal-rust/40 hover:bg-signal-rust/10 hover:border-signal-rust transition-colors focus:outline-none focus:ring-1 focus:ring-signal-rust">
              Sign Out
            </button>
          </nav>
        </div>
      </header>

      <div className="flex-1 max-w-7xl mx-auto p-6 w-full">

        {/* Tab Navigation — editorial small-caps strip */}
        <div className="border-b border-hairline-strong mb-8">
          <div className="flex items-end gap-1 overflow-x-auto -mb-px" role="tablist" aria-label="Admin panel sections">
            {TABS.map((tab, idx) => {
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  role="tab"
                  aria-selected={isActive}
                  aria-controls={`panel-${tab.id}`}
                  onClick={() => setActiveTab(tab.id)}
                  className={`group relative px-4 py-3 transition-colors whitespace-nowrap font-mono uppercase text-xs tracking-eyebrow border-b-2 ${
                    isActive
                      ? 'text-signal-amber border-signal-amber'
                      : 'text-ink-500 border-transparent hover:text-ink-200 hover:border-ink-700'
                  }`}
                >
                  <span className="opacity-60 mr-2 font-serif italic normal-case tracking-normal text-sm"
                        style={{ fontVariationSettings: '"opsz" 60' }}>
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Tab Content */}
        <div className="card-editorial p-8 animate-fade-up" role="tabpanel" id={`panel-${activeTab}`}>
          {/* SIEM Clients Tab */}
          {activeTab === 'siem' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">SIEM Connections</h2>
              <ErrorAlert
                error={errorInfo.error}
                suggestion={errorInfo.suggestion}
                category={errorInfo.category}
                onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
                onRetry={errorInfo.category === 'connection' ? testApiKey : undefined}
                className="mb-4"
              />
              {testResult && <p className={`mb-4 p-3 rounded ${testResult.includes('Success') ? 'text-green-400 bg-green-900/30 border border-green-800' : 'text-yellow-400 bg-yellow-900/30 border border-yellow-800'}`}>{testResult}</p>}

              <div className="mb-8">
                <h3 className="text-lg font-medium mb-4 text-zinc-300">Add New SIEM Connection</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <label htmlFor="siem-client-name" className="sr-only">Client name</label>
                    <input id="siem-client-name" name="client" placeholder="Enter a name to identify this SIEM (e.g., Production, DR-Site)" value={form.client} onChange={onChange}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                  </div>
                  <div>
                    <label htmlFor="siem-type-select" className="sr-only">SIEM type</label>
                    <select id="siem-type-select" name="siemType" value={form.siemType} onChange={onSiemTypeChange}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                    <option value="">-- Choose your SIEM platform --</option>
                    {Object.entries(SIEM_CONFIGS).map(([key, config]) => (
                      <option key={key} value={key}>{config.label}</option>
                    ))}
                  </select>
                  </div>
                </div>

                {form.siemType && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4 p-4 bg-zinc-800/50 border border-zinc-700 rounded">
                    <p className="col-span-2 text-sm text-zinc-400 mb-2">Configure {SIEM_CONFIGS[form.siemType]?.label} connection:</p>
                    {renderSiemFields()}
                  </div>
                )}

                <div className="flex gap-4">
                  <button onClick={addApiKey} disabled={siemLoading || !form.siemType} className="bg-indigo-600 text-white px-6 py-2 rounded hover:bg-indigo-700 transition disabled:opacity-50">
                    {siemLoading ? 'Working...' : 'Add SIEM Connection'}
                  </button>
                  <button onClick={testApiKey} disabled={siemLoading || !form.siemType} className="bg-green-600 text-white px-6 py-2 rounded hover:bg-green-700 transition disabled:opacity-50">
                    {siemLoading ? 'Testing...' : 'Test Connection'}
                  </button>
                </div>
              </div>

              <h3 className="text-lg font-medium mb-4 text-zinc-300">Existing SIEM Connections</h3>
              {apiKeys.length === 0 ? (
                <div className="text-center py-8 bg-zinc-800/30 rounded-lg border border-zinc-700">
                  <svg className="mx-auto h-10 w-10 text-zinc-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5.25 14.25h13.5m-13.5 0a3 3 0 01-3-3m3 3a3 3 0 100 6h13.5a3 3 0 100-6m-16.5-3a3 3 0 013-3h13.5a3 3 0 013 3m-19.5 0a4.5 4.5 0 01.9-2.7L5.737 5.1a3.375 3.375 0 012.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 01.9 2.7m0 0a3 3 0 01-3 3m0 3h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008zm-3 6h.008v.008h-.008v-.008zm0-6h.008v.008h-.008v-.008z" />
                  </svg>
                  <p className="text-zinc-500">No SIEM connections configured yet.</p>
                  <p className="text-zinc-600 text-sm mt-1">Add your first SIEM connection above to get started.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full border border-zinc-700">
                    <thead className="bg-zinc-800">
                      <tr>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Client</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">SIEM Type</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">API Host</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Status</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {apiKeys.map(({ id, client, siemType, apiHost, isActive }) => (
                        <tr key={id} className="hover:bg-zinc-800/50">
                          <td className="border border-zinc-700 px-4 py-2 text-zinc-200">{client}</td>
                          <td className="border border-zinc-700 px-4 py-2">
                            <span className="px-2 py-1 rounded text-sm bg-indigo-900/50 text-indigo-300 border border-indigo-700">{SIEM_CONFIGS[siemType]?.label || siemType}</span>
                          </td>
                          <td className="border border-zinc-700 px-4 py-2 break-all text-sm text-zinc-400">{apiHost}</td>
                          <td className="border border-zinc-700 px-4 py-2">
                            <span className={`px-2 py-1 rounded text-xs ${isActive !== false ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-zinc-700 text-zinc-400'}`}>
                              {isActive !== false ? 'Active' : 'Inactive'}
                            </span>
                          </td>
                          <td className="border border-zinc-700 px-4 py-2">
                            <button onClick={() => deleteApiKey(id)} disabled={siemLoading} className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 transition disabled:opacity-50 text-sm" aria-label={`Delete SIEM connection ${client}`}>Delete</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TI Sources Tab */}
          {activeTab === 'ti' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">Threat Intelligence Sources</h2>
              <ErrorAlert
                error={tiErrorInfo.error}
                suggestion={tiErrorInfo.suggestion}
                category={tiErrorInfo.category}
                onDismiss={() => setTiErrorInfo({ error: '', suggestion: '', category: '' })}
                onRetry={tiErrorInfo.category === 'connection' ? testTiSource : undefined}
                className="mb-4"
              />
              {tiTestResult && <p className={`mb-4 p-3 rounded ${tiTestResult.includes('Success') ? 'text-green-400 bg-green-900/30 border border-green-800' : 'text-yellow-400 bg-yellow-900/30 border border-yellow-800'}`}>{tiTestResult}</p>}

              <div className="mb-8">
                <h3 className="text-lg font-medium mb-4 text-zinc-300">Add New TI Source</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <label htmlFor="ti-source-name" className="sr-only">TI source name</label>
                    <input id="ti-source-name" name="name" placeholder="Give this TI source a name (e.g., Primary OTX, abuse.ch Feeds)" value={tiForm.name} onChange={onTiFormChange}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                  </div>
                  <div>
                    <label htmlFor="ti-platform-type" className="sr-only">TI platform type</label>
                    <select id="ti-platform-type" name="platformType" value={tiForm.platformType} onChange={onTiPlatformChange}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                    <option value="">-- Choose a threat intelligence platform --</option>
                    {(() => {
                      const groups = {};
                      Object.entries(TI_CONFIGS).forEach(([key, config]) => {
                        const cat = config.category || 'Other';
                        if (!groups[cat]) groups[cat] = [];
                        groups[cat].push({ key, label: config.label });
                      });
                      return Object.entries(groups).map(([cat, items]) => (
                        <optgroup key={cat} label={cat}>
                          {items.map(({ key, label }) => (<option key={key} value={key}>{label}</option>))}
                        </optgroup>
                      ));
                    })()}
                    </select>
                  </div>
                </div>

                {tiForm.platformType && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4 p-4 bg-zinc-800/50 border border-zinc-700 rounded">
                    <p className="col-span-2 text-sm text-zinc-400 mb-2">Configure {TI_CONFIGS[tiForm.platformType]?.label} connection:</p>
                    {renderTiFields()}
                  </div>
                )}

                <div className="flex gap-4">
                  <button onClick={addTiSource} disabled={tiLoading || !tiForm.platformType} className="bg-indigo-600 text-white px-6 py-2 rounded hover:bg-indigo-700 transition disabled:opacity-50">
                    {tiLoading ? 'Working...' : 'Add TI Source'}
                  </button>
                  <button onClick={testTiSource} disabled={tiLoading || !tiForm.platformType} className="bg-green-600 text-white px-6 py-2 rounded hover:bg-green-700 transition disabled:opacity-50">
                    {tiLoading ? 'Testing...' : 'Test Connection'}
                  </button>
                </div>
              </div>

              <h3 className="text-lg font-medium mb-4 text-zinc-300">Existing TI Sources</h3>
              {tiSources.length === 0 ? (
                <div className="text-center py-8 bg-zinc-800/30 rounded-lg border border-zinc-700">
                  <svg className="mx-auto h-10 w-10 text-zinc-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                  </svg>
                  <p className="text-zinc-500">No TI sources configured yet.</p>
                  <p className="text-zinc-600 text-sm mt-1">Add threat intelligence sources to enable hunt mode.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full border border-zinc-700">
                    <thead className="bg-zinc-800">
                      <tr>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Name</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Platform</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">API URL</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Status</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tiSources.map(({ id, name, platformType, apiUrl, isActive }) => (
                        <tr key={id} className="hover:bg-zinc-800/50">
                          <td className="border border-zinc-700 px-4 py-2 text-zinc-200">{name}</td>
                          <td className="border border-zinc-700 px-4 py-2">
                            <span className="px-2 py-1 rounded text-sm bg-amber-900/50 text-amber-300 border border-amber-700">{TI_CONFIGS[platformType]?.label || platformType}</span>
                            {TI_CONFIGS[platformType]?.category && <span className="ml-1 px-2 py-1 rounded text-xs bg-zinc-700 text-zinc-400">{TI_CONFIGS[platformType].category}</span>}
                          </td>
                          <td className="border border-zinc-700 px-4 py-2 break-all text-sm text-zinc-400">{apiUrl}</td>
                          <td className="border border-zinc-700 px-4 py-2">
                            <span className={`px-2 py-1 rounded text-xs ${isActive !== false ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-zinc-700 text-zinc-400'}`}>
                              {isActive !== false ? 'Active' : 'Inactive'}
                            </span>
                          </td>
                          <td className="border border-zinc-700 px-4 py-2">
                            <button onClick={() => deleteTiSource(id)} disabled={tiLoading} className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 transition disabled:opacity-50 text-sm" aria-label={`Delete TI source ${name}`}>Delete</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Recon Tab */}
          {activeTab === 'recon' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">Field Discovery</h2>
              <ReconSection apiKeys={apiKeys} token={token} API_URL={API_URL} SIEM_CONFIGS={SIEM_CONFIGS} />
            </div>
          )}

          {/* Field Mappings Tab */}
          {activeTab === 'mappings' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">Field Mappings</h2>
              <FieldMappingsTab token={token} API_URL={API_URL} apiKeys={apiKeys} SIEM_CONFIGS={SIEM_CONFIGS} />
              <LogSourceMappingsSection token={token} API_URL={API_URL} apiKeys={apiKeys} />
            </div>
          )}

          {/* Users Tab */}
          {activeTab === 'users' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">User Management</h2>
              {userMessage && <p className={`mb-4 p-3 rounded ${userMessage.includes('success') ? 'text-green-400 bg-green-900/30 border border-green-800' : 'text-red-400 bg-red-900/30 border border-red-800'}`} role="status">{userMessage}</p>}

              <div className="mb-8">
                <h3 className="text-lg font-medium mb-4 text-zinc-300">Add New User</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div>
                    <label htmlFor="new-user-username" className="sr-only">Username</label>
                    <input id="new-user-username" name="username" placeholder="Enter new username (e.g., john.doe)" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                  </div>
                  <div>
                    <label htmlFor="new-user-password" className="sr-only">Password</label>
                    <input id="new-user-password" name="password" placeholder="Create a secure password (min. 6 chars)" type="password" autoComplete="new-password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                  </div>
                  <div>
                    <label htmlFor="new-user-role" className="sr-only">Role</label>
                    <select id="new-user-role" value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                      className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                      <option value="admin">Admin</option>
                      <option value="analyst">Analyst</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </div>
                </div>

                {/* Permissions Grid - Beautiful Card Layout */}
                <div className="mb-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Feature Permissions Card */}
                  <div className="p-4 bg-gradient-to-br from-indigo-950/40 to-zinc-900 border border-indigo-800/50 rounded-lg">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="w-8 h-8 rounded-full bg-indigo-600/20 flex items-center justify-center">
                        <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                      </div>
                      <h4 className="text-sm font-semibold text-indigo-300">Feature Access</h4>
                    </div>
                    <div className="space-y-3">
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-indigo-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canSearch} onChange={(e) => setNewUser({ ...newUser, canSearch: e.target.checked })}
                          className="h-4 w-4 rounded border-indigo-600 bg-zinc-800 text-indigo-600 focus:ring-indigo-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Search IOCs</span>
                          <p className="text-xs text-zinc-500">Upload and search for indicators</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-indigo-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canHunt} onChange={(e) => setNewUser({ ...newUser, canHunt: e.target.checked })}
                          className="h-4 w-4 rounded border-indigo-600 bg-zinc-800 text-indigo-600 focus:ring-indigo-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Hunt Mode</span>
                          <p className="text-xs text-zinc-500">Automated threat hunting</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-indigo-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canExport} onChange={(e) => setNewUser({ ...newUser, canExport: e.target.checked })}
                          className="h-4 w-4 rounded border-indigo-600 bg-zinc-800 text-indigo-600 focus:ring-indigo-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Export Results</span>
                          <p className="text-xs text-zinc-500">Download CSV/JSON exports</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-indigo-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canViewRepo} onChange={(e) => setNewUser({ ...newUser, canViewRepo: e.target.checked })}
                          className="h-4 w-4 rounded border-indigo-600 bg-zinc-800 text-indigo-600 focus:ring-indigo-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">View Repository</span>
                          <p className="text-xs text-zinc-500">Access search history</p>
                        </div>
                      </label>
                    </div>
                  </div>

                  {/* Admin Permissions Card */}
                  <div className="p-4 bg-gradient-to-br from-amber-950/40 to-zinc-900 border border-amber-800/50 rounded-lg">
                    <div className="flex items-center gap-2 mb-4">
                      <div className="w-8 h-8 rounded-full bg-amber-600/20 flex items-center justify-center">
                        <svg className="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                      </div>
                      <h4 className="text-sm font-semibold text-amber-300">Admin Access</h4>
                    </div>
                    <div className="space-y-3">
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-amber-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canRecon} onChange={(e) => setNewUser({ ...newUser, canRecon: e.target.checked })}
                          className="h-4 w-4 rounded border-amber-600 bg-zinc-800 text-amber-600 focus:ring-amber-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Field Discovery</span>
                          <p className="text-xs text-zinc-500">Discover and analyze SIEM fields</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-amber-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canManageSIEM} onChange={(e) => setNewUser({ ...newUser, canManageSIEM: e.target.checked })}
                          className="h-4 w-4 rounded border-amber-600 bg-zinc-800 text-amber-600 focus:ring-amber-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Manage SIEM</span>
                          <p className="text-xs text-zinc-500">Add/edit SIEM connections</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-amber-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canManageTI} onChange={(e) => setNewUser({ ...newUser, canManageTI: e.target.checked })}
                          className="h-4 w-4 rounded border-amber-600 bg-zinc-800 text-amber-600 focus:ring-amber-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Manage TI Sources</span>
                          <p className="text-xs text-zinc-500">Configure threat intel feeds</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-amber-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canManageMappings} onChange={(e) => setNewUser({ ...newUser, canManageMappings: e.target.checked })}
                          className="h-4 w-4 rounded border-amber-600 bg-zinc-800 text-amber-600 focus:ring-amber-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Manage Mappings</span>
                          <p className="text-xs text-zinc-500">Edit field mappings</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-amber-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canManageUsers} onChange={(e) => setNewUser({ ...newUser, canManageUsers: e.target.checked })}
                          className="h-4 w-4 rounded border-amber-600 bg-zinc-800 text-amber-600 focus:ring-amber-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Manage Users</span>
                          <p className="text-xs text-zinc-500">Create/edit user accounts</p>
                        </div>
                      </label>
                      <label className="flex items-center gap-3 p-2 rounded-lg hover:bg-amber-900/20 transition cursor-pointer">
                        <input type="checkbox" checked={newUser.canManageSecurity} onChange={(e) => setNewUser({ ...newUser, canManageSecurity: e.target.checked })}
                          className="h-4 w-4 rounded border-amber-600 bg-zinc-800 text-amber-600 focus:ring-amber-500" />
                        <div>
                          <span className="text-sm font-medium text-zinc-200">Manage Security</span>
                          <p className="text-xs text-zinc-500">MFA & SSL configuration</p>
                        </div>
                      </label>
                    </div>
                  </div>
                </div>

                <button onClick={createUser} disabled={userLoading} className="bg-purple-600 text-white px-6 py-2 rounded hover:bg-purple-700 transition disabled:opacity-50">
                  {userLoading ? 'Creating...' : 'Add User'}
                </button>
              </div>

              <h3 className="text-lg font-medium mb-4 text-zinc-300">Existing Users</h3>
              {users.length === 0 ? (
                <div className="text-center py-8 bg-zinc-800/30 rounded-lg border border-zinc-700">
                  <svg className="mx-auto h-10 w-10 text-zinc-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
                  </svg>
                  <p className="text-zinc-500">No users found.</p>
                  <p className="text-zinc-600 text-sm mt-1">Create your first user account above.</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full border border-zinc-700">
                    <thead className="bg-zinc-800">
                      <tr>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Username</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Role</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Permissions</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Status</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">MFA</th>
                        <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map((user) => {
                        // Count permissions (4 features, 6 admin)
                        const featurePerms = [user.canSearch, user.canHunt, user.canExport, user.canViewRepo].filter(p => p !== false).length;
                        const adminPerms = [user.canRecon, user.canManageSIEM, user.canManageTI, user.canManageMappings, user.canManageUsers, user.canManageSecurity].filter(p => p === true).length;

                        return (
                          <tr key={user.id} className="hover:bg-zinc-800/50">
                            <td className="border border-zinc-700 px-4 py-2 text-zinc-200">{user.username}</td>
                            <td className="border border-zinc-700 px-4 py-2">
                              <span className={`px-2 py-1 rounded text-xs ${
                                user.role === 'admin' ? 'bg-purple-900/50 text-purple-300 border border-purple-700' :
                                user.role === 'analyst' ? 'bg-blue-900/50 text-blue-300 border border-blue-700' :
                                'bg-zinc-700 text-zinc-300'
                              }`}>
                                {user.role || 'analyst'}
                              </span>
                            </td>
                            <td className="border border-zinc-700 px-4 py-2">
                              <div className="flex gap-1 flex-wrap">
                                <span className="px-2 py-0.5 rounded text-xs bg-indigo-900/50 text-indigo-300 border border-indigo-700" title="Feature permissions: Search, Hunt, Export, Repository">
                                  {featurePerms}/4
                                </span>
                                {adminPerms > 0 && (
                                  <span className="px-2 py-0.5 rounded text-xs bg-amber-900/50 text-amber-300 border border-amber-700" title="Admin permissions: Field Discovery, SIEM, TI, Mappings, Users, Security">
                                    +{adminPerms} admin
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="border border-zinc-700 px-4 py-2">
                              <span className={`px-2 py-1 rounded text-xs ${user.isActive !== false ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-red-900/50 text-red-300 border border-red-700'}`}>
                                {user.isActive !== false ? 'Active' : 'Inactive'}
                              </span>
                            </td>
                            <td className="border border-zinc-700 px-4 py-2">
                              <div className="flex items-center gap-2">
                                <span className={`px-2 py-1 rounded text-xs ${user.mfaEnabled ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-zinc-700 text-zinc-400'}`}>
                                  {user.mfaEnabled ? 'On' : 'Off'}
                                </span>
                                {user.mfaEnabled && (
                                  <button
                                    onClick={() => resetUserMfa(user.id, user.username)}
                                    disabled={userLoading}
                                    className="text-xs text-amber-400 hover:text-amber-300 transition"
                                    title="Reset MFA for this user"
                                    aria-label={`Reset MFA for ${user.username}`}
                                  >
                                    Reset
                                  </button>
                                )}
                              </div>
                            </td>
                            <td className="border border-zinc-700 px-4 py-2">
                              <div className="flex gap-2">
                                <button
                                  onClick={() => openEditUser(user)}
                                  className="bg-indigo-600 text-white px-3 py-1 rounded hover:bg-indigo-700 transition text-sm"
                                  aria-label={`Edit user ${user.username}`}
                                >
                                  Edit
                                </button>
                                <button
                                  onClick={() => deleteUser(user.id, user.username)}
                                  disabled={userLoading || (user.role === 'admin' && users.filter(u => u.role === 'admin').length <= 1)}
                                  className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 transition disabled:opacity-50 text-sm"
                                  aria-label={`Delete user ${user.username}`}
                                >
                                  Delete
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Edit User Modal */}
              {editingUser && (
                <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50" role="dialog" aria-modal="true" aria-labelledby="edit-user-title" onClick={() => setEditingUser(null)}>
                  <div ref={editUserModalRef} className="bg-zinc-900 rounded-lg border border-zinc-700 p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto mx-4" onClick={e => e.stopPropagation()}>
                    <h3 id="edit-user-title" className="text-xl font-semibold mb-4">Edit User: {editingUser.username}</h3>

                    <div className="space-y-4 mb-6">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-zinc-300 mb-1">Username</label>
                          <input
                            type="text"
                            value={editUserForm.username}
                            onChange={(e) => setEditUserForm({ ...editUserForm, username: e.target.value })}
                            className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-zinc-300 mb-1">New Password (leave blank to keep)</label>
                          <input
                            type="password"
                            value={editUserForm.password}
                            onChange={(e) => setEditUserForm({ ...editUserForm, password: e.target.value })}
                            placeholder="Leave empty to keep existing"
                            autoComplete="new-password"
                            className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                          />
                        </div>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-zinc-300 mb-1">Role</label>
                          <select
                            value={editUserForm.role}
                            onChange={(e) => setEditUserForm({ ...editUserForm, role: e.target.value })}
                            className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                          >
                            <option value="admin">Admin</option>
                            <option value="analyst">Analyst</option>
                            <option value="viewer">Viewer</option>
                          </select>
                        </div>
                        <div className="flex items-end pb-1">
                          <label className="flex items-center gap-2">
                            <input
                              type="checkbox"
                              checked={editUserForm.isActive}
                              onChange={(e) => setEditUserForm({ ...editUserForm, isActive: e.target.checked })}
                              className="h-4 w-4 rounded border-zinc-600 bg-zinc-700 text-indigo-600"
                            />
                            <span className="text-sm text-zinc-300">Active (can log in)</span>
                          </label>
                        </div>
                      </div>

                      {/* Permissions Section - Beautiful Cards */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {/* Feature Permissions */}
                        <div className="p-4 bg-gradient-to-br from-indigo-950/40 to-zinc-800 border border-indigo-800/50 rounded-lg">
                          <div className="flex items-center gap-2 mb-3">
                            <div className="w-6 h-6 rounded-full bg-indigo-600/20 flex items-center justify-center">
                              <svg className="w-3 h-3 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                              </svg>
                            </div>
                            <span className="text-xs font-semibold text-indigo-300 uppercase tracking-wide">Features</span>
                          </div>
                          <div className="space-y-2">
                            {[
                              { key: 'canSearch', label: 'Search' },
                              { key: 'canHunt', label: 'Hunt' },
                              { key: 'canExport', label: 'Export' },
                              { key: 'canViewRepo', label: 'Repository' }
                            ].map(({ key, label }) => (
                              <label key={key} className="flex items-center gap-2 p-1.5 rounded hover:bg-indigo-900/20 transition cursor-pointer">
                                <input type="checkbox" checked={editUserForm[key]}
                                  onChange={(e) => setEditUserForm({ ...editUserForm, [key]: e.target.checked })}
                                  className="h-4 w-4 rounded border-indigo-600 bg-zinc-800 text-indigo-600" />
                                <span className="text-sm text-zinc-200">{label}</span>
                              </label>
                            ))}
                          </div>
                        </div>

                        {/* Admin Permissions */}
                        <div className="p-4 bg-gradient-to-br from-amber-950/40 to-zinc-800 border border-amber-800/50 rounded-lg">
                          <div className="flex items-center gap-2 mb-3">
                            <div className="w-6 h-6 rounded-full bg-amber-600/20 flex items-center justify-center">
                              <svg className="w-3 h-3 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                              </svg>
                            </div>
                            <span className="text-xs font-semibold text-amber-300 uppercase tracking-wide">Admin</span>
                          </div>
                          <div className="space-y-2">
                            {[
                              { key: 'canRecon', label: 'Field Discovery' },
                              { key: 'canManageSIEM', label: 'SIEM' },
                              { key: 'canManageTI', label: 'TI Sources' },
                              { key: 'canManageMappings', label: 'Mappings' },
                              { key: 'canManageUsers', label: 'Users' },
                              { key: 'canManageSecurity', label: 'Security' }
                            ].map(({ key, label }) => (
                              <label key={key} className="flex items-center gap-2 p-1.5 rounded hover:bg-amber-900/20 transition cursor-pointer">
                                <input type="checkbox" checked={editUserForm[key]}
                                  onChange={(e) => setEditUserForm({ ...editUserForm, [key]: e.target.checked })}
                                  className="h-4 w-4 rounded border-amber-600 bg-zinc-800 text-amber-600" />
                                <span className="text-sm text-zinc-200">{label}</span>
                              </label>
                            ))}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="flex gap-3 justify-end">
                      <button
                        onClick={() => setEditingUser(null)}
                        className="px-4 py-2 border border-zinc-700 rounded text-zinc-300 hover:bg-zinc-800 transition"
                      >
                        Cancel
                      </button>
                      <button
                        onClick={updateUser}
                        disabled={userLoading}
                        className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 transition disabled:opacity-50"
                      >
                        {userLoading ? 'Saving...' : 'Save Changes'}
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">Security Settings</h2>
              <SecurityTab token={token} API_URL={API_URL} onTokenUpdate={login} />
            </div>
          )}

          {/* Audit Logs Tab */}
          {activeTab === 'audit' && (
            <div>
              <h2 className="text-xl font-semibold mb-4">Audit Logs</h2>
              <AuditLogsTab token={token} API_URL={API_URL} />
            </div>
          )}
        </div>
      </div>

      <Footer />
    </div>
  );
}
