import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import HuntModal from '../components/HuntModal';
import Footer from '../components/Footer';
import { LeopardLogoCompact } from '../components/Logo';
import ErrorAlert from '../components/ErrorAlert';
import { apiFetch } from '../utils/apiClient';

/* === Dropdown with checkboxes inside === */
function ClientMultiSelectDropdown({
  allClients,
  setAllClients,
  selectedClients,
  setSelectedClients,
  options
}) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef(null);
  const menuRef = useRef(null);

  useEffect(() => {
    function onDocClick(e) {
      if (!btnRef.current || !menuRef.current) return;
      const withinButton = btnRef.current.contains(e.target);
      const withinMenu = menuRef.current.contains(e.target);
      if (!withinButton && !withinMenu) setOpen(false);
    }
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const summary = allClients
    ? 'All Clients'
    : selectedClients.length
      ? `${selectedClients.length} selected`
      : 'Select clients...';

  const toggleAll = (checked) => {
    setAllClients(checked);
    if (checked) setSelectedClients([]);
  };

  const toggleOne = (c, checked) => {
    setAllClients(false);
    setSelectedClients(prev =>
      checked ? [...new Set([...prev, c])] : prev.filter(x => x !== c)
    );
  };

  return (
    <div className="relative">
      <button
        type="button"
        ref={btnRef}
        onClick={() => setOpen(v => !v)}
        className="w-full p-2 border rounded-md bg-zinc-800 text-zinc-100 border-zinc-700 flex justify-between items-center hover:border-zinc-600 transition"
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span className="truncate">{summary}</span>
        <svg className={`w-4 h-4 ml-2 transition-transform ${open ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.71a.75.75 0 111.06 1.06l-4.24 4.25a.75.75 0 01-1.06 0L5.21 8.29a.75.75 0 01.02-1.08z" />
        </svg>
      </button>

      {open && (
        <div
          ref={menuRef}
          className="absolute z-20 mt-1 w-full max-h-64 overflow-auto rounded-md border border-zinc-700 bg-zinc-800 shadow-lg"
          role="listbox"
          tabIndex={-1}
        >
          <label className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-zinc-700">
            <input
              type="checkbox"
              checked={allClients}
              onChange={(e) => toggleAll(e.target.checked)}
              className="h-4 w-4 rounded border-zinc-600 bg-zinc-700 text-indigo-600 focus:ring-indigo-500"
            />
            <span className="font-medium text-zinc-100">All Clients</span>
          </label>

          <div className={`${allClients ? 'opacity-50 pointer-events-none' : ''}`}>
            {options.map(c => (
              <label
                key={c}
                className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-zinc-700"
              >
                <input
                  type="checkbox"
                  checked={selectedClients.includes(c)}
                  onChange={(e) => toggleOne(c, e.target.checked)}
                  className="h-4 w-4 rounded border-zinc-600 bg-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="text-zinc-200">{c}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

const API_URL = process.env.REACT_APP_API_URL || '/api';

export default function UploadPage() {
  const navigate = useNavigate();
  const fileInputRef = useRef(null);

  const [file, setFile] = useState(null);
  const [text, setText] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });
  const [searchPeriod, setSearchPeriod] = useState(5);
  const [dragActive, setDragActive] = useState(false);

  // Clients - fetched from backend
  const [clientOptions, setClientOptions] = useState([]);
  const [selectedClients, setSelectedClients] = useState([]);
  const [allClients, setAllClients] = useState(true);

  // Check if search auth is required
  const [searchAuthRequired, setSearchAuthRequired] = useState(false);
  useEffect(() => {
    apiFetch(`${API_URL}/settings/search-auth`)
      .then(r => r.json())
      .then(data => setSearchAuthRequired(!!data.requireSearchAuth))
      .catch(() => {});
  }, []);

  const getAuthHeaders = () => {
    if (!searchAuthRequired) return {};
    const token = localStorage.getItem('token');
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  useEffect(() => {
    const controller = new AbortController();
    apiFetch(`${API_URL}/clients`, { signal: controller.signal })
      .then(r => r.json())
      .then(data => {
        const names = data.map(c => c.name);
        setClientOptions([...new Set(names)]);
      })
      .catch((err) => {
        if (err.name !== 'AbortError') setClientOptions([]);
      });
    return () => controller.abort();
  }, []);

  // Hunt modal
  const [huntOpen, setHuntOpen] = useState(false);

  const [uploading, setUploading] = useState(false);
  const [uploadMessage, setUploadMessage] = useState('');
  const [searchSteps, setSearchSteps] = useState([]);
  const searchSseRef = useRef(null);

  // Export status
  const [exporting, setExporting] = useState(false);
  const [exportMsg, setExportMsg] = useState('');
  const [jsonExporting, setJsonExporting] = useState(false);
  const sseRef = useRef(null);
  const pollRef = useRef(null);

  const searchOptions = [
    { label: 'Last 5 minutes', value: 5 },
    { label: 'Last 15 minutes', value: 15 },
    { label: 'Last 30 minutes', value: 30 },
    { label: 'Last 1 hour', value: 60 },
    { label: 'Last 6 hours', value: 360 },
    { label: 'Last 12 hours', value: 720 },
    { label: 'Last 1 day', value: 1440 },
    { label: 'Last 3 days', value: 4320 },
    { label: 'Last 1 week', value: 10080 },
    { label: 'Last 1 month', value: 43200 },
    { label: 'Last 3 months', value: 129600 },
    { label: 'Last 6 months', value: 259200 },
    { label: 'Last 1 year', value: 525600 }
  ];

  // Cleanup SSE/poll on unmount
  useEffect(() => {
    return () => {
      if (sseRef.current) sseRef.current.close();
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const ALLOWED_EXTENSIONS = ['.pdf', '.xlsx', '.csv', '.txt'];

  function handleDrag(e) {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const droppedFile = e.dataTransfer?.files?.[0];
    if (droppedFile) {
      const fileName = droppedFile.name.toLowerCase();
      const isValid = ALLOWED_EXTENSIONS.some(ext => fileName.endsWith(ext));
      if (!isValid) {
        setErrorInfo({ error: `Invalid file type. Accepted formats: ${ALLOWED_EXTENSIONS.join(', ')}`, suggestion: 'Upload a PDF, XLSX, CSV, or TXT file containing your IOCs.', category: 'validation' });
        setFile(null);
        return;
      }
      setFile(droppedFile);
      setErrorInfo({ error: '', suggestion: '', category: '' });
      setResult(null);
    }
  }

  function onFileChange(e) {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      const fileName = selectedFile.name.toLowerCase();
      const isValid = ALLOWED_EXTENSIONS.some(ext => fileName.endsWith(ext));
      if (!isValid) {
        setErrorInfo({ error: `Invalid file type. Accepted formats: ${ALLOWED_EXTENSIONS.join(', ')}`, suggestion: 'Upload a PDF, XLSX, CSV, or TXT file containing your IOCs.', category: 'validation' });
        setFile(null);
        e.target.value = ''; // Reset file input
        return;
      }
    }
    setFile(selectedFile);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setResult(null);
  }

  function onTextChange(e) {
    setText(e.target.value);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setResult(null);
  }

  async function onSubmit(e) {
    e.preventDefault();
    if (!file && !text.trim()) {
      setErrorInfo({ error: 'Please upload a file or paste some text.', suggestion: 'Upload a PDF, XLSX, CSV, or TXT file, or paste IOC values in the text area.', category: 'validation' });
      return;
    }

    setLoading(true);
    setUploading(true);
    setUploadMessage("Uploading IOCs...");
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setResult(null);
    setSearchSteps([]);

    // Generate searchId so we can track progress via SSE
    const searchId = `search_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    // Open SSE for live progress
    try {
      const token = localStorage.getItem('token');
      const sseParams = new URLSearchParams({ searchId });
      if (searchAuthRequired && token) sseParams.set('token', token);
      const es = new EventSource(`${API_URL}/search-events?${sseParams}`);
      searchSseRef.current = es;
      es.onmessage = (evt) => {
        try {
          const d = JSON.parse(evt.data);
          if (d.newSteps && d.newSteps.length > 0) {
            setSearchSteps(prev => [...prev, ...d.newSteps]);
          }
          if (d.done) {
            setUploadMessage("Finalizing results...");
          }
        } catch {}
      };
      es.onerror = () => { /* SSE failure is non-fatal, progress just won't show */ };
    } catch {}

    try {
      const formData = new FormData();
      if (file) formData.append('file', file);
      if (text) formData.append('text', text);
      if (password) formData.append('password', password);
      formData.append('searchMinutesAgo', searchPeriod);
      formData.append('searchId', searchId);

      const clientPayload = allClients ? 'ALL' : selectedClients.join(',');
      formData.append('client', clientPayload);

      setUploadMessage("Searching SIEMs...");

      const res = await apiFetch(`${API_URL}/upload`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) {
        setErrorInfo({
          error: data.error || 'Upload failed.',
          suggestion: data.suggestion || '',
          category: data.category || ''
        });
        setUploadMessage("Upload failed. Please try again.");
        return;
      }

      setResult(data);
      setFile(null);
      if (fileInputRef.current) fileInputRef.current.value = '';
      setText('');
      setUploadMessage("Done! Search completed successfully.");
    } catch (err) {
      setErrorInfo({ error: err.message || 'Upload failed.', suggestion: 'Check your network connection and try again.', category: 'connection' });
      setUploadMessage("Upload failed. Please try again.");
    } finally {
      setLoading(false);
      setUploading(false);
      if (searchSseRef.current) { searchSseRef.current.close(); searchSseRef.current = null; }
    }
  }

  // --- Export status wire-up (SSE with polling fallback) ---
  const startStatusStream = () => {
    try {
      const token = localStorage.getItem('token');
      const sseUrl = searchAuthRequired && token
        ? `${API_URL}/export-events?token=${encodeURIComponent(token)}`
        : `${API_URL}/export-events`;
      const es = new EventSource(sseUrl);
      sseRef.current = es;

      es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data || '{}');
          const { exporting: isExporting } = data;
          setExporting(!!isExporting);
          setExportMsg(isExporting ? 'Preparing your CSV...' : 'Export complete.');
          if (!isExporting) {
            es.close();
            sseRef.current = null;
          }
        } catch {
          // ignore bad frames
        }
      };

      es.onerror = () => {
        es.close();
        sseRef.current = null;
        startStatusPolling();
      };
    } catch {
      startStatusPolling();
    }
  };

  const startStatusPolling = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    const poll = async () => {
      try {
        const r = await apiFetch(`${API_URL}/export-status`, { headers: getAuthHeaders() });
        const j = await r.json();
        const isExporting = !!j.exporting;
        setExporting(isExporting);
        setExportMsg(isExporting ? 'Preparing your CSV...' : 'Export complete.');
        if (!isExporting && pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
      } catch {
        // ignore
      }
    };
    poll();
    pollRef.current = setInterval(poll, 2000);
  };

  const exportFromServer = async (format = 'kv') => {
    if (exporting) return;
    setExporting(true);
    setExportMsg('Starting export...');
    startStatusStream();

    try {
      const params = new URLSearchParams();
      params.set('layout', format === 'wide' ? 'flat' : 'block');

      if (result?.resultIds?.length) {
        params.set('ids', result.resultIds.join(','));
      }

      const BASE_URL = API_URL.replace(/\/api\/?$/, '');
      const res = await apiFetch(`${BASE_URL}/export-results?${params.toString()}`, { headers: getAuthHeaders() });
      if (!res.ok) {
        setExporting(false);
        setExportMsg('');
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || 'Export failed');
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = format === 'wide' ? 'siem_results_wide.csv' : 'siem_results_tidy.csv';
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErrorInfo({ error: e.message || 'Export failed.', suggestion: 'Try exporting again. If the problem persists, check the backend logs.', category: 'server' });
    } finally {
      setTimeout(() => {
        setExporting(false);
        setExportMsg('');
        if (sseRef.current) { sseRef.current.close(); sseRef.current = null; }
        if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
      }, 1500);
    }
  };

  const exportJsonFromServer = async () => {
    if (jsonExporting) return;
    setJsonExporting(true);
    try {
      const res = await apiFetch(`${API_URL}/export-json`, { headers: getAuthHeaders() });
      if (!res.ok) throw new Error('JSON export failed');
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'search-results.json';
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setErrorInfo({ error: e.message || 'JSON export failed.', suggestion: 'Try exporting again. If the problem persists, check the backend logs.', category: 'server' });
    } finally {
      setJsonExporting(false);
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-zinc-950 text-zinc-100">
      <div className="flex-1 p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
        <div className="flex items-center gap-3">
          <LeopardLogoCompact size={40} showText={false} />
          <div>
            <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
              The Leopard
            </h1>
            <p className="text-zinc-400 text-xs">IOC Search & Analysis</p>
          </div>
        </div>
        <nav className="flex items-center gap-3 flex-wrap" aria-label="Main navigation">
          <button
            onClick={() => setHuntOpen(true)}
            className="px-4 py-2 rounded-md bg-amber-600 text-white hover:bg-amber-700 font-semibold transition focus:outline-none focus:ring-2 focus:ring-amber-500 focus:ring-offset-2 focus:ring-offset-zinc-950"
            aria-label="Open threat hunt modal"
          >
            Hunt
          </button>
          <button
            onClick={() => navigate('/repo')}
            className="px-4 py-2 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-zinc-950"
          >
            Searches Repo
          </button>
          <button
            onClick={() => navigate('/admin')}
            className="px-4 py-2 rounded-md bg-purple-600 text-white hover:bg-purple-700 transition focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 focus:ring-offset-zinc-950"
          >
            Admin Panel
          </button>
        </nav>
      </div>

      {/* Form */}
      <form onSubmit={onSubmit} className="space-y-6" aria-label="IOC upload form">
        {/* Period & Client */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label htmlFor="search-period" className="block mb-1 font-medium text-zinc-300">Search Period</label>
            <select
              id="search-period"
              value={searchPeriod}
              onChange={(e) => setSearchPeriod(Number(e.target.value))}
              className="w-full p-2 border rounded-md bg-zinc-800 text-zinc-100 border-zinc-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              {searchOptions.map(({ label, value }) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
            {searchPeriod >= 129600 && (
              <div className="mt-2 p-3 bg-amber-900/50 border border-amber-700 rounded-md">
                <p className="text-amber-300 text-sm font-medium flex items-center gap-2">
                  <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  Warning: Large Search Period
                </p>
                <p className="text-amber-200 text-xs mt-1">
                  Searching 3+ months of data may take a long time and could timeout. Consider using a shorter period or searching specific clients only.
                </p>
              </div>
            )}
          </div>

          <div>
            <label className="block mb-1 font-medium text-zinc-300">Target Clients</label>
            <ClientMultiSelectDropdown
              allClients={allClients}
              setAllClients={setAllClients}
              selectedClients={selectedClients}
              setSelectedClients={setSelectedClients}
              options={clientOptions}
            />
            {!allClients && selectedClients.length === 0 && (
              <div className="text-xs text-yellow-400 mt-2">
                Select at least one client or toggle "All Clients".
              </div>
            )}
          </div>
        </div>

        {/* Upload Areas */}
        <div className="flex flex-col md:flex-row gap-6">
          {/* File Upload */}
          <div className="flex-1 bg-zinc-900 shadow-lg rounded-lg p-6 border border-zinc-700">
            <h2 className="text-xl font-semibold mb-4 text-zinc-100">Upload File</h2>
            <label
              htmlFor="fileUpload"
              className={`block cursor-pointer border-2 border-dashed rounded-md p-8 text-center transition-colors ${
                dragActive
                  ? 'border-indigo-500 bg-indigo-900/20 text-indigo-400'
                  : 'border-zinc-700 text-zinc-400 hover:border-indigo-500 hover:text-indigo-400'
              }`}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
            >
              {file ? (
                <div>
                  <svg className="mx-auto h-8 w-8 text-indigo-400 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                  </svg>
                  <p className="text-zinc-200 font-medium">{file.name}</p>
                </div>
              ) : (
                <>
                  <svg className="mx-auto h-10 w-10 text-zinc-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                  </svg>
                  <p>Drag & drop a file here, or click to browse</p>
                  <p className="text-xs text-zinc-500 mt-2">Accepted formats: PDF, XLSX, CSV, TXT</p>
                </>
              )}
              <input id="fileUpload" type="file" className="hidden" accept=".pdf,.xlsx,.csv,.txt" onChange={onFileChange} ref={fileInputRef} aria-label="Upload IOC file" />
            </label>
            <label htmlFor="pdf-password" className="sr-only">PDF password</label>
            <input
              id="pdf-password"
              type="password"
              placeholder="PDF password (only if file is encrypted)"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              className="mt-4 p-2 border rounded-md w-full bg-zinc-800 text-zinc-100 border-zinc-700 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            {file && (
              <button
                type="button"
                onClick={() => setFile(null)}
                className="mt-3 text-sm text-red-400 hover:underline"
              >
                Remove file
              </button>
            )}
          </div>

          {/* Text Paste */}
          <div className="flex-1 bg-zinc-900 shadow-lg rounded-lg p-6 border border-zinc-700 flex flex-col">
            <h2 className="text-xl font-semibold mb-4 text-zinc-100">Paste Text</h2>
            <textarea
              rows={10}
              placeholder="Paste IOCs here - one per line or comma-separated.&#10;&#10;Examples:&#10;192.168.1.100&#10;malware.evil-domain.com&#10;e99a18c428cb38d5f260853678922e03&#10;hxxps://phishing[.]site/login"
              className="flex-grow p-3 border rounded-md resize-none focus:ring-2 focus:ring-indigo-500 bg-zinc-800 text-zinc-100 border-zinc-700 placeholder-zinc-500 focus:outline-none transition-colors"
              value={text}
              onChange={onTextChange}
              aria-label="Paste IOC text"
            />
            {text && (
              <button
                type="button"
                onClick={() => setText('')}
                className="mt-3 self-end text-sm text-red-400 hover:underline"
              >
                Clear text
              </button>
            )}
          </div>
        </div>

        {/* Submit Button */}
        <div className="text-center mt-6">
          <button
            type="submit"
            disabled={loading || (!allClients && selectedClients.length === 0)}
            className="px-8 py-3 bg-indigo-600 text-white font-semibold rounded-md hover:bg-indigo-700 disabled:opacity-50 transition focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-zinc-950 inline-flex items-center gap-2"
          >
            {loading && (
              <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
            )}
            {loading ? 'Processing...' : 'Submit'}
          </button>
        </div>
      </form>

      {/* Upload / Export Progress */}
      {(uploading || exporting) && (
        <div className="mt-6 max-w-xl mx-auto p-4 bg-yellow-900/50 text-yellow-200 border border-yellow-700 rounded-md" role="status" aria-live="polite">
          <div className="flex items-center justify-center gap-3">
            <svg className="animate-spin h-5 w-5 text-yellow-300 flex-shrink-0" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <span>{uploading ? uploadMessage : (exportMsg || 'Exporting...')}</span>
          </div>
          {uploading && searchSteps.length > 0 && (
            <div className="mt-3 space-y-1 text-xs max-h-40 overflow-y-auto">
              {searchSteps.map((step, i) => (
                <div key={i} className="flex items-center gap-2">
                  <span className={`inline-block w-2 h-2 rounded-full flex-shrink-0 ${
                    step.status === 'hit' ? 'bg-green-400' : step.status === 'error' ? 'bg-red-400' : 'bg-zinc-500'
                  }`} />
                  <span className="text-yellow-100">{step.client}</span>
                  <span className="text-yellow-300/60">{step.filterType}</span>
                  <span className={`ml-auto font-medium ${
                    step.status === 'hit' ? 'text-green-400' : step.status === 'error' ? 'text-red-400' : 'text-zinc-400'
                  }`}>{step.status}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Errors */}
      <ErrorAlert
        error={errorInfo.error}
        suggestion={errorInfo.suggestion}
        category={errorInfo.category}
        onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
        onRetry={errorInfo.category === 'connection' ? () => onSubmit({ preventDefault: () => {} }) : undefined}
        className="mt-6 max-w-xl mx-auto"
      />

      {/* Results */}
      {result && (
        <div className="mt-6 max-w-4xl mx-auto space-y-6" role="region" aria-live="polite" aria-label="Search results">
          {result.siemResults && (
            <div className="bg-zinc-900 shadow-md rounded-lg border border-zinc-700 p-6">
              <h3 className="text-xl font-bold mb-4 text-zinc-100">SIEM Results by Client</h3>
              <ul className="divide-y divide-zinc-800">
                {[...new Set(result.siemResults.map(r => r.client))].map((client) => (
                  <li key={client} className="py-2">
                    <div className="text-lg font-semibold text-indigo-400 mb-1">{client}</div>
                    <ul className="pl-4">
                      {result.siemResults
                        .filter(r => r.client === client)
                        .map((item, i) => (
                          <li key={i} className="flex justify-between items-center py-1">
                            <span className="text-sm text-zinc-300">{item.filterType}</span>
                            <span className={`px-3 py-1 text-sm rounded-full
                              ${item.status === 'hit'
                                ? 'bg-red-900/50 text-red-300 border border-red-700'
                                : 'bg-green-900/50 text-green-300 border border-green-700'}`}>
                              {item.status === 'hit' ? 'Hit Detected' : 'No Hit'}
                            </span>
                          </li>
                        ))}
                    </ul>
                  </li>
                ))}
              </ul>
              <p className="mb-4 text-sm text-yellow-400 italic mt-4">
                Note: CSV exports are limited - please check your SIEM for full results.
              </p>
            </div>
          )}

          <div className="flex flex-wrap justify-center gap-3">
            <button
              onClick={() => exportFromServer('wide')}
              disabled={exporting}
              className="px-6 py-3 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 transition focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-zinc-950"
            >
              {exporting ? 'Exporting...' : 'Export CSV'}
            </button>
            <button
              onClick={exportJsonFromServer}
              disabled={exporting || jsonExporting}
              className="px-6 py-3 bg-zinc-700 text-white rounded-md hover:bg-zinc-600 disabled:opacity-50 transition focus:outline-none focus:ring-2 focus:ring-zinc-500 focus:ring-offset-2 focus:ring-offset-zinc-950"
            >
              {jsonExporting ? 'Exporting...' : 'Export JSON'}
            </button>
          </div>
        </div>
      )}

      {/* Hunt Modal */}
      <HuntModal
        isOpen={huntOpen}
        onClose={() => setHuntOpen(false)}
        clientOptions={clientOptions}
        onHuntResult={(data) => {
          setResult(data);
        }}
      />
      </div>

      <Footer />
    </div>
  );
}
