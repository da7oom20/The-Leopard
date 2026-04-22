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
        className="field-boxed flex justify-between items-center hover:border-signal-amber transition-colors"
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span className="truncate text-ink-100">{summary}</span>
        <svg className={`w-3.5 h-3.5 ml-2 text-ink-400 transition-transform ${open ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.71a.75.75 0 111.06 1.06l-4.24 4.25a.75.75 0 01-1.06 0L5.21 8.29a.75.75 0 01.02-1.08z" />
        </svg>
      </button>

      {open && (
        <div
          ref={menuRef}
          className="absolute z-20 mt-1 w-full max-h-64 overflow-auto border border-ink-700 bg-ink-900 shadow-editorial-lg"
          role="listbox"
          tabIndex={-1}
        >
          <label className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-ink-800 border-b border-hairline">
            <input
              type="checkbox"
              checked={allClients}
              onChange={(e) => toggleAll(e.target.checked)}
              className="h-4 w-4 border-ink-600 bg-ink-850 text-signal-amber focus:ring-signal-amber rounded-none"
            />
            <span className="font-mono uppercase text-micro tracking-eyebrow text-ink-100">All Clients</span>
          </label>

          <div className={`${allClients ? 'opacity-40 pointer-events-none' : ''}`}>
            {options.map(c => (
              <label
                key={c}
                className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-ink-800"
              >
                <input
                  type="checkbox"
                  checked={selectedClients.includes(c)}
                  onChange={(e) => toggleOne(c, e.target.checked)}
                  className="h-4 w-4 border-ink-600 bg-ink-850 text-signal-amber focus:ring-signal-amber rounded-none"
                />
                <span className="text-ink-200 text-sm">{c}</span>
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
    <div className="flex flex-col min-h-screen bg-ink-950 text-ink-50 grain">
      {/* Editorial header band */}
      <header className="border-b border-hairline-strong vignette-deep">
        <div className="max-w-7xl mx-auto px-6 pt-8 pb-6 flex flex-col sm:flex-row justify-between items-start sm:items-end gap-6">
          <div>
            <span className="eyebrow-amber">The Leopard · Field Console</span>
            <h1 className="mt-2 font-serif italic text-5xl leading-none tracking-tight wordmark-gradient"
                style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
              Hunt
            </h1>
            <p className="mt-2 font-mono text-micro text-ink-500 tracking-wider-2">
              INDICATOR SEARCH · MULTI-SIEM
            </p>
          </div>
          <nav className="flex items-center gap-2 flex-wrap" aria-label="Main navigation">
            <button onClick={() => setHuntOpen(true)} className="btn-amber py-2" aria-label="Open threat hunt modal">
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" aria-hidden="true">
                <circle cx="11" cy="11" r="7" />
                <path d="M20 20l-3.5-3.5" strokeLinecap="round" />
              </svg>
              Hunt Mode
            </button>
            <button onClick={() => navigate('/repo')} className="btn-ghost py-2">
              Repo
            </button>
            <button onClick={() => navigate('/admin')} className="btn-ghost py-2">
              Admin
            </button>
          </nav>
        </div>
      </header>

      <div className="flex-1 max-w-7xl mx-auto p-6 w-full">

      {/* Form */}
      <form onSubmit={onSubmit} className="space-y-8 animate-fade-up" aria-label="IOC upload form">
        {/* Period & Client */}
        <section>
          <span className="eyebrow">Section · Targeting</span>
          <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label htmlFor="search-period" className="font-mono text-xs uppercase tracking-eyebrow text-ink-400 block mb-2">Search Period</label>
              <select
                id="search-period"
                value={searchPeriod}
                onChange={(e) => setSearchPeriod(Number(e.target.value))}
                className="field-boxed"
              >
                {searchOptions.map(({ label, value }) => (
                  <option key={value} value={value}>{label}</option>
                ))}
              </select>
              {searchPeriod >= 129600 && (
                <div className="mt-3 p-3 border-l-2 border-signal-amber bg-signal-amber/8 border-y border-r border-y-hairline border-r-hairline">
                  <p className="font-mono text-micro tracking-eyebrow text-signal-amber flex items-center gap-2">
                    <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3m0 4h.01M5.07 19h13.86a2 2 0 001.74-3L13.74 4a2 2 0 00-3.48 0L3.33 16a2 2 0 001.74 3z" />
                    </svg>
                    LARGE SEARCH PERIOD
                  </p>
                  <p className="text-ink-300 text-xs mt-1.5 leading-relaxed">
                    Searching 3+ months may run long or time out. Consider a shorter window or fewer clients.
                  </p>
                </div>
              )}
            </div>

            <div>
              <label className="font-mono text-xs uppercase tracking-eyebrow text-ink-400 block mb-2">Target Clients</label>
              <ClientMultiSelectDropdown
                allClients={allClients}
                setAllClients={setAllClients}
                selectedClients={selectedClients}
                setSelectedClients={setSelectedClients}
                options={clientOptions}
              />
              {!allClients && selectedClients.length === 0 && (
                <div className="text-xs text-signal-amber mt-2 font-mono uppercase tracking-eyebrow">
                  Select at least one client or toggle All Clients
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Upload Areas */}
        <section>
          <span className="eyebrow">Section · Indicators</span>
          <div className="mt-3 flex flex-col md:flex-row gap-4">
            {/* File Upload */}
            <div className="flex-1 card-editorial p-6">
              <h2 className="font-serif text-xl text-ink-50 mb-4 leading-none"
                  style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                Upload file
              </h2>
              <label
                htmlFor="fileUpload"
                className={`block cursor-pointer border border-dashed p-8 text-center transition-colors ${
                  dragActive
                    ? 'border-signal-amber bg-signal-amber/8 text-signal-amber'
                    : 'border-ink-700 text-ink-400 hover:border-signal-amber hover:text-signal-amber'
                }`}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
              >
                {file ? (
                  <div>
                    <svg className="mx-auto h-7 w-7 text-signal-amber mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.25}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                    </svg>
                    <p className="text-ink-100 font-mono text-sm break-all">{file.name}</p>
                  </div>
                ) : (
                  <>
                    <svg className="mx-auto h-8 w-8 text-ink-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true" strokeWidth={1.25}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                    </svg>
                    <p className="text-sm">Drag &amp; drop a file, or click to browse</p>
                    <p className="font-mono text-micro tracking-eyebrow text-ink-600 mt-2">PDF · XLSX · CSV · TXT</p>
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
                className="mt-4 field-boxed text-sm"
              />
              {file && (
                <button
                  type="button"
                  onClick={() => setFile(null)}
                  className="mt-3 text-xs font-mono uppercase tracking-eyebrow text-signal-rust hover:text-signal-amber transition-colors"
                >
                  Remove file
                </button>
              )}
            </div>

            {/* Text Paste */}
            <div className="flex-1 card-editorial p-6 flex flex-col">
              <h2 className="font-serif text-xl text-ink-50 mb-4 leading-none"
                  style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                Paste indicators
              </h2>
              <textarea
                rows={10}
                placeholder="One per line or comma-separated.&#10;&#10;192.168.1.100&#10;malware.evil-domain.com&#10;e99a18c428cb38d5f260853678922e03&#10;hxxps://phishing[.]site/login"
                className="flex-grow field-boxed font-mono text-sm resize-none"
                value={text}
                onChange={onTextChange}
                aria-label="Paste IOC text"
              />
              {text && (
                <button
                  type="button"
                  onClick={() => setText('')}
                  className="mt-3 self-end text-xs font-mono uppercase tracking-eyebrow text-signal-rust hover:text-signal-amber transition-colors"
                >
                  Clear text
                </button>
              )}
            </div>
          </div>
        </section>

        {/* Submit Button */}
        <div className="flex justify-center pt-2">
          <button
            type="submit"
            disabled={loading || (!allClients && selectedClients.length === 0)}
            className="btn-amber px-10 py-3.5"
          >
            {loading && (
              <svg className="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                <circle className="opacity-30" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
                <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
            )}
            {loading ? 'Searching across SIEMs' : 'Begin Hunt'}
            {!loading && (
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" d="M13.75 6.75L19.25 12l-5.5 5.25M19 12H4.75" />
              </svg>
            )}
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
