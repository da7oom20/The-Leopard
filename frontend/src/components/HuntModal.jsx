import React, { useState, useEffect, useRef } from 'react';
import ErrorAlert from './ErrorAlert';
import { apiFetch } from '../utils/apiClient';

/**
 * Reusable client multi-select dropdown
 */
function ClientDropdown({ allClients, setAllClients, selectedClients, setSelectedClients, options }) {
  const [open, setOpen] = useState(false);
  const btnRef = useRef(null);
  const menuRef = useRef(null);

  useEffect(() => {
    function onDocClick(e) {
      if (!btnRef.current || !menuRef.current) return;
      if (!btnRef.current.contains(e.target) && !menuRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onDocClick);
    return () => document.removeEventListener('mousedown', onDocClick);
  }, []);

  const summary = allClients
    ? 'All Clients'
    : selectedClients.length
      ? `${selectedClients.length} selected`
      : 'Select clients...';

  return (
    <div className="relative">
      <button
        type="button"
        ref={btnRef}
        onClick={() => setOpen(v => !v)}
        className="w-full p-2 border rounded-md bg-zinc-800 text-zinc-100 border-zinc-700 flex justify-between items-center text-sm hover:border-zinc-600 transition"
      >
        <span className="truncate">{summary}</span>
        <svg className={`w-4 h-4 ml-2 transition-transform ${open ? 'rotate-180' : ''}`} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
          <path d="M5.23 7.21a.75.75 0 011.06.02L10 10.94l3.71-3.71a.75.75 0 111.06 1.06l-4.24 4.25a.75.75 0 01-1.06 0L5.21 8.29a.75.75 0 01.02-1.08z" />
        </svg>
      </button>

      {open && (
        <div ref={menuRef} className="absolute z-30 mt-1 w-full max-h-48 overflow-auto rounded-md border border-zinc-700 bg-zinc-800 shadow-lg">
          <label className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-zinc-700">
            <input type="checkbox" checked={allClients} onChange={(e) => { setAllClients(e.target.checked); if (e.target.checked) setSelectedClients([]); }} className="h-4 w-4 rounded border-zinc-600 bg-zinc-700 text-indigo-600" />
            <span className="font-medium text-sm text-zinc-100">All Clients</span>
          </label>
          <div className={allClients ? 'opacity-50 pointer-events-none' : ''}>
            {options.map(c => (
              <label key={c} className="flex items-center gap-2 px-3 py-2 cursor-pointer hover:bg-zinc-700">
                <input
                  type="checkbox"
                  checked={selectedClients.includes(c)}
                  onChange={(e) => {
                    setAllClients(false);
                    setSelectedClients(prev => e.target.checked ? [...new Set([...prev, c])] : prev.filter(x => x !== c));
                  }}
                  className="h-4 w-4 rounded border-zinc-600 bg-zinc-700 text-indigo-600"
                />
                <span className="text-sm text-zinc-200">{c}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

const SEARCH_OPTIONS = [
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

export default function HuntModal({ isOpen, onClose, clientOptions, onHuntResult }) {
  const [tiSources, setTiSources] = useState([]);
  const [selectedSource, setSelectedSource] = useState('');
  const [iocType, setIocType] = useState('');
  const [searchPeriod, setSearchPeriod] = useState(1440);
  const [allClients, setAllClients] = useState(true);
  const [selectedClients, setSelectedClients] = useState([]);

  // Advanced options
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [maxIOCs, setMaxIOCs] = useState(100);
  const [confidenceMin, setConfidenceMin] = useState(80);
  const [daysBack, setDaysBack] = useState(1);

  const [loading, setLoading] = useState(false);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });
  const [result, setResult] = useState(null);

  // Available IOC types based on selected source
  const [availableTypes, setAvailableTypes] = useState([]);

  // Download IOC list as TXT file
  const downloadIOCs = () => {
    if (!result?.iocList?.length) return;
    const text = result.iocList.join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hunt_iocs_${result.huntId || 'export'}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  useEffect(() => {
    if (!isOpen) return;
    const API_URL = process.env.REACT_APP_API_URL || '/api';
    const controller = new AbortController();
    apiFetch(`${API_URL}/ti-sources`, { signal: controller.signal })
      .then(r => r.json())
      .then(data => setTiSources(data))
      .catch((err) => {
        if (err.name !== 'AbortError') setTiSources([]);
      });
    return () => controller.abort();
  }, [isOpen]);

  useEffect(() => {
    if (selectedSource) {
      const source = tiSources.find(s => String(s.id) === String(selectedSource));
      if (source) {
        setAvailableTypes(source.supportedTypes || []);
        setIocType('');
      }
    } else {
      setAvailableTypes([]);
      setIocType('');
    }
  }, [selectedSource, tiSources]);

  const isReady = selectedSource && iocType && (allClients || selectedClients.length > 0);

  const handleHunt = async () => {
    if (!isReady) return;

    setLoading(true);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setResult(null);

    try {
      const API_URL = process.env.REACT_APP_API_URL || '/api';
      const clientPayload = allClients ? 'ALL' : selectedClients.join(',');

      const res = await apiFetch(`${API_URL}/hunt`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tiSourceId: selectedSource,
          iocType,
          client: clientPayload,
          searchMinutesAgo: searchPeriod,
          feedOptions: {
            limit: maxIOCs,
            confidenceMin,
            daysBack
          }
        })
      });

      const data = await res.json();
      if (!res.ok) {
        setErrorInfo({
          error: data.error || 'Hunt failed.',
          suggestion: data.suggestion || '',
          category: data.category || ''
        });
        return;
      }

      setResult(data);
      if (onHuntResult) onHuntResult(data);
    } catch (err) {
      setErrorInfo({ error: err.message || 'Hunt failed.', suggestion: 'Check your network connection and try again.', category: 'connection' });
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setResult(null);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setSelectedSource('');
    setIocType('');
    onClose();
  };

  // Lock body scroll when modal is open
  useEffect(() => {
    if (!isOpen) return;
    const original = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = original; };
  }, [isOpen]);

  // Close on Escape key and trap focus
  const modalRef = useRef(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        setResult(null);
        setErrorInfo({ error: '', suggestion: '', category: '' });
        setSelectedSource('');
        setIocType('');
        onCloseRef.current();
        return;
      }
      // Focus trap: keep Tab within the modal
      if (e.key === 'Tab' && modalRef.current) {
        const focusable = modalRef.current.querySelectorAll(
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
    // Auto-focus the modal on open
    if (modalRef.current) {
      const firstFocusable = modalRef.current.querySelector('button, [href], input, select, textarea');
      if (firstFocusable) firstFocusable.focus();
    }
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={handleClose} role="dialog" aria-modal="true" aria-labelledby="hunt-modal-title">
      <div
        ref={modalRef}
        className="bg-zinc-900 rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto border border-zinc-700"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex justify-between items-center p-6 border-b border-zinc-800">
          <h2 id="hunt-modal-title" className="text-xl font-bold text-zinc-100">Hunt - Threat Intelligence Search</h2>
          <button onClick={handleClose} className="text-zinc-400 hover:text-zinc-200 text-2xl transition rounded-md p-1 hover:bg-zinc-800 focus:outline-none focus:ring-2 focus:ring-indigo-500" aria-label="Close hunt modal">&times;</button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {/* TI Platform */}
          <div>
            <label className="block mb-1 font-medium text-sm text-zinc-300">TI Platform</label>
            <select
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              className="w-full p-2 border rounded-md bg-zinc-800 text-zinc-100 border-zinc-700 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="">-- Choose a TI source to hunt from --</option>
              {tiSources.map(s => (
                <option key={s.id} value={s.id}>{s.name} ({s.platformType})</option>
              ))}
            </select>
            {tiSources.length === 0 && (
              <p className="text-xs text-yellow-400 mt-1">
                No TI sources configured. Add them in the Admin panel.
              </p>
            )}
          </div>

          {/* IOC Type */}
          <div>
            <label className="block mb-1 font-medium text-sm text-zinc-300">IOC Type</label>
            <select
              value={iocType}
              onChange={(e) => setIocType(e.target.value)}
              disabled={!selectedSource}
              className="w-full p-2 border rounded-md bg-zinc-800 text-zinc-100 border-zinc-700 text-sm disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="">-- Select what type of IOC to hunt --</option>
              {availableTypes.map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Target Clients */}
          <div>
            <label className="block mb-1 font-medium text-sm text-zinc-300">Target Clients</label>
            <ClientDropdown
              allClients={allClients}
              setAllClients={setAllClients}
              selectedClients={selectedClients}
              setSelectedClients={setSelectedClients}
              options={clientOptions}
            />
          </div>

          {/* Period */}
          <div>
            <label className="block mb-1 font-medium text-sm text-zinc-300">Search Period</label>
            <select
              value={searchPeriod}
              onChange={(e) => setSearchPeriod(Number(e.target.value))}
              className="w-full p-2 border rounded-md bg-zinc-800 text-zinc-100 border-zinc-700 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              {SEARCH_OPTIONS.map(({ label, value }) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </div>

          {/* Advanced Options */}
          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced(v => !v)}
              className="text-sm text-indigo-400 hover:underline"
            >
              {showAdvanced ? 'Hide' : 'Show'} Advanced Options
            </button>
            {showAdvanced && (
              <div className="mt-3 p-3 bg-zinc-800 rounded space-y-3 border border-zinc-700">
                <div>
                  <label className="block mb-1 text-xs text-zinc-400">Max IOCs to Fetch</label>
                  <input type="number" value={maxIOCs} onChange={(e) => setMaxIOCs(Number(e.target.value))} min={1} max={1000}
                    className="w-full p-2 border rounded text-sm bg-zinc-700 text-zinc-100 border-zinc-600 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                </div>
                <div>
                  <label className="block mb-1 text-xs text-zinc-400">Min Confidence Score</label>
                  <input type="number" value={confidenceMin} onChange={(e) => setConfidenceMin(Number(e.target.value))} min={0} max={100}
                    className="w-full p-2 border rounded text-sm bg-zinc-700 text-zinc-100 border-zinc-600 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                </div>
                <div>
                  <label className="block mb-1 text-xs text-zinc-400">TI Feed Days Back</label>
                  <input type="number" value={daysBack} onChange={(e) => setDaysBack(Number(e.target.value))} min={1} max={30}
                    className="w-full p-2 border rounded text-sm bg-zinc-700 text-zinc-100 border-zinc-600 focus:outline-none focus:ring-2 focus:ring-indigo-500" />
                </div>
              </div>
            )}
          </div>

          {/* Status */}
          <div className="flex items-center gap-2 text-sm">
            <span className="font-medium text-zinc-300">Status:</span>
            {loading ? (
              <span className="text-yellow-400">Hunting...</span>
            ) : isReady ? (
              <span className="text-green-400">Ready</span>
            ) : (
              <span className="text-zinc-500">Select all required fields</span>
            )}
          </div>

          {/* Error */}
          <ErrorAlert
            error={errorInfo.error}
            suggestion={errorInfo.suggestion}
            category={errorInfo.category}
            onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
            onRetry={isReady && !loading ? handleHunt : undefined}
          />

          {/* Results */}
          {result && (
            <div className="p-4 bg-zinc-800 rounded space-y-3 border border-zinc-700">
              <div className="flex justify-between items-center">
                <h4 className="font-semibold text-zinc-100">Hunt Results</h4>
                {result.iocList && result.iocList.length > 0 && (
                  <button
                    onClick={downloadIOCs}
                    className="px-3 py-1 text-xs bg-indigo-600 text-white rounded hover:bg-indigo-700 transition"
                  >
                    Download IOCs ({result.iocList.length})
                  </button>
                )}
              </div>

              {result.message && (
                <div className="p-3 bg-yellow-900/50 text-yellow-200 border border-yellow-700 rounded text-sm">
                  {result.message}
                </div>
              )}

              <div className="grid grid-cols-2 gap-2 text-sm">
                <div className="text-zinc-400">IOCs Fetched:</div>
                <div className="font-medium text-zinc-100">{result.iocsFetched}</div>
                <div className="text-zinc-400">Clients Searched:</div>
                <div className="font-medium text-zinc-100">{result.summary?.clientsSearched || 0}</div>
                <div className="text-zinc-400">Hits:</div>
                <div className="font-medium text-red-400">{result.summary?.hits || 0}</div>
                <div className="text-zinc-400">No Hits:</div>
                <div className="font-medium text-green-400">{result.summary?.noHits || 0}</div>
                {(result.summary?.errors || 0) > 0 && (
                  <>
                    <div className="text-zinc-400">Errors:</div>
                    <div className="font-medium text-yellow-400">{result.summary.errors}</div>
                  </>
                )}
              </div>

              {result.siemResults && result.siemResults.length > 0 && (
                <div className="mt-2">
                  <h5 className="text-sm font-medium mb-1 text-zinc-300">SIEM Results:</h5>
                  <ul className="space-y-1">
                    {result.siemResults.map((r, i) => (
                      <li key={i} className="flex justify-between text-sm">
                        <span className="text-zinc-300">{r.client} - {r.filterType}</span>
                        <span className={`px-2 py-0.5 rounded-full text-xs ${
                          r.status === 'hit'
                            ? 'bg-red-900/50 text-red-300 border border-red-700'
                            : r.status === 'error'
                              ? 'bg-yellow-900/50 text-yellow-300 border border-yellow-700'
                              : 'bg-green-900/50 text-green-300 border border-green-700'
                        }`}>
                          {r.status === 'hit' ? 'Hit' : r.status === 'error' ? 'Error' : 'No Hit'}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 p-6 border-t border-zinc-800">
          <button
            onClick={handleClose}
            className="px-4 py-2 border border-zinc-700 rounded-md text-zinc-300 hover:bg-zinc-800 transition"
          >
            {result ? 'Close' : 'Cancel'}
          </button>
          {!result && (
            <button
              onClick={handleHunt}
              disabled={!isReady || loading}
              className="px-6 py-2 bg-amber-600 text-white font-semibold rounded-md hover:bg-amber-700 disabled:opacity-50 transition focus:outline-none focus:ring-2 focus:ring-amber-500 inline-flex items-center gap-2"
            >
              {loading && (
                <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
              )}
              {loading ? 'Hunting...' : 'Hunt'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
