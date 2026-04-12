import React, { useState } from 'react';
import axios from 'axios';
import ErrorAlert, { parseApiError } from './ErrorAlert';

const IOC_TYPES = ['IP', 'Hash', 'Domain', 'URL', 'Email', 'FileName'];
const DEPTH_OPTIONS = [1000, 2000, 5000, 10000];

export default function ReconSection({ apiKeys, token, API_URL, SIEM_CONFIGS }) {
  // Step state
  const [selectedClient, setSelectedClient] = useState(null);
  const [logSources, setLogSources] = useState([]);
  const [selectedLogSource, setSelectedLogSource] = useState(null);
  const [iocType, setIocType] = useState('IP');
  const [depth, setDepth] = useState(1000);

  // Results state
  const [results, setResults] = useState(null);
  const [selectedFields, setSelectedFields] = useState(new Set());

  // Approved mappings
  const [mappings, setMappings] = useState([]);

  // UI state
  const [loading, setLoading] = useState(false);
  const [loadingSources, setLoadingSources] = useState(false);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });
  const [success, setSuccess] = useState('');

  // Get unique clients from apiKeys
  const clients = apiKeys.filter(k => k.isActive !== false);

  const onClientChange = async (e) => {
    const clientId = e.target.value;
    if (!clientId) {
      setSelectedClient(null);
      setLogSources([]);
      setSelectedLogSource(null);
      setResults(null);
      setMappings([]);
      return;
    }

    const client = clients.find(c => String(c.id) === clientId);
    setSelectedClient(client);
    setSelectedLogSource(null);
    setResults(null);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setSuccess('');

    // Fetch log sources
    setLoadingSources(true);
    try {
      const res = await axios.get(`${API_URL}/recon/log-sources/${clientId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setLogSources(res.data || []);
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({
        error: parsed.error || 'Failed to fetch log sources.',
        suggestion: parsed.suggestion || 'Check that the SIEM connection is active and the credentials are valid.',
        category: parsed.category || 'connection'
      });
      setLogSources([]);
    } finally {
      setLoadingSources(false);
    }

    // Fetch existing mappings
    try {
      const res = await axios.get(`${API_URL}/recon/mappings/${clientId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMappings(res.data || []);
    } catch (err) {
      // Non-fatal
    }
  };

  const onLogSourceChange = (e) => {
    const sourceId = e.target.value;
    const source = logSources.find(s => String(s.id) === sourceId);
    setSelectedLogSource(source);
    setResults(null);
  };

  const dig = async () => {
    if (!selectedClient || !selectedLogSource) return;

    setLoading(true);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setSuccess('');
    setResults(null);
    setSelectedFields(new Set());

    try {
      const res = await axios.post(`${API_URL}/recon/dig`, {
        clientId: selectedClient.id,
        logSource: selectedLogSource,
        iocType,
        depth
      }, {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 180000
      });

      setResults(res.data);
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({
        error: parsed.error || 'Dig failed.',
        suggestion: parsed.suggestion || 'Try a smaller depth or check the SIEM connection.',
        category: parsed.category || 'server'
      });
    } finally {
      setLoading(false);
    }
  };

  const toggleField = (fieldName) => {
    setSelectedFields(prev => {
      const next = new Set(prev);
      if (next.has(fieldName)) {
        next.delete(fieldName);
      } else {
        next.add(fieldName);
      }
      return next;
    });
  };

  const selectAll = () => {
    if (!results?.fields) return;
    setSelectedFields(new Set(results.fields.map(f => f.fieldName)));
  };

  const deselectAll = () => {
    setSelectedFields(new Set());
  };

  const approve = async (andDigDeeper = false) => {
    if (selectedFields.size === 0) {
      setErrorInfo({ error: 'Select at least one field to approve.', suggestion: 'Click on fields in the table above to select them before approving.', category: 'validation' });
      return;
    }

    setLoading(true);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    setSuccess('');

    try {
      await axios.post(`${API_URL}/recon/approve`, {
        clientId: selectedClient.id,
        filterType: iocType,
        fields: Array.from(selectedFields),
        logSource: selectedLogSource?.name || selectedLogSource?.id
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });

      setSuccess(`Approved ${selectedFields.size} field(s) for ${iocType}.`);

      // Refresh mappings
      const res = await axios.get(`${API_URL}/recon/mappings/${selectedClient.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMappings(res.data || []);

      if (andDigDeeper) {
        const nextDepth = Math.min(depth * 2, 10000);
        setDepth(nextDepth);
        setLoading(false);
        // Trigger new dig with increased depth
        setTimeout(() => dig(), 100);
        return;
      }
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({
        error: parsed.error || 'Approve failed.',
        suggestion: parsed.suggestion || 'Try again or check the backend logs.',
        category: parsed.category || 'server'
      });
    } finally {
      setLoading(false);
    }
  };

  const deleteMapping = async (mappingId) => {
    if (!window.confirm('Delete this field mapping?')) return;
    try {
      await axios.delete(`${API_URL}/recon/mappings/${mappingId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMappings(prev => prev.filter(m => m.id !== mappingId));
      setSuccess('Mapping deleted.');
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({
        error: parsed.error || 'Delete failed.',
        suggestion: parsed.suggestion || 'Try again or check the backend logs.',
        category: parsed.category || 'server'
      });
    }
  };

  const digDeeper = () => {
    const nextDepth = Math.min(depth * 2, 10000);
    setDepth(nextDepth);
    setTimeout(() => dig(), 100);
  };

  return (
    <div>
      <p className="text-sm text-zinc-400 mb-6">
        Discover which SIEM fields store specific IOC types by analyzing raw logs.
      </p>

      <ErrorAlert
        error={errorInfo.error}
        suggestion={errorInfo.suggestion}
        category={errorInfo.category}
        onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
        className="mb-4"
      />
      {success && <p className="text-green-400 mb-4 p-3 bg-green-900/30 border border-green-800 rounded" role="status">{success}</p>}

      {/* Step 1: Select Client */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div>
          <label className="block text-sm font-medium text-zinc-300 mb-1">SIEM Client</label>
          <select
            value={selectedClient?.id || ''}
            onChange={onClientChange}
            className="bg-zinc-800 border border-zinc-700 p-3 rounded w-full text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">-- Choose SIEM to analyze --</option>
            {clients.map(c => (
              <option key={c.id} value={c.id}>
                {c.client} ({SIEM_CONFIGS[c.siemType]?.label || c.siemType})
              </option>
            ))}
          </select>
        </div>

        {/* Step 2: Log Source */}
        <div>
          <label className="block text-sm font-medium text-zinc-300 mb-1">Log Source</label>
          <select
            value={selectedLogSource?.id || ''}
            onChange={onLogSourceChange}
            disabled={!selectedClient || loadingSources}
            className="bg-zinc-800 border border-zinc-700 p-3 rounded w-full text-zinc-100 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="">{loadingSources ? 'Loading sources...' : '-- Choose a log source --'}</option>
            {logSources.map(s => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        </div>

        {/* Step 3: IOC Type */}
        <div>
          <label className="block text-sm font-medium text-zinc-300 mb-1">IOC Type</label>
          <select
            value={iocType}
            onChange={(e) => setIocType(e.target.value)}
            className="bg-zinc-800 border border-zinc-700 p-3 rounded w-full text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {IOC_TYPES.map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>

        {/* Step 4: Depth */}
        <div>
          <label className="block text-sm font-medium text-zinc-300 mb-1">Depth</label>
          <select
            value={depth}
            onChange={(e) => setDepth(Number(e.target.value))}
            className="bg-zinc-800 border border-zinc-700 p-3 rounded w-full text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            aria-label="Search depth - number of logs to analyze"
          >
            {DEPTH_OPTIONS.map(d => (
              <option key={d} value={d}>{(d / 1000).toFixed(0)}K logs</option>
            ))}
          </select>
        </div>
      </div>

      {/* Dig Button */}
      <div className="mb-6">
        <button
          onClick={dig}
          disabled={loading || !selectedClient || !selectedLogSource}
          className="bg-indigo-600 text-white px-8 py-2 rounded hover:bg-indigo-700 transition disabled:opacity-50 font-medium"
          aria-label="Dig - discover IOC fields in SIEM logs"
        >
          {loading ? 'Digging...' : 'Dig'}
        </button>
      </div>

      {/* Results Table */}
      {results && (
        <div className="mb-8">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-lg font-semibold text-zinc-100">
              Discovered Fields ({results.fields?.length || 0} matches from {results.totalLogs} logs)
            </h4>
            <div className="flex gap-2">
              <button onClick={selectAll} className="text-sm text-indigo-400 hover:underline" aria-label="Select all discovered fields">Select All</button>
              <button onClick={deselectAll} className="text-sm text-zinc-400 hover:underline" aria-label="Deselect all discovered fields">Deselect All</button>
            </div>
          </div>

          {results.fields?.length === 0 ? (
            <p className="text-zinc-400 p-4 bg-zinc-800 border border-zinc-700 rounded">
              No fields containing {iocType} values were found in {results.totalLogs} logs. Try a deeper search or different log source.
            </p>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="min-w-full border border-zinc-700">
                  <thead className="bg-zinc-800">
                    <tr>
                      <th scope="col" className="border border-zinc-700 px-3 py-2 w-10"><span className="sr-only">Select</span></th>
                      <th scope="col" className="border border-zinc-700 px-4 py-2 text-left text-zinc-300">Field Name</th>
                      <th scope="col" className="border border-zinc-700 px-4 py-2 text-right text-zinc-300">Matches</th>
                      <th scope="col" className="border border-zinc-700 px-4 py-2 text-right text-zinc-300">Total Seen</th>
                      <th scope="col" className="border border-zinc-700 px-4 py-2 text-right text-zinc-300">Match %</th>
                      <th scope="col" className="border border-zinc-700 px-4 py-2 text-left text-zinc-300">Sample Values</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.fields.map((field) => (
                      <tr
                        key={field.fieldName}
                        className={`hover:bg-zinc-800/50 cursor-pointer ${selectedFields.has(field.fieldName) ? 'bg-indigo-900/30' : ''}`}
                        onClick={() => toggleField(field.fieldName)}
                      >
                        <td className="border border-zinc-700 px-3 py-2 text-center">
                          <input
                            type="checkbox"
                            checked={selectedFields.has(field.fieldName)}
                            onChange={() => toggleField(field.fieldName)}
                            onClick={(e) => e.stopPropagation()}
                            className="h-4 w-4 rounded border-zinc-600 bg-zinc-700 text-indigo-600"
                          />
                        </td>
                        <td className="border border-zinc-700 px-4 py-2 font-mono text-sm text-zinc-200">{field.fieldName}</td>
                        <td className="border border-zinc-700 px-4 py-2 text-right font-medium text-zinc-100">{field.matchCount}</td>
                        <td className="border border-zinc-700 px-4 py-2 text-right text-zinc-400">{field.totalSeen}</td>
                        <td className="border border-zinc-700 px-4 py-2 text-right">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            field.matchPercent >= 80 ? 'bg-green-900/50 text-green-300 border border-green-700' :
                            field.matchPercent >= 40 ? 'bg-yellow-900/50 text-yellow-300 border border-yellow-700' :
                            'bg-zinc-700 text-zinc-300'
                          }`}>
                            {field.matchPercent}%
                          </span>
                        </td>
                        <td className="border border-zinc-700 px-4 py-2 text-sm text-zinc-400 max-w-xs truncate">
                          {field.sampleValues?.join(', ')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3 mt-4">
                <button
                  onClick={() => approve(false)}
                  disabled={loading || selectedFields.size === 0}
                  className="bg-green-600 text-white px-6 py-2 rounded hover:bg-green-700 transition disabled:opacity-50"
                >
                  Approve Selected ({selectedFields.size})
                </button>
                <button
                  onClick={digDeeper}
                  disabled={loading || depth >= 10000}
                  className="bg-yellow-600 text-white px-6 py-2 rounded hover:bg-yellow-700 transition disabled:opacity-50"
                >
                  Dig Deeper
                </button>
                <button
                  onClick={() => approve(true)}
                  disabled={loading || selectedFields.size === 0 || depth >= 10000}
                  className="bg-indigo-600 text-white px-6 py-2 rounded hover:bg-indigo-700 transition disabled:opacity-50"
                >
                  Approve & Dig Deeper
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {/* Approved Mappings */}
      {mappings.length > 0 && (
        <div className="mt-6">
          <h4 className="text-lg font-semibold mb-3 text-zinc-100">Approved Field Mappings</h4>
          <div className="overflow-x-auto">
            <table className="min-w-full border border-zinc-700">
              <thead className="bg-zinc-800">
                <tr>
                  <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">IOC Type</th>
                  <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Fields</th>
                  <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Log Source</th>
                  <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Status</th>
                  <th scope="col" className="border border-zinc-700 px-4 py-2 text-zinc-300">Actions</th>
                </tr>
              </thead>
              <tbody>
                {mappings.map((m) => (
                  <tr key={m.id} className="hover:bg-zinc-800/50">
                    <td className="border border-zinc-700 px-4 py-2">
                      <span className="px-2 py-1 rounded text-sm bg-indigo-900/50 text-indigo-300 border border-indigo-700">{m.filterType}</span>
                    </td>
                    <td className="border border-zinc-700 px-4 py-2 font-mono text-sm text-zinc-300">
                      {(m.fields || []).join(', ')}
                    </td>
                    <td className="border border-zinc-700 px-4 py-2 text-sm text-zinc-400">{m.logSource || '-'}</td>
                    <td className="border border-zinc-700 px-4 py-2">
                      <span className={`px-2 py-1 rounded text-xs ${m.isApproved ? 'bg-green-900/50 text-green-300 border border-green-700' : 'bg-zinc-700 text-zinc-400'}`}>
                        {m.isApproved ? 'Active' : 'Draft'}
                      </span>
                    </td>
                    <td className="border border-zinc-700 px-4 py-2">
                      <button
                        onClick={() => deleteMapping(m.id)}
                        className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 transition text-sm"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
