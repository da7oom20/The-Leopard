import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import ErrorAlert, { parseApiError } from './ErrorAlert';

const IOC_TYPES = ['IP', 'Hash', 'Domain', 'URL', 'Email', 'FileName'];

export default function FieldMappingsTab({ token, API_URL, apiKeys, SIEM_CONFIGS }) {
  const [mappings, setMappings] = useState([]);
  const [siemDefaults, setSiemDefaults] = useState({});
  const [loading, setLoading] = useState(false);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });
  const [success, setSuccess] = useState('');
  const successTimerRef = useRef(null);
  const errorTimerRef = useRef(null);
  const [viewMode, setViewMode] = useState('defaults'); // 'defaults' or 'overrides'
  const [expandedSiem, setExpandedSiem] = useState(null);

  // Edit default field modal state
  const [editDefaultModal, setEditDefaultModal] = useState(null); // { siemType, iocType, fields, queryExample }
  const [editDefaultFields, setEditDefaultFields] = useState('');
  const [editDefaultQuery, setEditDefaultQuery] = useState('');
  const [editConfirmed, setEditConfirmed] = useState(false);

  const setAutoSuccess = (msg) => {
    setSuccess(msg);
    if (successTimerRef.current) clearTimeout(successTimerRef.current);
    successTimerRef.current = setTimeout(() => setSuccess(''), 3000);
  };

  const setAutoError = (info) => {
    setErrorInfo(info);
    if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
    errorTimerRef.current = setTimeout(() => setErrorInfo({ error: '', suggestion: '', category: '' }), 5000);
  };

  useEffect(() => {
    return () => {
      if (successTimerRef.current) clearTimeout(successTimerRef.current);
      if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
    };
  }, []);

  // Filter state for overrides
  const [filterClient, setFilterClient] = useState('');
  const [filterType, setFilterType] = useState('');

  // Edit modal state (overrides)
  const [editModal, setEditModal] = useState(null);
  const [editFields, setEditFields] = useState('');

  // Add modal state
  const [addModal, setAddModal] = useState(false);
  const [newMapping, setNewMapping] = useState({
    clientId: '',
    filterType: 'IP',
    fields: '',
    logSource: ''
  });

  // Fetch SIEM defaults
  useEffect(() => {
    axios.get(`${API_URL}/admin/siem-defaults`, {
      headers: { Authorization: `Bearer ${token}` }
    }).then(res => setSiemDefaults(res.data || {}))
      .catch(() => {});
  }, [token, API_URL]);

  const fetchAllMappings = async () => {
    setLoading(true);
    setErrorInfo({ error: '', suggestion: '', category: '' });
    try {
      const res = await axios.get(`${API_URL}/recon/mappings`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const allMappings = (res.data || []).map(m => {
        const client = apiKeys.find(k => k.id === m.clientId || k.client === m.client);
        return {
          ...m,
          clientName: client?.client || m.client || 'Unknown',
          siemType: client?.siemType || m.siemType || 'unknown'
        };
      });
      setMappings(allMappings);
    } catch (err) {
      try {
        const allMappings = [];
        const promises = apiKeys.map(client =>
          axios.get(`${API_URL}/recon/mappings/${client.id}`, {
            headers: { Authorization: `Bearer ${token}` }
          }).then(res => {
            const data = res.data || [];
            data.forEach(m => { m.clientName = client.client; m.siemType = client.siemType; });
            return data;
          }).catch(() => [])
        );
        const results = await Promise.all(promises);
        results.forEach(data => allMappings.push(...data));
        setMappings(allMappings);
      } catch (fallbackErr) {
        setAutoError({ error: 'Failed to fetch field mappings.', suggestion: 'Check your session and try refreshing the page.', category: 'server' });
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (apiKeys.length > 0) fetchAllMappings();
  }, [apiKeys, token]);

  const filteredMappings = mappings.filter(m => {
    if (filterClient && m.clientName !== filterClient) return false;
    if (filterType && m.filterType !== filterType) return false;
    return true;
  });

  const uniqueClients = [...new Set(apiKeys.map(k => k.client))];

  const deleteMapping = async (id) => {
    if (!window.confirm('Delete this field mapping override?')) return;
    try {
      await axios.delete(`${API_URL}/recon/mappings/${id}`, { headers: { Authorization: `Bearer ${token}` } });
      setMappings(prev => prev.filter(m => m.id !== id));
      setAutoSuccess('Mapping deleted.');
    } catch (err) {
      const parsed = parseApiError(err);
      setAutoError({ error: parsed.error || 'Failed to delete mapping.', suggestion: parsed.suggestion || '', category: parsed.category || 'server' });
    }
  };

  const openEditModal = (mapping) => {
    setEditModal(mapping);
    setEditFields((mapping.fields || []).join(', '));
  };

  const saveEdit = async () => {
    if (!editModal) return;
    setLoading(true);
    try {
      const fieldsArray = editFields.split(',').map(f => f.trim()).filter(Boolean);
      await axios.put(`${API_URL}/recon/mappings/${editModal.id}`, { fields: fieldsArray }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMappings(prev => prev.map(m => m.id === editModal.id ? { ...m, fields: fieldsArray } : m));
      setEditModal(null);
      setAutoSuccess('Mapping updated.');
    } catch (err) {
      const parsed = parseApiError(err);
      setAutoError({ error: parsed.error || 'Failed to update mapping.', suggestion: parsed.suggestion || '', category: parsed.category || 'server' });
    } finally {
      setLoading(false);
    }
  };

  const toggleStatus = async (mapping) => {
    setLoading(true);
    try {
      await axios.put(`${API_URL}/recon/mappings/${mapping.id}`, { isApproved: !mapping.isApproved }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMappings(prev => prev.map(m => m.id === mapping.id ? { ...m, isApproved: !m.isApproved } : m));
      setAutoSuccess(`Mapping ${mapping.isApproved ? 'disabled' : 'enabled'}.`);
    } catch (err) {
      const parsed = parseApiError(err);
      setAutoError({ error: parsed.error || 'Failed to toggle mapping status.', suggestion: parsed.suggestion || '', category: parsed.category || 'server' });
    } finally {
      setLoading(false);
    }
  };

  const addNewMapping = async () => {
    if (!newMapping.clientId || !newMapping.filterType || !newMapping.fields.trim()) {
      setAutoError({ error: 'Client, IOC type, and fields are required.', suggestion: '', category: 'validation' });
      return;
    }
    setLoading(true);
    try {
      const fieldsArray = newMapping.fields.split(',').map(f => f.trim()).filter(Boolean);
      await axios.post(`${API_URL}/recon/approve`, {
        clientId: parseInt(newMapping.clientId),
        filterType: newMapping.filterType,
        fields: fieldsArray,
        logSource: newMapping.logSource || 'Manual'
      }, { headers: { Authorization: `Bearer ${token}` } });
      setAddModal(false);
      setNewMapping({ clientId: '', filterType: 'IP', fields: '', logSource: '' });
      fetchAllMappings();
      setAutoSuccess('Mapping created.');
    } catch (err) {
      const parsed = parseApiError(err);
      setAutoError({ error: parsed.error || 'Failed to create mapping.', suggestion: parsed.suggestion || '', category: parsed.category || 'server' });
    } finally {
      setLoading(false);
    }
  };

  // Open edit modal for a default SIEM field row
  const openEditDefaultModal = (siemType, iocType, fields, queryExample) => {
    setEditDefaultModal({ siemType, iocType });
    setEditDefaultFields((fields || []).join(', '));
    setEditDefaultQuery(queryExample || '');
    setEditConfirmed(false);
  };

  const saveDefaultEdit = () => {
    if (!editDefaultModal || !editConfirmed) return;
    // Apply locally only (these are display defaults - actual changes require adapter code modification)
    setSiemDefaults(prev => {
      const updated = { ...prev };
      const siemConfig = { ...updated[editDefaultModal.siemType] };
      siemConfig.fieldMappings = { ...siemConfig.fieldMappings };
      siemConfig.fieldMappings[editDefaultModal.iocType] = editDefaultFields.split(',').map(f => f.trim()).filter(Boolean);
      if (siemConfig.queryExamples) {
        siemConfig.queryExamples = { ...siemConfig.queryExamples };
        siemConfig.queryExamples[editDefaultModal.iocType] = editDefaultQuery;
      }
      updated[editDefaultModal.siemType] = siemConfig;
      return updated;
    });
    setEditDefaultModal(null);
    setAutoSuccess('Default updated locally. Note: This is a display-only change for this session.');
  };

  // Modal escape/focus handling
  const activeModalRef = useRef(null);
  useEffect(() => {
    if (!editModal && !addModal && !editDefaultModal) return;
    const original = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        if (editModal) setEditModal(null);
        if (addModal) setAddModal(false);
        if (editDefaultModal) setEditDefaultModal(null);
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => { document.body.style.overflow = original; document.removeEventListener('keydown', onKeyDown); };
  }, [editModal, addModal, editDefaultModal]);

  // ========== RENDER ==========

  const siemTypeColors = {
    splunk: 'bg-green-900/40 text-green-300 border-green-700',
    logrhythm: 'bg-blue-900/40 text-blue-300 border-blue-700',
    qradar: 'bg-purple-900/40 text-purple-300 border-purple-700',
    elastic: 'bg-yellow-900/40 text-yellow-300 border-yellow-700',
    wazuh: 'bg-cyan-900/40 text-cyan-300 border-cyan-700',
    manageengine: 'bg-orange-900/40 text-orange-300 border-orange-700',
  };

  const iocTypeColors = {
    IP: 'bg-blue-900/50 text-blue-300 border-blue-700',
    Hash: 'bg-purple-900/50 text-purple-300 border-purple-700',
    Domain: 'bg-green-900/50 text-green-300 border-green-700',
    URL: 'bg-yellow-900/50 text-yellow-300 border-yellow-700',
    Email: 'bg-pink-900/50 text-pink-300 border-pink-700',
    FileName: 'bg-orange-900/50 text-orange-300 border-orange-700',
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-4">
        <p className="text-sm text-zinc-400">
          View default SIEM search fields and query patterns, or manage custom field mapping overrides.
        </p>
      </div>

      {/* View mode toggle */}
      <div className="flex gap-2 mb-6">
        <button
          onClick={() => setViewMode('defaults')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition ${
            viewMode === 'defaults'
              ? 'bg-indigo-600 text-white'
              : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
          }`}
        >
          SIEM Defaults
        </button>
        <button
          onClick={() => setViewMode('overrides')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition ${
            viewMode === 'overrides'
              ? 'bg-indigo-600 text-white'
              : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
          }`}
        >
          Custom Overrides {mappings.length > 0 && `(${mappings.length})`}
        </button>
      </div>

      <ErrorAlert error={errorInfo.error} suggestion={errorInfo.suggestion} category={errorInfo.category}
        onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })} className="mb-4" />
      {success && <p className="text-green-400 mb-4 p-3 bg-green-900/30 border border-green-800 rounded" role="status">{success}</p>}

      {/* ============ SIEM DEFAULTS VIEW ============ */}
      {viewMode === 'defaults' && (
        <div className="space-y-4">
          <p className="text-xs text-zinc-500 mb-2">
            Built-in field mappings and query patterns used by each SIEM adapter. Custom overrides (from Field Discovery or manual) take priority over these defaults.
          </p>

          {Object.entries(siemDefaults).length === 0 ? (
            <p className="text-zinc-400 text-center py-8">Loading SIEM defaults...</p>
          ) : (
            Object.entries(siemDefaults).map(([siemType, config]) => (
              <div key={siemType} className={`border rounded-lg overflow-hidden ${siemTypeColors[siemType] || 'border-zinc-700'}`}>
                {/* Header - clickable to expand */}
                <button
                  onClick={() => setExpandedSiem(expandedSiem === siemType ? null : siemType)}
                  className="w-full flex items-center justify-between px-5 py-3 bg-zinc-800/80 hover:bg-zinc-800 transition text-left"
                >
                  <div className="flex items-center gap-3">
                    <span className={`px-2.5 py-1 rounded text-xs font-semibold border ${siemTypeColors[siemType] || 'bg-zinc-700 text-zinc-300 border-zinc-600'}`}>
                      {config.label}
                    </span>
                    <span className="text-zinc-400 text-sm">{config.queryLanguage}</span>
                    <span className="text-zinc-500 text-xs">({Object.keys(config.fieldMappings || {}).length} IOC types)</span>
                  </div>
                  <svg className={`w-5 h-5 text-zinc-400 transition-transform ${expandedSiem === siemType ? 'rotate-180' : ''}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {/* Expanded content */}
                {expandedSiem === siemType && (
                  <div className="p-5 bg-zinc-900/50">
                    <div className="overflow-x-auto">
                      <table className="min-w-full border border-zinc-700 text-sm">
                        <thead className="bg-zinc-800/50">
                          <tr>
                            <th className="border border-zinc-700 px-3 py-2 text-left text-zinc-300 w-28">IOC Type</th>
                            <th className="border border-zinc-700 px-3 py-2 text-left text-zinc-300">Fields Searched</th>
                            <th className="border border-zinc-700 px-3 py-2 text-left text-zinc-300">Query Pattern</th>
                            <th className="border border-zinc-700 px-3 py-2 text-center text-zinc-300 w-20">Edit</th>
                          </tr>
                        </thead>
                        <tbody>
                          {IOC_TYPES.map(iocType => {
                            const fields = config.fieldMappings?.[iocType] || [];
                            if (fields.length === 0) return null;
                            const queryExample = config.queryExamples?.[iocType] || '';
                            return (
                              <tr key={iocType} className="hover:bg-zinc-800/30">
                                <td className="border border-zinc-700 px-3 py-2">
                                  <span className={`px-2 py-0.5 rounded text-xs border ${iocTypeColors[iocType] || 'bg-indigo-900/50 text-indigo-300 border-indigo-700'}`}>
                                    {iocType}
                                  </span>
                                </td>
                                <td className="border border-zinc-700 px-3 py-2">
                                  <div className="flex flex-wrap gap-1.5">
                                    {fields.map((f, i) => (
                                      <span key={i} className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-600 text-zinc-300 font-mono text-xs">
                                        {f}
                                      </span>
                                    ))}
                                  </div>
                                </td>
                                <td className="border border-zinc-700 px-3 py-2">
                                  <pre className="text-xs text-zinc-400 font-mono whitespace-pre-wrap break-all max-w-md">
                                    {queryExample || '-'}
                                  </pre>
                                </td>
                                <td className="border border-zinc-700 px-3 py-2 text-center">
                                  <button
                                    onClick={() => openEditDefaultModal(siemType, iocType, fields, queryExample)}
                                    className="bg-zinc-700 text-zinc-200 px-3 py-1 rounded hover:bg-zinc-600 transition text-xs"
                                    title="Edit fields and query pattern"
                                  >
                                    Edit
                                  </button>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* ============ CUSTOM OVERRIDES VIEW ============ */}
      {viewMode === 'overrides' && (
        <div>
          <div className="flex justify-between items-center mb-4">
            <p className="text-xs text-zinc-500">
              Custom overrides replace the default fields for a specific client and IOC type. Created via Field Discovery or manually.
            </p>
            <button onClick={() => setAddModal(true)}
              className="bg-indigo-600 text-white px-4 py-2 rounded hover:bg-indigo-700 transition font-medium text-sm">
              + Add Override
            </button>
          </div>

          {/* Filters */}
          <div className="flex gap-4 mb-6">
            <div>
              <label className="block text-sm font-medium text-zinc-400 mb-1">Filter by Client</label>
              <select value={filterClient} onChange={(e) => setFilterClient(e.target.value)}
                className="bg-zinc-800 border border-zinc-700 p-2 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                <option value="">All Clients</option>
                {uniqueClients.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-zinc-400 mb-1">Filter by IOC Type</label>
              <select value={filterType} onChange={(e) => setFilterType(e.target.value)}
                className="bg-zinc-800 border border-zinc-700 p-2 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                <option value="">All Types</option>
                {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
          </div>

          {/* Table */}
          {loading && mappings.length === 0 ? (
            <p className="text-zinc-400 text-center py-8">Loading...</p>
          ) : filteredMappings.length === 0 ? (
            <p className="text-zinc-400 text-center py-8 bg-zinc-800/50 rounded border border-zinc-700">
              No custom overrides. The system is using the SIEM defaults shown in the "SIEM Defaults" tab.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full border border-zinc-700">
                <thead className="bg-zinc-800">
                  <tr>
                    <th scope="col" className="border border-zinc-700 px-4 py-3 text-left text-zinc-300">Client</th>
                    <th scope="col" className="border border-zinc-700 px-4 py-3 text-left text-zinc-300">SIEM</th>
                    <th scope="col" className="border border-zinc-700 px-4 py-3 text-left text-zinc-300">IOC Type</th>
                    <th scope="col" className="border border-zinc-700 px-4 py-3 text-left text-zinc-300">Fields (Override)</th>
                    <th scope="col" className="border border-zinc-700 px-4 py-3 text-left text-zinc-300">Source</th>
                    <th scope="col" className="border border-zinc-700 px-4 py-3 text-center text-zinc-300">Status</th>
                    <th scope="col" className="border border-zinc-700 px-4 py-3 text-center text-zinc-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredMappings.map((m) => (
                    <tr key={m.id} className="hover:bg-zinc-800/50">
                      <td className="border border-zinc-700 px-4 py-2 text-zinc-200">{m.clientName}</td>
                      <td className="border border-zinc-700 px-4 py-2">
                        <span className={`px-2 py-1 rounded text-xs border ${siemTypeColors[m.siemType] || 'bg-zinc-700 text-zinc-300 border-zinc-600'}`}>
                          {SIEM_CONFIGS[m.siemType]?.label || m.siemType}
                        </span>
                      </td>
                      <td className="border border-zinc-700 px-4 py-2">
                        <span className={`px-2 py-1 rounded text-xs border ${iocTypeColors[m.filterType] || 'bg-indigo-900/50 text-indigo-300 border-indigo-700'}`}>{m.filterType}</span>
                      </td>
                      <td className="border border-zinc-700 px-4 py-2 font-mono text-sm text-zinc-300 max-w-xs">
                        {(m.fields || []).join(', ')}
                      </td>
                      <td className="border border-zinc-700 px-4 py-2 text-sm text-zinc-400">{m.logSource || '-'}</td>
                      <td className="border border-zinc-700 px-4 py-2 text-center">
                        <button onClick={() => toggleStatus(m)}
                          className={`px-2 py-1 rounded text-xs transition ${m.isApproved
                            ? 'bg-green-900/50 text-green-300 border border-green-700 hover:bg-green-800/50'
                            : 'bg-zinc-700 text-zinc-400 hover:bg-zinc-600'}`}>
                          {m.isApproved ? 'Active' : 'Disabled'}
                        </button>
                      </td>
                      <td className="border border-zinc-700 px-4 py-2 text-center">
                        <div className="flex gap-2 justify-center">
                          <button onClick={() => openEditModal(m)}
                            className="bg-zinc-700 text-zinc-200 px-3 py-1 rounded hover:bg-zinc-600 transition text-sm">Edit</button>
                          <button onClick={() => deleteMapping(m.id)}
                            className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 transition text-sm">Delete</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Edit Override Modal */}
      {editModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={() => setEditModal(null)} role="dialog" aria-modal="true" aria-labelledby="edit-mapping-title">
          <div ref={activeModalRef} className="bg-zinc-900 rounded-lg shadow-xl w-full max-w-md mx-4 border border-zinc-700" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-zinc-800">
              <h3 id="edit-mapping-title" className="text-lg font-semibold text-zinc-100">Edit Field Mapping</h3>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Client</label>
                <p className="text-zinc-400">{editModal.clientName} ({SIEM_CONFIGS[editModal.siemType]?.label || editModal.siemType})</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">IOC Type</label>
                <p className="text-zinc-400">{editModal.filterType}</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Fields (comma-separated)</label>
                <input type="text" value={editFields} onChange={(e) => setEditFields(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Enter SIEM field names separated by commas" />
              </div>
            </div>
            <div className="p-6 border-t border-zinc-800 flex justify-end gap-3">
              <button onClick={() => setEditModal(null)} className="px-4 py-2 border border-zinc-700 rounded text-zinc-300 hover:bg-zinc-800 transition">Cancel</button>
              <button onClick={saveEdit} disabled={loading} className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 transition disabled:opacity-50">
                {loading ? 'Saving...' : 'Save'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Default Field Modal */}
      {editDefaultModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={() => setEditDefaultModal(null)} role="dialog" aria-modal="true" aria-labelledby="edit-default-title">
          <div className="bg-zinc-900 rounded-lg shadow-xl w-full max-w-lg mx-4 border border-zinc-700" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-zinc-800">
              <h3 id="edit-default-title" className="text-lg font-semibold text-zinc-100">
                Edit Default &mdash; {siemDefaults[editDefaultModal.siemType]?.label} / {editDefaultModal.iocType}
              </h3>
            </div>
            <div className="p-6 space-y-4">
              {/* Disclaimer */}
              <div className="bg-amber-900/30 border border-amber-700 rounded-lg p-4">
                <div className="flex gap-2 items-start">
                  <svg className="w-5 h-5 text-amber-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                  </svg>
                  <div>
                    <p className="text-amber-300 text-sm font-semibold">Warning: Modifying search defaults may affect results</p>
                    <p className="text-amber-400/80 text-xs mt-1">
                      Changing the default fields or query pattern can cause searches to return different results, miss IOC hits, or produce errors.
                      Only modify these if you understand how your SIEM indexes data. Changes apply to this session only.
                    </p>
                  </div>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Fields (comma-separated)</label>
                <textarea
                  value={editDefaultFields}
                  onChange={(e) => setEditDefaultFields(e.target.value)}
                  rows={3}
                  className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="e.g., src_ip, dest_ip, client_ip"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Query Pattern</label>
                <textarea
                  value={editDefaultQuery}
                  onChange={(e) => setEditDefaultQuery(e.target.value)}
                  rows={3}
                  className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="Query pattern example"
                />
              </div>

              {/* Confirmation checkbox */}
              <label className="flex items-start gap-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={editConfirmed}
                  onChange={(e) => setEditConfirmed(e.target.checked)}
                  className="mt-1 w-4 h-4 rounded border-zinc-600 bg-zinc-800 text-indigo-500 focus:ring-indigo-500 focus:ring-offset-0"
                />
                <span className="text-sm text-zinc-300">
                  I understand that modifying these defaults may affect search accuracy and I have verified the changes.
                </span>
              </label>
            </div>
            <div className="p-6 border-t border-zinc-800 flex justify-end gap-3">
              <button onClick={() => setEditDefaultModal(null)} className="px-4 py-2 border border-zinc-700 rounded text-zinc-300 hover:bg-zinc-800 transition">Cancel</button>
              <button
                onClick={saveDefaultEdit}
                disabled={!editConfirmed}
                className={`px-4 py-2 rounded transition ${
                  editConfirmed
                    ? 'bg-amber-600 text-white hover:bg-amber-700'
                    : 'bg-zinc-700 text-zinc-500 cursor-not-allowed'
                }`}
              >
                Save Changes
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Modal */}
      {addModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={() => setAddModal(false)} role="dialog" aria-modal="true" aria-labelledby="add-mapping-title">
          <div ref={activeModalRef} className="bg-zinc-900 rounded-lg shadow-xl w-full max-w-md mx-4 border border-zinc-700" onClick={e => e.stopPropagation()}>
            <div className="p-6 border-b border-zinc-800">
              <h3 id="add-mapping-title" className="text-lg font-semibold text-zinc-100">Add Field Mapping Override</h3>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Client</label>
                <select value={newMapping.clientId} onChange={(e) => setNewMapping({ ...newMapping, clientId: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                  <option value="">-- Choose a SIEM client --</option>
                  {apiKeys.map(k => <option key={k.id} value={k.id}>{k.client} ({SIEM_CONFIGS[k.siemType]?.label || k.siemType})</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">IOC Type</label>
                <select value={newMapping.filterType} onChange={(e) => setNewMapping({ ...newMapping, filterType: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500">
                  {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Fields (comma-separated)</label>
                <input type="text" value={newMapping.fields} onChange={(e) => setNewMapping({ ...newMapping, fields: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="e.g., src_ip, dst_ip, originHost" />
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Source (optional)</label>
                <input type="text" value={newMapping.logSource} onChange={(e) => setNewMapping({ ...newMapping, logSource: e.target.value })}
                  className="w-full bg-zinc-800 border border-zinc-700 p-3 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  placeholder="e.g., Field Discovery, Manual" />
              </div>
            </div>
            <div className="p-6 border-t border-zinc-800 flex justify-end gap-3">
              <button onClick={() => setAddModal(false)} className="px-4 py-2 border border-zinc-700 rounded text-zinc-300 hover:bg-zinc-800 transition">Cancel</button>
              <button onClick={addNewMapping} disabled={loading} className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 transition disabled:opacity-50">
                {loading ? 'Creating...' : 'Create'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
