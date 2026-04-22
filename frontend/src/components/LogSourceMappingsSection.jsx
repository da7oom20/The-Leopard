import React, { useState, useEffect, useMemo } from 'react';
import axios from 'axios';

const IOC_TYPES = ['IP', 'Hash', 'Domain', 'URL', 'Email', 'FileName'];

const sourceLabel = (siemType) => {
  switch ((siemType || '').toLowerCase()) {
    case 'splunk': return 'Indexes';
    case 'logrhythm': return 'Log Sources';
    case 'elastic': return 'Indexes';
    case 'wazuh': return 'Agents';
    case 'qradar': return 'Log Sources';
    case 'manageengine': return 'Log Sources';
    default: return 'Log Sources';
  }
};

const sourceKey = (s) => String(s.id ?? s.listId ?? s.name ?? s.guid ?? '');

export default function LogSourceMappingsSection({ token, API_URL, apiKeys }) {
  const [selectedClientId, setSelectedClientId] = useState('');
  const [activeIoc, setActiveIoc] = useState('IP');
  const [sources, setSources] = useState([]);
  const [siemType, setSiemType] = useState('');
  const [selectionsByIoc, setSelectionsByIoc] = useState(() =>
    Object.fromEntries(IOC_TYPES.map(t => [t, new Set()]))
  );
  const [filters, setFilters] = useState({ name: '', entities: new Set(), types: new Set() });
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState({ kind: '', message: '' });

  const selectedClient = useMemo(
    () => apiKeys.find(k => String(k.id) === String(selectedClientId)) || null,
    [apiKeys, selectedClientId]
  );

  const resetFilters = () => setFilters({ name: '', entities: new Set(), types: new Set() });
  const resetSelections = () => setSelectionsByIoc(Object.fromEntries(IOC_TYPES.map(t => [t, new Set()])));

  const loadAll = async (clientId) => {
    if (!clientId) return;
    resetSelections();
    resetFilters();
    setStatus({ kind: '', message: '' });
    setLoading(true);
    try {
      const [srcRes, mapRes] = await Promise.all([
        axios.get(`${API_URL}/admin/log-sources/${clientId}`, { headers: { Authorization: `Bearer ${token}` } }),
        axios.get(`${API_URL}/admin/log-source-mappings/${clientId}`, { headers: { Authorization: `Bearer ${token}` } })
      ]);
      setSources(Array.isArray(srcRes.data?.sources) ? srcRes.data.sources : []);
      setSiemType(srcRes.data?.siemType || mapRes.data?.siemType || '');
      const grouped = mapRes.data?.mappings || {};
      const next = Object.fromEntries(IOC_TYPES.map(t => [t, new Set()]));
      for (const t of IOC_TYPES) {
        for (const item of grouped[t] || []) {
          next[t].add(String(item.listId ?? item.id ?? item.name ?? item.guid ?? ''));
        }
      }
      setSelectionsByIoc(next);
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Failed to load';
      setStatus({ kind: 'error', message: msg });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (selectedClientId) loadAll(selectedClientId);
    else { setSources([]); setSiemType(''); resetSelections(); resetFilters(); }
  }, [selectedClientId]);

  // Distinct root-entity values (grouping parent + children under one pill).
  // Falls back to entityName when rootEntityName isn't present (e.g. non-LR SIEMs).
  // Returns [{ root, count, children: [leaf...] }] sorted by root.
  const availableEntities = useMemo(() => {
    const buckets = new Map();
    sources.forEach(src => {
      const root = src.entityRootName || src.entityName;
      if (!root) return;
      const key = String(root);
      if (!buckets.has(key)) buckets.set(key, { root: key, count: 0, children: new Set() });
      const bucket = buckets.get(key);
      bucket.count += 1;
      const leaf = src.entityName && String(src.entityName) !== key ? String(src.entityName) : null;
      if (leaf) bucket.children.add(leaf);
    });
    return [...buckets.values()]
      .map(b => ({ ...b, children: [...b.children].sort() }))
      .sort((a, b) => a.root.localeCompare(b.root));
  }, [sources]);

  const availableTypes = useMemo(() => {
    const s = new Set();
    sources.forEach(src => { if (src.logSourceTypeName) s.add(String(src.logSourceTypeName)); });
    return [...s].sort();
  }, [sources]);

  const filtered = useMemo(() => {
    const nameFilter = (filters.name || '').toLowerCase().trim();
    return sources.filter(s => {
      if (nameFilter) {
        const hay = [
          s.name, s.hostName, s.entityName, s.entityRootName, s.logSourceTypeName,
          String(s.id ?? ''), String(s.listId ?? '')
        ].join(' ').toLowerCase();
        if (!hay.includes(nameFilter)) return false;
      }
      if (filters.entities.size > 0) {
        const root = String(s.entityRootName || s.entityName || '');
        if (!filters.entities.has(root)) return false;
      }
      if (filters.types.size > 0 && !filters.types.has(String(s.logSourceTypeName || ''))) return false;
      return true;
    });
  }, [sources, filters]);

  const togglePill = (group, value) => {
    setFilters(prev => {
      const next = new Set(prev[group]);
      if (next.has(value)) next.delete(value); else next.add(value);
      return { ...prev, [group]: next };
    });
  };

  const toggleSelection = (key) => {
    setSelectionsByIoc(prev => {
      const next = { ...prev };
      const set = new Set(next[activeIoc]);
      if (set.has(key)) set.delete(key); else set.add(key);
      next[activeIoc] = set;
      return next;
    });
  };

  const selectAllVisible = () => {
    setSelectionsByIoc(prev => {
      const next = { ...prev };
      const set = new Set(next[activeIoc]);
      filtered.forEach(s => set.add(sourceKey(s)));
      next[activeIoc] = set;
      return next;
    });
  };

  const clearVisible = () => {
    setSelectionsByIoc(prev => {
      const next = { ...prev };
      const set = new Set(next[activeIoc]);
      filtered.forEach(s => set.delete(sourceKey(s)));
      next[activeIoc] = set;
      return next;
    });
  };

  const saveActiveIoc = async () => {
    if (!selectedClientId) return;
    setSaving(true);
    setStatus({ kind: '', message: '' });
    const keys = Array.from(selectionsByIoc[activeIoc] || []);
    const items = keys
      .map(k => sources.find(s => sourceKey(s) === k))
      .filter(Boolean)
      .map(s => ({
        listId: s.listId ?? s.id ?? null,
        name: s.name ?? null,
        guid: s.guid ?? null,
        listType: s.listType ?? null
      }));
    const payload = { clientId: parseInt(selectedClientId, 10), mappings: { [activeIoc]: items } };
    try {
      const res = await axios.post(`${API_URL}/admin/log-source-mappings`, payload, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStatus({ kind: 'success', message: `Saved ${items.length} ${sourceLabel(siemType).toLowerCase()} for ${activeIoc}.` });
    } catch (err) {
      setStatus({ kind: 'error', message: err.response?.data?.error || 'Failed to save mappings' });
    } finally {
      setSaving(false);
    }
  };

  const activeSet = selectionsByIoc[activeIoc] || new Set();
  const selectedCount = activeSet.size;

  return (
    <div className="mt-10 pt-8 border-t border-zinc-800">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-zinc-100">Log Source Mapping</h3>
          <p className="text-sm text-zinc-400">
            Pick a SIEM client and one IOC type at a time. Filter the available {sourceLabel(siemType).toLowerCase()} by entity, type, or name, then save.
          </p>
        </div>
      </div>

      {/* Client selector */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <label className="text-sm text-zinc-400">Client:</label>
        <select
          value={selectedClientId}
          onChange={(e) => setSelectedClientId(e.target.value)}
          className="bg-zinc-800 border border-zinc-700 px-3 py-2 rounded text-zinc-100 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">— Choose a SIEM client —</option>
          {apiKeys.map(k => (
            <option key={k.id} value={k.id}>{k.client} ({k.siemType})</option>
          ))}
        </select>
        {selectedClientId && (
          <button
            onClick={() => loadAll(selectedClientId)}
            disabled={loading}
            className="px-3 py-2 bg-zinc-700 text-zinc-100 rounded text-sm hover:bg-zinc-600 transition disabled:opacity-50"
          >
            {loading ? 'Loading…' : 'Reload'}
          </button>
        )}
        {selectedClientId && (
          <span className="text-xs text-zinc-500">
            {sources.length} {sourceLabel(siemType).toLowerCase()} available
          </span>
        )}
      </div>

      {status.message && (
        <div className={`p-3 rounded mb-4 text-sm ${
          status.kind === 'success' ? 'bg-green-900/30 text-green-400 border border-green-800' :
          status.kind === 'error' ? 'bg-red-900/30 text-red-400 border border-red-800' :
          'bg-yellow-900/30 text-yellow-400 border border-yellow-800'
        }`}>
          {status.message}
        </div>
      )}

      {selectedClientId && sources.length === 0 && !loading && !status.message && (
        <p className="text-sm text-zinc-500 italic">No {sourceLabel(siemType).toLowerCase()} returned by the SIEM.</p>
      )}

      {sources.length > 0 && (
        <>
          {/* IOC type tabs */}
          <div className="flex flex-wrap gap-1 mb-4 border-b border-zinc-800">
            {IOC_TYPES.map(ioc => {
              const count = (selectionsByIoc[ioc] || new Set()).size;
              const isActive = activeIoc === ioc;
              return (
                <button
                  key={ioc}
                  onClick={() => setActiveIoc(ioc)}
                  className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition ${
                    isActive
                      ? 'border-indigo-500 text-indigo-300'
                      : 'border-transparent text-zinc-400 hover:text-zinc-200 hover:border-zinc-700'
                  }`}
                >
                  {ioc}
                  {count > 0 && (
                    <span className={`ml-2 inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 rounded-full text-xs ${
                      isActive ? 'bg-indigo-600 text-white' : 'bg-zinc-700 text-zinc-200'
                    }`}>
                      {count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Filters */}
          <div className="bg-zinc-900/40 border border-zinc-800 rounded-lg p-4 mb-4 space-y-3">
            <div>
              <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">Search</label>
              <input
                type="text"
                placeholder={`Filter by name, host, ID…`}
                value={filters.name}
                onChange={(e) => setFilters(prev => ({ ...prev, name: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-700 px-3 py-2 rounded text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            {availableEntities.length > 0 && (
              <div>
                <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
                  Entity{filters.entities.size > 0 && <span className="ml-2 text-indigo-400 normal-case tracking-normal">{filters.entities.size} selected</span>}
                </label>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto pr-1">
                  {availableEntities.map(({ root, count, children }) => {
                    const on = filters.entities.has(root);
                    const hasKids = children.length > 0;
                    const tooltip = hasKids
                      ? `${root} (root) + ${children.length} child entit${children.length === 1 ? 'y' : 'ies'}: ${children.join(', ')} · ${count} sources`
                      : `${root} · ${count} source${count === 1 ? '' : 's'}`;
                    return (
                      <button
                        key={root}
                        onClick={() => togglePill('entities', root)}
                        title={tooltip}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-full border transition ${
                          on
                            ? 'bg-indigo-600 border-indigo-500 text-white'
                            : 'bg-zinc-800 border-zinc-700 text-zinc-300 hover:border-zinc-600'
                        }`}
                      >
                        <span>{root}</span>
                        {hasKids && (
                          <span className={`text-[10px] leading-none ${on ? 'text-white/70' : 'text-zinc-500'}`}>
                            +{children.length}
                          </span>
                        )}
                        <span className={`font-mono text-[10px] leading-none px-1 rounded-sm ${
                          on ? 'bg-white/20 text-white' : 'bg-zinc-900 text-zinc-400'
                        }`}>
                          {count}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {availableTypes.length > 0 && (
              <div>
                <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
                  Log Source Type{filters.types.size > 0 && <span className="ml-2 text-indigo-400 normal-case tracking-normal">{filters.types.size} selected</span>}
                </label>
                <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto pr-1">
                  {availableTypes.map(t => {
                    const on = filters.types.has(t);
                    return (
                      <button
                        key={t}
                        onClick={() => togglePill('types', t)}
                        className={`px-2.5 py-1 text-xs rounded-full border transition ${
                          on
                            ? 'bg-indigo-600 border-indigo-500 text-white'
                            : 'bg-zinc-800 border-zinc-700 text-zinc-300 hover:border-zinc-600'
                        }`}
                      >
                        {t}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {(filters.name || filters.entities.size > 0 || filters.types.size > 0) && (
              <div>
                <button
                  onClick={resetFilters}
                  className="text-xs text-zinc-400 hover:text-zinc-200 underline"
                >
                  Clear filters
                </button>
              </div>
            )}
          </div>

          {/* Filtered list */}
          <div className="bg-zinc-900/40 border border-zinc-800 rounded-lg">
            <div className="flex items-center justify-between px-4 py-2 border-b border-zinc-800">
              <span className="text-sm text-zinc-400">
                {filtered.length} of {sources.length} shown · {selectedCount} selected for <span className="text-indigo-300 font-medium">{activeIoc}</span>
              </span>
              <div className="flex gap-2">
                <button
                  onClick={selectAllVisible}
                  disabled={filtered.length === 0}
                  className="text-xs px-2 py-1 border border-zinc-700 text-zinc-300 rounded hover:bg-zinc-800 transition disabled:opacity-50"
                >
                  Select all visible
                </button>
                <button
                  onClick={clearVisible}
                  disabled={filtered.length === 0}
                  className="text-xs px-2 py-1 border border-zinc-700 text-zinc-300 rounded hover:bg-zinc-800 transition disabled:opacity-50"
                >
                  Deselect visible
                </button>
              </div>
            </div>
            <div className="max-h-96 overflow-y-auto">
              {filtered.length === 0 ? (
                <p className="text-sm text-zinc-500 italic px-4 py-6 text-center">
                  No {sourceLabel(siemType).toLowerCase()} match the current filters.
                </p>
              ) : (
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-zinc-900 text-xs text-zinc-500 uppercase">
                    <tr>
                      <th className="px-3 py-2 w-8"></th>
                      <th className="px-3 py-2 text-left">Name</th>
                      <th className="px-3 py-2 text-left">Entity</th>
                      <th className="px-3 py-2 text-left">Type</th>
                      <th className="px-3 py-2 text-left">Host</th>
                      <th className="px-3 py-2 text-right">ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(s => {
                      const key = sourceKey(s);
                      const isChecked = activeSet.has(key);
                      return (
                        <tr
                          key={key}
                          onClick={() => toggleSelection(key)}
                          className={`cursor-pointer border-t border-zinc-800 hover:bg-zinc-800/50 ${isChecked ? 'bg-indigo-900/20' : ''}`}
                        >
                          <td className="px-3 py-2">
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={() => toggleSelection(key)}
                              onClick={(e) => e.stopPropagation()}
                              className="h-4 w-4 rounded border-zinc-600 bg-zinc-800 text-indigo-500 focus:ring-indigo-500"
                            />
                          </td>
                          <td className="px-3 py-2 text-zinc-100">{s.name || '(unnamed)'}</td>
                          <td className="px-3 py-2 text-zinc-400">
                            {s.entityRootName && s.entityName && s.entityRootName !== s.entityName ? (
                              <span>
                                <span className="text-zinc-200">{s.entityRootName}</span>
                                <span className="text-zinc-600 mx-1">·</span>
                                <span>{s.entityName}</span>
                              </span>
                            ) : (
                              <span>{s.entityRootName || s.entityName || '—'}</span>
                            )}
                          </td>
                          <td className="px-3 py-2 text-zinc-400">{s.logSourceTypeName || '—'}</td>
                          <td className="px-3 py-2 text-zinc-400">{s.hostName || '—'}</td>
                          <td className="px-3 py-2 text-right text-xs text-zinc-500 font-mono">{s.id ?? s.listId ?? ''}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="flex items-center justify-end gap-2 mt-4">
            <button
              onClick={saveActiveIoc}
              disabled={saving}
              className="px-4 py-2 bg-indigo-600 text-white rounded font-medium hover:bg-indigo-700 transition disabled:opacity-50"
            >
              {saving ? 'Saving…' : `Save ${activeIoc} mapping`}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
