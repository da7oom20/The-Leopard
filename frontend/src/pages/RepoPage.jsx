import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Footer from '../components/Footer';
import { LeopardLogoCompact } from '../components/Logo';
import ErrorAlert from '../components/ErrorAlert';
import { apiFetch } from '../utils/apiClient';

const API_URL = process.env.REACT_APP_API_URL || '/api';

export default function RepoPage() {
    const navigate = useNavigate();
    const [items, setItems] = useState([]);
    const [offset, setOffset] = useState(0);
    const [hasMore, setHasMore] = useState(true);
    const [loading, setLoading] = useState(false);
    const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });
    const [exportErrorInfo, setExportErrorInfo] = useState({ error: '', suggestion: '', category: '' });
    const [downloadingId, setDownloadingId] = useState(null);
    const LIMIT = 10;
    const [searchAuthRequired, setSearchAuthRequired] = useState(false);
    // Track whether we've finished checking /settings/search-auth. Without
    // this the initial /repo load raced the settings fetch: if auth was
    // required the request went out with no Authorization header, got 401,
    // and fired the shared session-expired event (which auto-logged the
    // user out and painted both "Failed to load search history" and
    // "Your session has expired" banners).
    const [authSettingsLoaded, setAuthSettingsLoaded] = useState(false);

    // Filters
    const [filterClient, setFilterClient] = useState('');
    const [filterType, setFilterType] = useState('');
    const [filterHit, setFilterHit] = useState('');
    const [filterDateFrom, setFilterDateFrom] = useState('');
    const [filterDateTo, setFilterDateTo] = useState('');
    const [filterOptions, setFilterOptions] = useState({ clients: [], filterTypes: [] });

    useEffect(() => {
        apiFetch(`${API_URL}/settings/search-auth`)
          .then(r => r.json())
          .then(data => setSearchAuthRequired(!!data.requireSearchAuth))
          .catch(() => {})
          .finally(() => setAuthSettingsLoaded(true));
    }, []);

    // Always attach the bearer token if we have one, regardless of whether
    // auth is currently required. The backend only reads it when
    // optionalSearchAuth is active; sending it when it's not needed is a
    // no-op. This makes the client resilient to the settings fetch
    // resolving after the first data fetch.
    const getAuthHeaders = () => {
        const token = localStorage.getItem('token');
        return token ? { Authorization: `Bearer ${token}` } : {};
    };

    // Fetch filter options once we know the auth requirement.
    useEffect(() => {
        if (!authSettingsLoaded) return;
        apiFetch(`${API_URL}/repo/filters`, { headers: getAuthHeaders() })
          .then(r => r.json())
          .then(data => setFilterOptions({ clients: data.clients || [], filterTypes: data.filterTypes || [] }))
          .catch(() => {});
    }, [authSettingsLoaded]);

    const buildQuery = (nextOffset) => {
        const params = new URLSearchParams({ offset: nextOffset, limit: LIMIT });
        if (filterClient) params.set('client', filterClient);
        if (filterType) params.set('filterType', filterType);
        if (filterHit) params.set('hit', filterHit);
        if (filterDateFrom) params.set('dateFrom', filterDateFrom);
        if (filterDateTo) params.set('dateTo', filterDateTo);
        return params.toString();
    };

    const loadPage = async (nextOffset = 0) => {
        if (loading) return;
        setLoading(true);
        setErrorInfo({ error: '', suggestion: '', category: '' });
        try {
            const res = await apiFetch(`${API_URL}/repo?${buildQuery(nextOffset)}`, { headers: getAuthHeaders() });
            if (!res.ok) throw new Error('Failed to load search history');
            const data = await res.json();
            setItems(prev => nextOffset === 0 ? data.items : [...prev, ...data.items]);
            setOffset(nextOffset + LIMIT);
            setHasMore(Boolean(data.hasMore));
        } catch (e) {
            setErrorInfo({ error: e.message || 'Failed to load search history.', suggestion: 'Check your network connection and try refreshing the page.', category: 'connection' });
        } finally {
            setLoading(false);
        }
    };

    // Wait for the auth setting to be known before firing the first
    // /repo request — otherwise we'd send no token, get 401, and trigger
    // a spurious session-expired event. Intentionally depends only on
    // authSettingsLoaded so this fires exactly once on first load.
    useEffect(() => {
        if (!authSettingsLoaded) return;
        loadPage(0);
    }, [authSettingsLoaded]);

    const applyFilters = () => {
        setItems([]);
        setOffset(0);
        setHasMore(true);
        loadPage(0);
    };

    const clearFilters = () => {
        setFilterClient('');
        setFilterType('');
        setFilterHit('');
        setFilterDateFrom('');
        setFilterDateTo('');
        setItems([]);
        setOffset(0);
        setHasMore(true);
        // loadPage will be triggered by the effect below
    };

    // Reload when filters are cleared (all empty)
    const [pendingClear, setPendingClear] = useState(false);
    useEffect(() => {
        if (pendingClear && !filterClient && !filterType && !filterHit && !filterDateFrom && !filterDateTo) {
            setPendingClear(false);
            loadPage(0);
        }
    }, [pendingClear, filterClient, filterType, filterHit, filterDateFrom, filterDateTo]);

    const handleClear = () => {
        setFilterClient('');
        setFilterType('');
        setFilterHit('');
        setFilterDateFrom('');
        setFilterDateTo('');
        setItems([]);
        setOffset(0);
        setHasMore(true);
        setPendingClear(true);
    };

    const downloadCsvForRow = async (id) => {
        if (downloadingId) return;
        setDownloadingId(id);
        setExportErrorInfo({ error: '', suggestion: '', category: '' });
        try {
            const BASE_URL = API_URL.replace(/\/api\/?$/, '');
            const res = await apiFetch(`${BASE_URL}/export-results?resultId=${encodeURIComponent(id)}&layout=flat`, { headers: getAuthHeaders() });
            if (!res.ok) throw new Error('Export failed');
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `result_${id}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        } catch (e) {
            setExportErrorInfo({ error: e.message || 'Export failed.', suggestion: 'Try again. If the problem persists, check the backend logs.', category: 'server' });
        } finally {
            setDownloadingId(null);
        }
    };

    // Which resultId is currently being re-run. Only one at a time so the
    // UI stays responsive and we don't flood the SIEM with concurrent
    // re-runs from a double-click.
    const [rerunningId, setRerunningId] = useState(null);
    const rerunFilter = async (resultId) => {
        if (rerunningId) return;
        setRerunningId(resultId);
        setErrorInfo({ error: '', suggestion: '', category: '' });
        try {
            const res = await apiFetch(`${API_URL}/hunt/rerun`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
                body: JSON.stringify({ resultId })
            });
            if (!res.ok) {
                let msg = 'Re-run failed';
                try { const d = await res.json(); msg = d.error || msg; } catch (_) {}
                throw new Error(msg);
            }
            const updated = await res.json();
            // Patch the single row in-place. The hunt list structure is
            // items[].clients[].filters[], so find and replace by resultId.
            setItems(prev => prev.map(h => ({
                ...h,
                clients: h.clients.map(c => ({
                    ...c,
                    filters: c.filters.map(f => f.resultId === resultId ? {
                        ...f,
                        hit: updated.hit,
                        resultCount: updated.resultCount,
                        searchDuration: updated.searchDuration,
                        errorMessage: updated.errorMessage || null
                    } : f)
                }))
            })));
        } catch (e) {
            setErrorInfo({
                error: e.message || 'Re-run failed.',
                suggestion: 'Check SIEM connectivity and that this client is still active.',
                category: 'server'
            });
        } finally {
            setRerunningId(null);
        }
    };

    const hitChipClass = (hit) =>
        hit === 'hit'
            ? 'bg-red-900/50 text-red-300 border border-red-700'
            : hit === 'error'
                ? 'bg-amber-900/50 text-amber-300 border border-amber-700'
                : 'bg-green-900/50 text-green-300 border border-green-700';
    const hitLabel = (hit) =>
        hit === 'hit' ? 'Hit' : hit === 'error' ? 'Error' : 'No Hit';

    const hasActiveFilters = filterClient || filterType || filterHit || filterDateFrom || filterDateTo;

    return (
        <div className="flex flex-col min-h-screen bg-zinc-950 text-zinc-100">
            <div className="flex-1 p-6">
                {/* Header */}
                <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
                    <div className="flex items-center gap-3">
                        <LeopardLogoCompact size={36} showText={false} />
                        <div>
                            <h1 className="text-2xl font-bold text-zinc-100">Searches Repo</h1>
                            <p className="text-zinc-400 text-xs">Search history and results</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-3 flex-wrap">
                        <button
                            onClick={() => navigate('/')}
                            className="px-4 py-2 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        >
                            Back to Search
                        </button>
                        <button
                            onClick={() => navigate('/admin')}
                            className="px-4 py-2 rounded-md bg-zinc-700 text-white hover:bg-zinc-600 transition focus:outline-none focus:ring-2 focus:ring-zinc-500"
                        >
                            Admin Panel
                        </button>
                    </div>
                </div>

                {/* Disclaimer */}
                <div className="mb-4 p-3 bg-yellow-900/50 text-yellow-200 border border-yellow-700 rounded-md text-sm">
                    <strong>Note:</strong> CSV exports contain a limited subset of results intended as a quick reference.
                    Please review the full results directly in your SIEM for comprehensive data.
                </div>

                {/* Filters */}
                <div className="mb-4 p-4 bg-zinc-900 border border-zinc-700 rounded-lg">
                    <div className="flex flex-wrap gap-3 items-end">
                        <div>
                            <label htmlFor="filter-client" className="block text-xs text-zinc-400 mb-1">Client</label>
                            <select
                                id="filter-client"
                                value={filterClient}
                                onChange={e => setFilterClient(e.target.value)}
                                className="p-2 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            >
                                <option value="">All Clients</option>
                                {filterOptions.clients.map(c => <option key={c} value={c}>{c}</option>)}
                            </select>
                        </div>
                        <div>
                            <label htmlFor="filter-type" className="block text-xs text-zinc-400 mb-1">IOC Type</label>
                            <select
                                id="filter-type"
                                value={filterType}
                                onChange={e => setFilterType(e.target.value)}
                                className="p-2 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            >
                                <option value="">All Types</option>
                                {filterOptions.filterTypes.map(t => <option key={t} value={t}>{t}</option>)}
                            </select>
                        </div>
                        <div>
                            <label htmlFor="filter-hit" className="block text-xs text-zinc-400 mb-1">Status</label>
                            <select
                                id="filter-hit"
                                value={filterHit}
                                onChange={e => setFilterHit(e.target.value)}
                                className="p-2 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            >
                                <option value="">All</option>
                                <option value="hit">Hit</option>
                                <option value="no hit">No Hit</option>
                                <option value="error">Error</option>
                            </select>
                        </div>
                        <div>
                            <label htmlFor="filter-from" className="block text-xs text-zinc-400 mb-1">From</label>
                            <input
                                id="filter-from"
                                type="date"
                                value={filterDateFrom}
                                onChange={e => setFilterDateFrom(e.target.value)}
                                className="p-2 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            />
                        </div>
                        <div>
                            <label htmlFor="filter-to" className="block text-xs text-zinc-400 mb-1">To</label>
                            <input
                                id="filter-to"
                                type="date"
                                value={filterDateTo}
                                onChange={e => setFilterDateTo(e.target.value)}
                                className="p-2 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                            />
                        </div>
                        <button
                            onClick={applyFilters}
                            disabled={loading}
                            className="px-4 py-2 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
                        >
                            Apply
                        </button>
                        {hasActiveFilters && (
                            <button
                                onClick={handleClear}
                                disabled={loading}
                                className="px-4 py-2 rounded-md bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition text-sm focus:outline-none focus:ring-2 focus:ring-zinc-500 disabled:opacity-50"
                            >
                                Clear
                            </button>
                        )}
                    </div>
                </div>

                {/* Error Messages */}
                <ErrorAlert
                    error={errorInfo.error}
                    suggestion={errorInfo.suggestion}
                    category={errorInfo.category}
                    onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
                    className="mb-4"
                />
                <ErrorAlert
                    error={exportErrorInfo.error}
                    suggestion={exportErrorInfo.suggestion}
                    category={exportErrorInfo.category}
                    onDismiss={() => setExportErrorInfo({ error: '', suggestion: '', category: '' })}
                    className="mb-4"
                />

                {/* Grouped hunt cards */}
                {items.length === 0 && !loading && (
                    <div className="bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-12 text-center">
                        <svg className="mx-auto h-10 w-10 text-zinc-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                        </svg>
                        <p className="text-zinc-500">{hasActiveFilters ? 'No results match your filters.' : 'No search submissions yet.'}</p>
                        <p className="text-zinc-600 text-xs mt-1">{hasActiveFilters ? 'Try adjusting or clearing the filters.' : 'Completed searches will appear here.'}</p>
                    </div>
                )}

                <div className="space-y-4">
                    {items.map(hunt => (
                        <div key={hunt.huntId} className="bg-zinc-900 border border-zinc-700 rounded-lg overflow-hidden">
                            {/* Hunt header */}
                            <div className="px-4 py-3 bg-zinc-800/50 border-b border-zinc-700 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                                <div>
                                    <div className="text-sm font-medium text-zinc-100 break-all">
                                        {hunt.fileName || '(no file name)'}
                                    </div>
                                    <div className="text-xs text-zinc-500 mt-0.5 flex flex-wrap gap-x-3 gap-y-1">
                                        <span>{new Date(hunt.createdAt).toLocaleString()}</span>
                                        <span>{hunt.clients.length} client{hunt.clients.length !== 1 ? 's' : ''}</span>
                                        {hunt.minutesBack != null && (
                                            <span>window: {hunt.minutesBack} min</span>
                                        )}
                                        <span className="font-mono text-[0.65rem] text-zinc-600" title={hunt.huntId}>
                                            hunt id: {hunt.huntId.length > 40 ? hunt.huntId.slice(0, 40) + '…' : hunt.huntId}
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Per-client sections */}
                            <div className="divide-y divide-zinc-800">
                                {hunt.clients.map(c => (
                                    <div key={c.client} className="px-4 py-3">
                                        <div className="text-sm font-semibold text-zinc-200 mb-2 flex items-center gap-2">
                                            <span>{c.client}</span>
                                            <span className="text-xs font-normal text-zinc-500">({c.siemType || 'logrhythm'})</span>
                                        </div>
                                        <div className="overflow-x-auto">
                                            <table className="min-w-full text-sm">
                                                <thead className="text-zinc-400 text-xs uppercase tracking-wider">
                                                    <tr>
                                                        <th scope="col" className="text-left py-1.5 pr-4 font-medium">IOC Type</th>
                                                        <th scope="col" className="text-left py-1.5 pr-4 font-medium">IOCs</th>
                                                        <th scope="col" className="text-left py-1.5 pr-4 font-medium">Status</th>
                                                        <th scope="col" className="text-left py-1.5 pr-4 font-medium">Results</th>
                                                        <th scope="col" className="text-right py-1.5 pl-4 font-medium">Actions</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-zinc-800/60">
                                                    {c.filters.map(f => (
                                                        <tr key={f.resultId}>
                                                            <td className="py-2 pr-4 text-zinc-200 whitespace-nowrap">{f.filterType || '-'}</td>
                                                            <td className="py-2 pr-4 text-zinc-400">{f.iocCount}</td>
                                                            <td className="py-2 pr-4">
                                                                <span
                                                                    className={`px-2 py-0.5 rounded text-xs font-medium ${hitChipClass(f.hit)}`}
                                                                    title={f.hit === 'error' && f.errorMessage ? f.errorMessage : undefined}
                                                                >
                                                                    {hitLabel(f.hit)}
                                                                </span>
                                                            </td>
                                                            <td className="py-2 pr-4 text-zinc-300">{f.resultCount}</td>
                                                            <td className="py-2 pl-4 text-right whitespace-nowrap">
                                                                <div className="inline-flex items-center gap-2">
                                                                    <button
                                                                        onClick={() => rerunFilter(f.resultId)}
                                                                        disabled={rerunningId !== null}
                                                                        className="px-2.5 py-1 rounded-md bg-zinc-700 text-zinc-100 hover:bg-zinc-600 transition text-xs focus:outline-none focus:ring-2 focus:ring-zinc-500 disabled:opacity-50 inline-flex items-center gap-1.5"
                                                                        aria-label={`Re-run ${f.filterType} for ${c.client}`}
                                                                        title={rerunningId === f.resultId ? 'Re-running…' : 'Re-run this search'}
                                                                    >
                                                                        {rerunningId === f.resultId && (
                                                                            <svg className="animate-spin h-3 w-3" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                                                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                                                            </svg>
                                                                        )}
                                                                        {rerunningId === f.resultId ? 'Running…' : 'Re-run'}
                                                                    </button>
                                                                    <button
                                                                        onClick={() => downloadCsvForRow(f.resultId)}
                                                                        disabled={downloadingId === f.resultId}
                                                                        className="px-2.5 py-1 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition text-xs focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
                                                                        aria-label={`Download CSV for ${c.client} / ${f.filterType}`}
                                                                        title="Download CSV"
                                                                    >
                                                                        {downloadingId === f.resultId ? '…' : 'CSV'}
                                                                    </button>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}

                    {loading && (
                        <div className="bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-6 text-center">
                            <div className="flex items-center justify-center gap-2 text-zinc-400">
                                <svg className="animate-spin h-5 w-5 text-indigo-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                                <span>Loading...</span>
                            </div>
                        </div>
                    )}
                </div>

                {/* Pagination */}
                <div className="mt-4 flex justify-center gap-4">
                    {hasMore && !loading && (
                        <button
                            onClick={() => loadPage(offset)}
                            className="px-5 py-2 rounded-md bg-zinc-700 text-white hover:bg-zinc-600 transition focus:outline-none focus:ring-2 focus:ring-zinc-500"
                        >
                            Load More
                        </button>
                    )}
                </div>

                {/* Summary */}
                {items.length > 0 && (
                    <p className="text-center text-zinc-500 text-xs mt-3">
                        Showing {items.length} hunt{items.length !== 1 ? 's' : ''}
                        {hasMore ? ' (more available)' : ''}
                    </p>
                )}
            </div>

            <Footer />
        </div>
    );
}
