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
          .catch(() => {});
    }, []);

    const getAuthHeaders = () => {
        if (!searchAuthRequired) return {};
        const token = localStorage.getItem('token');
        return token ? { Authorization: `Bearer ${token}` } : {};
    };

    // Fetch filter options
    useEffect(() => {
        apiFetch(`${API_URL}/repo/filters`, { headers: getAuthHeaders() })
          .then(r => r.json())
          .then(data => setFilterOptions({ clients: data.clients || [], filterTypes: data.filterTypes || [] }))
          .catch(() => {});
    }, []);

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

    useEffect(() => {
        loadPage(0);
    }, []);

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

                {/* Table */}
                <div className="overflow-x-auto bg-zinc-900 border border-zinc-700 rounded-lg">
                    <table className="min-w-full text-sm" aria-label="Search history table">
                        <thead className="bg-zinc-800/50 text-zinc-300">
                            <tr>
                                <th scope="col" className="text-left px-4 py-3 font-medium">Date</th>
                                <th scope="col" className="text-left px-4 py-3 font-medium">Client</th>
                                <th scope="col" className="text-left px-4 py-3 font-medium">IOC Types</th>
                                <th scope="col" className="text-left px-4 py-3 font-medium">Hit?</th>
                                <th scope="col" className="text-left px-4 py-3 font-medium">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-zinc-800">
                            {items.length === 0 && !loading && (
                                <tr>
                                    <td colSpan={5} className="px-4 py-12 text-center">
                                        <svg className="mx-auto h-10 w-10 text-zinc-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                                        </svg>
                                        <p className="text-zinc-500">{hasActiveFilters ? 'No results match your filters.' : 'No search submissions yet.'}</p>
                                        <p className="text-zinc-600 text-xs mt-1">{hasActiveFilters ? 'Try adjusting or clearing the filters.' : 'Completed searches will appear here.'}</p>
                                    </td>
                                </tr>
                            )}

                            {items.map(row => (
                                <tr key={row.id} className="hover:bg-zinc-800/50 transition-colors">
                                    <td className="px-4 py-3 text-zinc-300 whitespace-nowrap">{new Date(row.createdAt).toLocaleString()}</td>
                                    <td className="px-4 py-3 text-zinc-300">{row.client}</td>
                                    <td className="px-4 py-3 text-zinc-400">{row.iocTypes || '-'}</td>
                                    <td className="px-4 py-3">
                                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                                            row.hit === 'hit'
                                                ? 'bg-red-900/50 text-red-300 border border-red-700'
                                                : row.hit === 'error'
                                                    ? 'bg-amber-900/50 text-amber-300 border border-amber-700'
                                                    : 'bg-green-900/50 text-green-300 border border-green-700'
                                        }`}>
                                            {row.hit || 'no hit'}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3">
                                        <button
                                            onClick={() => downloadCsvForRow(row.id)}
                                            disabled={downloadingId === row.id}
                                            className="px-3 py-1.5 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 transition text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50 inline-flex items-center gap-1.5"
                                            aria-label={`Download CSV for submission ${row.id}`}
                                        >
                                            {downloadingId === row.id && (
                                                <svg className="animate-spin h-3.5 w-3.5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                                </svg>
                                            )}
                                            {downloadingId === row.id ? 'Downloading...' : 'Download CSV'}
                                        </button>
                                    </td>
                                </tr>
                            ))}

                            {loading && (
                                <tr>
                                    <td colSpan={5} className="px-4 py-6 text-center">
                                        <div className="flex items-center justify-center gap-2 text-zinc-400">
                                            <svg className="animate-spin h-5 w-5 text-indigo-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                            </svg>
                                            <span>Loading...</span>
                                        </div>
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
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
                        Showing {items.length} submission{items.length !== 1 ? 's' : ''}
                        {hasMore ? ' (more available)' : ''}
                    </p>
                )}
            </div>

            <Footer />
        </div>
    );
}
