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
            ? 'border-signal-rust/40 text-signal-rust bg-signal-rust/10'
            : hit === 'error'
                ? 'border-signal-warning/40 text-signal-warning bg-signal-warning/10'
                : 'border-signal-jade/40 text-signal-jade bg-signal-jade/10';
    const hitLabel = (hit) =>
        hit === 'hit' ? 'Hit' : hit === 'error' ? 'Error' : 'No Hit';

    const hasActiveFilters = filterClient || filterType || filterHit || filterDateFrom || filterDateTo;

    return (
        <div className="flex flex-col min-h-screen bg-ink-950 text-ink-50 grain">
            {/* Editorial header band — matches UploadPage */}
            <header className="border-b border-hairline-strong vignette-deep">
                <div className="max-w-7xl mx-auto px-6 pt-8 pb-6 flex flex-col sm:flex-row justify-between items-start sm:items-end gap-6">
                    <div className="flex items-start gap-3">
                        <LeopardLogoCompact size={36} showText={false} />
                        <div>
                            <span className="eyebrow-amber">The Leopard · Field Console</span>
                            <h1 className="mt-2 font-serif italic text-5xl leading-none tracking-tight wordmark-gradient"
                                style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                                Repo
                            </h1>
                            <p className="mt-2 font-mono text-micro text-ink-500 tracking-wider-2">
                                SEARCH HISTORY · HUNTS BY CLIENT
                            </p>
                        </div>
                    </div>
                    <nav className="flex items-center gap-2 flex-wrap" aria-label="Main navigation">
                        <button onClick={() => navigate('/')} className="btn-amber py-2">
                            Hunt
                        </button>
                        <button onClick={() => navigate('/admin')} className="btn-ghost py-2">
                            Admin
                        </button>
                    </nav>
                </div>
            </header>

            <div className="flex-1 max-w-7xl mx-auto p-6 w-full">

                {/* Disclaimer */}
                <div className="mb-6 p-3 border-l-2 border-signal-amber bg-signal-amber/8 border-y border-r border-y-hairline border-r-hairline">
                    <p className="font-mono text-micro tracking-eyebrow text-signal-amber flex items-center gap-2">
                        <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        NOTE · CSV EXPORT SUBSET
                    </p>
                    <p className="text-ink-300 text-xs mt-1.5 leading-relaxed">
                        CSV exports contain a limited subset of results intended as a quick reference. Review the full results directly in your SIEM for comprehensive data.
                    </p>
                </div>

                {/* Filters */}
                <section className="mb-6">
                    <span className="eyebrow">Section · Filters</span>
                    <div className="mt-3 card-editorial p-5">
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 items-end">
                            <div>
                                <label htmlFor="filter-client" className="font-mono text-xs uppercase tracking-eyebrow text-ink-400 block mb-2">Client</label>
                                <select
                                    id="filter-client"
                                    value={filterClient}
                                    onChange={e => setFilterClient(e.target.value)}
                                    className="field-boxed"
                                >
                                    <option value="">All Clients</option>
                                    {filterOptions.clients.map(c => <option key={c} value={c}>{c}</option>)}
                                </select>
                            </div>
                            <div>
                                <label htmlFor="filter-type" className="font-mono text-xs uppercase tracking-eyebrow text-ink-400 block mb-2">IOC Type</label>
                                <select
                                    id="filter-type"
                                    value={filterType}
                                    onChange={e => setFilterType(e.target.value)}
                                    className="field-boxed"
                                >
                                    <option value="">All Types</option>
                                    {filterOptions.filterTypes.map(t => <option key={t} value={t}>{t}</option>)}
                                </select>
                            </div>
                            <div>
                                <label htmlFor="filter-hit" className="font-mono text-xs uppercase tracking-eyebrow text-ink-400 block mb-2">Status</label>
                                <select
                                    id="filter-hit"
                                    value={filterHit}
                                    onChange={e => setFilterHit(e.target.value)}
                                    className="field-boxed"
                                >
                                    <option value="">All</option>
                                    <option value="hit">Hit</option>
                                    <option value="no hit">No Hit</option>
                                    <option value="error">Error</option>
                                </select>
                            </div>
                            <div>
                                <label htmlFor="filter-from" className="font-mono text-xs uppercase tracking-eyebrow text-ink-400 block mb-2">From</label>
                                <input
                                    id="filter-from"
                                    type="date"
                                    value={filterDateFrom}
                                    onChange={e => setFilterDateFrom(e.target.value)}
                                    className="field-boxed"
                                />
                            </div>
                            <div>
                                <label htmlFor="filter-to" className="font-mono text-xs uppercase tracking-eyebrow text-ink-400 block mb-2">To</label>
                                <input
                                    id="filter-to"
                                    type="date"
                                    value={filterDateTo}
                                    onChange={e => setFilterDateTo(e.target.value)}
                                    className="field-boxed"
                                />
                            </div>
                            <div className="flex gap-2">
                                <button
                                    onClick={applyFilters}
                                    disabled={loading}
                                    className="btn-amber py-2"
                                >
                                    Apply
                                </button>
                                {hasActiveFilters && (
                                    <button
                                        onClick={handleClear}
                                        disabled={loading}
                                        className="btn-ghost py-2"
                                    >
                                        Clear
                                    </button>
                                )}
                            </div>
                        </div>
                    </div>
                </section>

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
                <section>
                    <span className="eyebrow">Section · Hunts</span>

                    {items.length === 0 && !loading && (
                        <div className="mt-3 card-editorial px-4 py-12 text-center">
                            <svg className="mx-auto h-10 w-10 text-ink-600 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                            </svg>
                            <p className="text-ink-300">{hasActiveFilters ? 'No results match your filters.' : 'No search submissions yet.'}</p>
                            <p className="text-ink-500 text-xs mt-1 font-mono uppercase tracking-eyebrow">{hasActiveFilters ? 'TRY ADJUSTING OR CLEARING THE FILTERS' : 'COMPLETED SEARCHES WILL APPEAR HERE'}</p>
                        </div>
                    )}

                    <div className="mt-3 space-y-5">
                        {items.map(hunt => (
                            <article key={hunt.huntId} className="card-editorial overflow-hidden animate-fade-up">
                                {/* Hunt header */}
                                <header className="px-5 py-4 border-b border-hairline bg-ink-900/40">
                                    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                                        <div className="min-w-0">
                                            <span className="eyebrow-amber">Hunt</span>
                                            <h2 className="mt-1 font-serif text-xl text-ink-50 leading-tight break-all" style={{ fontVariationSettings: '"opsz" 60' }}>
                                                {hunt.fileName || '(no file name)'}
                                            </h2>
                                            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-micro uppercase tracking-eyebrow text-ink-500">
                                                <span>{new Date(hunt.createdAt).toLocaleString()}</span>
                                                <span>{hunt.clients.length} client{hunt.clients.length !== 1 ? 's' : ''}</span>
                                                {hunt.minutesBack != null && (
                                                    <span>window · {hunt.minutesBack} min</span>
                                                )}
                                            </div>
                                            <div className="mt-1 font-mono text-[0.65rem] text-ink-600 truncate" title={hunt.huntId}>
                                                id · {hunt.huntId}
                                            </div>
                                        </div>
                                    </div>
                                </header>

                                {/* Per-client sections */}
                                <div className="divide-y divide-hairline">
                                    {hunt.clients.map(c => (
                                        <div key={c.client} className="px-5 py-4">
                                            <div className="mb-3 flex items-baseline gap-3 flex-wrap">
                                                <h3 className="font-serif text-lg text-ink-100 leading-none" style={{ fontVariationSettings: '"opsz" 60' }}>
                                                    {c.client}
                                                </h3>
                                                <span className="font-mono text-micro uppercase tracking-eyebrow text-ink-500">
                                                    {c.siemType || 'logrhythm'}
                                                </span>
                                            </div>
                                            <div className="overflow-x-auto">
                                                <table className="min-w-full text-sm">
                                                    <thead>
                                                        <tr className="border-b border-hairline">
                                                            <th scope="col" className="text-left py-2 pr-4 font-mono text-micro uppercase tracking-eyebrow text-ink-400">IOC Type</th>
                                                            <th scope="col" className="text-left py-2 pr-4 font-mono text-micro uppercase tracking-eyebrow text-ink-400">IOCs</th>
                                                            <th scope="col" className="text-left py-2 pr-4 font-mono text-micro uppercase tracking-eyebrow text-ink-400">Status</th>
                                                            <th scope="col" className="text-left py-2 pr-4 font-mono text-micro uppercase tracking-eyebrow text-ink-400">Results</th>
                                                            <th scope="col" className="text-right py-2 pl-4 font-mono text-micro uppercase tracking-eyebrow text-ink-400">Actions</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {c.filters.map(f => (
                                                            <tr key={f.resultId} className="border-b border-hairline last:border-b-0">
                                                                <td className="py-2.5 pr-4 text-ink-100 whitespace-nowrap">{f.filterType || '-'}</td>
                                                                <td className="py-2.5 pr-4 text-ink-300 tabular-nums">{f.iocCount}</td>
                                                                <td className="py-2.5 pr-4">
                                                                    <span
                                                                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 font-mono uppercase text-micro tracking-wider-2 border ${hitChipClass(f.hit)}`}
                                                                        title={f.hit === 'error' && f.errorMessage ? f.errorMessage : undefined}
                                                                    >
                                                                        {hitLabel(f.hit)}
                                                                    </span>
                                                                </td>
                                                                <td className="py-2.5 pr-4 text-ink-100 tabular-nums">{f.resultCount}</td>
                                                                <td className="py-2.5 pl-4 text-right whitespace-nowrap">
                                                                    <div className="inline-flex items-center gap-2">
                                                                        <button
                                                                            onClick={() => rerunFilter(f.resultId)}
                                                                            disabled={rerunningId !== null}
                                                                            className="btn-ghost py-1.5 px-3 text-xs"
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
                                                                            className="btn-amber py-1.5 px-3 text-xs"
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
                            </article>
                        ))}

                        {loading && (
                            <div className="card-editorial px-4 py-6 text-center">
                                <div className="flex items-center justify-center gap-2 text-ink-300">
                                    <svg className="animate-spin h-5 w-5 text-signal-amber" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                    </svg>
                                    <span className="font-mono text-micro uppercase tracking-eyebrow">Loading…</span>
                                </div>
                            </div>
                        )}
                    </div>
                </section>

                {/* Pagination */}
                <div className="mt-6 flex justify-center gap-4">
                    {hasMore && !loading && (
                        <button onClick={() => loadPage(offset)} className="btn-ghost py-2">
                            Load More
                        </button>
                    )}
                </div>

                {/* Summary */}
                {items.length > 0 && (
                    <p className="text-center text-ink-500 text-xs mt-3 font-mono uppercase tracking-eyebrow">
                        Showing {items.length} hunt{items.length !== 1 ? 's' : ''}
                        {hasMore ? ' · more available' : ''}
                    </p>
                )}
            </div>

            <Footer />
        </div>
    );
}
