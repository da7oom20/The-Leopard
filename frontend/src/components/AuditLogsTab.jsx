import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ErrorAlert, { parseApiError } from './ErrorAlert';

const CATEGORIES = [
  { value: '', label: 'All Categories' },
  { value: 'auth', label: 'Authentication' },
  { value: 'user', label: 'User Management' },
  { value: 'siem', label: 'SIEM' },
  { value: 'ti', label: 'Threat Intelligence' },
  { value: 'security', label: 'Security' },
  { value: 'settings', label: 'Settings' },
];

export default function AuditLogsTab({ token, API_URL }) {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [limit] = useState(20);
  const [category, setCategory] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '' });

  const fetchLogs = async (p = page, cat = category) => {
    setLoading(true);
    setErrorInfo({ error: '', suggestion: '' });
    try {
      const params = new URLSearchParams({ page: p, limit });
      if (cat) params.set('category', cat);
      const res = await axios.get(`${API_URL}/admin/audit-logs?${params}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setItems(res.data.items || []);
      setTotal(res.data.total || 0);
      setPage(res.data.page || 1);
      setPages(res.data.pages || 1);
    } catch (err) {
      const parsed = parseApiError(err);
      setErrorInfo({ error: parsed.error || 'Failed to load audit logs.', suggestion: parsed.suggestion || '' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs(1, category);
  }, [token, API_URL, category]);

  const goToPage = (p) => {
    if (p < 1 || p > pages) return;
    setPage(p);
    fetchLogs(p, category);
  };

  const formatDate = (d) => {
    try { return new Date(d).toLocaleString(); }
    catch { return d; }
  };

  const actionLabel = (action) => {
    const labels = {
      'auth.login': 'Login',
      'user.create': 'Create User',
      'user.update': 'Update User',
      'user.delete': 'Delete User',
      'user.password_change': 'Password Change',
      'mfa.reset': 'MFA Reset',
      'siem.create': 'Add SIEM',
      'siem.delete': 'Delete SIEM',
      'ti.create': 'Add TI Source',
      'ti.delete': 'Delete TI Source',
      'settings.update': 'Update Setting',
    };
    return labels[action] || action;
  };

  const categoryColor = (cat) => {
    const colors = {
      auth: 'bg-blue-900/50 text-blue-300 border-blue-700',
      user: 'bg-purple-900/50 text-purple-300 border-purple-700',
      siem: 'bg-green-900/50 text-green-300 border-green-700',
      ti: 'bg-amber-900/50 text-amber-300 border-amber-700',
      security: 'bg-red-900/50 text-red-300 border-red-700',
      settings: 'bg-zinc-700/50 text-zinc-300 border-zinc-600',
    };
    return colors[cat] || 'bg-zinc-700/50 text-zinc-300 border-zinc-600';
  };

  // Build page numbers to show
  const pageNumbers = [];
  const maxVisible = 5;
  let startPage = Math.max(1, page - Math.floor(maxVisible / 2));
  let endPage = Math.min(pages, startPage + maxVisible - 1);
  if (endPage - startPage + 1 < maxVisible) startPage = Math.max(1, endPage - maxVisible + 1);
  for (let i = startPage; i <= endPage; i++) pageNumbers.push(i);

  return (
    <div>
      {/* Filters */}
      <div className="flex flex-col sm:flex-row gap-4 mb-4">
        <div>
          <label htmlFor="audit-category-filter" className="block text-sm font-medium text-zinc-400 mb-1">Filter by Category</label>
          <select
            id="audit-category-filter"
            value={category}
            onChange={(e) => { setCategory(e.target.value); setPage(1); }}
            className="p-2 bg-zinc-800 border border-zinc-700 rounded-md text-zinc-100 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {CATEGORIES.map(c => (
              <option key={c.value} value={c.value}>{c.label}</option>
            ))}
          </select>
        </div>
        <div className="flex items-end">
          <span className="text-sm text-zinc-500">{total} total entries</span>
        </div>
      </div>

      <ErrorAlert
        error={errorInfo.error}
        suggestion={errorInfo.suggestion}
        onDismiss={() => setErrorInfo({ error: '', suggestion: '' })}
        className="mb-4"
      />

      {/* Table */}
      <div className="overflow-x-auto bg-zinc-900 border border-zinc-700 rounded-lg">
        <table className="min-w-full text-sm" aria-label="Audit logs table">
          <thead className="bg-zinc-800/50 text-zinc-300">
            <tr>
              <th scope="col" className="text-left px-4 py-3 font-medium">Timestamp</th>
              <th scope="col" className="text-left px-4 py-3 font-medium">Action</th>
              <th scope="col" className="text-left px-4 py-3 font-medium">Category</th>
              <th scope="col" className="text-left px-4 py-3 font-medium">User</th>
              <th scope="col" className="text-left px-4 py-3 font-medium">Target</th>
              <th scope="col" className="text-left px-4 py-3 font-medium">IP</th>
              <th scope="col" className="text-left px-4 py-3 font-medium">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {items.length === 0 && !loading && (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center">
                  <p className="text-zinc-500">No audit log entries found.</p>
                  {category && <p className="text-zinc-600 text-xs mt-1">Try clearing the category filter.</p>}
                </td>
              </tr>
            )}
            {items.map(item => (
              <tr key={item.id} className="hover:bg-zinc-800/50 transition-colors">
                <td className="px-4 py-3 text-zinc-400 whitespace-nowrap text-xs">{formatDate(item.createdAt)}</td>
                <td className="px-4 py-3 text-zinc-200 whitespace-nowrap">{actionLabel(item.action)}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium border ${categoryColor(item.category)}`}>
                    {item.category}
                  </span>
                </td>
                <td className="px-4 py-3 text-zinc-300 whitespace-nowrap">{item.actorUsername || `ID:${item.actorId}`}</td>
                <td className="px-4 py-3 text-zinc-400 whitespace-nowrap">
                  {item.targetType ? `${item.targetType} #${item.targetId}` : '-'}
                </td>
                <td className="px-4 py-3 text-zinc-500 whitespace-nowrap font-mono text-xs">{item.ip || '-'}</td>
                <td className="px-4 py-3 text-zinc-500 text-xs max-w-xs truncate">
                  {item.details ? (
                    <span title={JSON.stringify(item.details)}>
                      {Object.entries(item.details).map(([k, v]) => `${k}=${v}`).join(', ')}
                    </span>
                  ) : '-'}
                </td>
              </tr>
            ))}
            {loading && (
              <tr>
                <td colSpan={7} className="px-4 py-6 text-center">
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
      {pages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <p className="text-sm text-zinc-500">
            Page {page} of {pages}
          </p>
          <div className="flex items-center gap-1">
            <button
              onClick={() => goToPage(page - 1)}
              disabled={page <= 1 || loading}
              className="px-3 py-1.5 rounded text-sm bg-zinc-800 text-zinc-300 hover:bg-zinc-700 disabled:opacity-40 disabled:cursor-not-allowed transition"
            >
              Prev
            </button>
            {pageNumbers.map(p => (
              <button
                key={p}
                onClick={() => goToPage(p)}
                disabled={loading}
                className={`px-3 py-1.5 rounded text-sm transition ${
                  p === page
                    ? 'bg-indigo-600 text-white'
                    : 'bg-zinc-800 text-zinc-300 hover:bg-zinc-700'
                }`}
              >
                {p}
              </button>
            ))}
            <button
              onClick={() => goToPage(page + 1)}
              disabled={page >= pages || loading}
              className="px-3 py-1.5 rounded text-sm bg-zinc-800 text-zinc-300 hover:bg-zinc-700 disabled:opacity-40 disabled:cursor-not-allowed transition"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
