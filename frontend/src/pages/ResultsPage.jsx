import React, { useEffect, useState, useContext } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';
import AuthContext from '../context/AuthContext';
import Footer from '../components/Footer';
import { LeopardLogoCompact } from '../components/Logo';
import ErrorAlert, { parseApiError } from '../components/ErrorAlert';

export default function ResultsPage() {
  const { submissionId } = useParams();
  const { token } = useContext(AuthContext);
  const navigate = useNavigate();

  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorInfo, setErrorInfo] = useState({ error: '', suggestion: '', category: '' });
  const PAGE_SIZE = 100;
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    async function fetchResults() {
      setLoading(true);
      setErrorInfo({ error: '', suggestion: '', category: '' });
      try {
        const API_URL = process.env.REACT_APP_API_URL || '/api';
        const res = await axios.get(`${API_URL}/results/${submissionId}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setResults(res.data);
      } catch (err) {
        const parsed = parseApiError(err);
        setErrorInfo({
          error: parsed.error || 'Failed to fetch results.',
          suggestion: parsed.suggestion || 'The submission may not exist or you may not have permission. Try going back and searching again.',
          category: parsed.category || 'server'
        });
      } finally {
        setLoading(false);
      }
    }
    fetchResults();
  }, [submissionId, token]);

  const downloadCSV = () => {
    const csv = [
      'IOC,Type,Hit,Details',
      ...results.map(r =>
        `"${(r.ioc || '').replace(/"/g, '""')}","${(r.iocType || '').replace(/"/g, '""')}",${r.hit ? 'Hit' : 'No Hit'},"${(r.details || '').replace(/"/g, '""')}"`
      )
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `results_submission_${submissionId}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col min-h-screen bg-ink-950 text-ink-50 grain">
      {/* Editorial header band — matches UploadPage/RepoPage */}
      <header className="border-b border-hairline-strong vignette-deep">
        <div className="max-w-7xl mx-auto px-6 pt-8 pb-6 flex flex-col sm:flex-row justify-between items-start sm:items-end gap-6">
          <div className="flex items-start gap-3">
            <LeopardLogoCompact size={36} showText={false} />
            <div>
              <span className="eyebrow-amber">The Leopard · Field Console</span>
              <h1 className="mt-2 font-serif italic text-5xl leading-none tracking-tight wordmark-gradient"
                  style={{ fontVariationSettings: '"opsz" 144, "wght" 400' }}>
                Results
              </h1>
              <p className="mt-2 font-mono text-micro text-ink-500 tracking-wider-2">
                SUBMISSION · #{submissionId}
              </p>
            </div>
          </div>
          <nav className="flex items-center gap-2 flex-wrap" aria-label="Main navigation">
            <button onClick={() => navigate('/')} className="btn-amber py-2">
              Hunt
            </button>
            <button onClick={() => navigate('/repo')} className="btn-ghost py-2">
              Repo
            </button>
          </nav>
        </div>
      </header>

      <div className="flex-1 max-w-7xl mx-auto p-6 w-full">
        {/* Error */}
        <ErrorAlert
          error={errorInfo.error}
          suggestion={errorInfo.suggestion}
          category={errorInfo.category}
          onDismiss={() => setErrorInfo({ error: '', suggestion: '', category: '' })}
          className="mb-6"
        />

        {/* Loading */}
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 text-ink-300">
            <svg className="animate-spin h-8 w-8 text-signal-amber mb-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <p className="font-mono text-micro uppercase tracking-eyebrow">Loading results…</p>
          </div>
        ) : results.length === 0 ? (
          /* Empty State */
          <div className="card-editorial text-center py-16">
            <svg className="mx-auto h-12 w-12 text-ink-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-ink-200 text-lg font-serif" style={{ fontVariationSettings: '"opsz" 60' }}>No results found for this submission.</p>
            <p className="text-ink-500 text-xs mt-2 font-mono uppercase tracking-eyebrow">THE SEARCH MAY NOT HAVE RETURNED ANY MATCHES</p>
          </div>
        ) : (
          <section>
            <span className="eyebrow">Section · Matches</span>

            {/* Action Bar */}
            <div className="mt-3 flex items-center justify-between mb-4">
              <p className="font-mono text-micro uppercase tracking-eyebrow text-ink-400">
                {results.length} result{results.length !== 1 ? 's' : ''} found
              </p>
              <button
                onClick={downloadCSV}
                className="btn-amber py-2"
                aria-label="Download results as CSV"
              >
                Download CSV
              </button>
            </div>

            {/* Results Table - Paginated */}
            <div className="overflow-x-auto card-editorial">
              <table className="min-w-full text-sm" aria-label="IOC search results">
                <thead>
                  <tr className="border-b border-hairline">
                    <th scope="col" className="text-left px-4 py-3 font-mono text-micro uppercase tracking-eyebrow text-ink-400">IOC</th>
                    <th scope="col" className="text-left px-4 py-3 font-mono text-micro uppercase tracking-eyebrow text-ink-400">Type</th>
                    <th scope="col" className="text-left px-4 py-3 font-mono text-micro uppercase tracking-eyebrow text-ink-400">Hit</th>
                    <th scope="col" className="text-left px-4 py-3 font-mono text-micro uppercase tracking-eyebrow text-ink-400">Details</th>
                  </tr>
                </thead>
                <tbody>
                  {results.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE).map((r) => (
                    <tr key={r.id} className={`border-b border-hairline last:border-b-0 transition-colors ${r.hit ? 'bg-signal-rust/5' : ''}`}>
                      <td className="px-4 py-3 font-mono text-sm text-ink-100 break-all">{r.ioc}</td>
                      <td className="px-4 py-3">
                        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 font-mono uppercase text-micro tracking-wider-2 border border-signal-amber/40 text-signal-amber bg-signal-amber/10">
                          {r.iocType}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 font-mono uppercase text-micro tracking-wider-2 border ${
                          r.hit
                            ? 'border-signal-rust/40 text-signal-rust bg-signal-rust/10'
                            : 'border-signal-jade/40 text-signal-jade bg-signal-jade/10'
                        }`}>
                          {r.hit ? 'Hit' : 'No Hit'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-ink-300 max-w-md truncate">{r.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {results.length > PAGE_SIZE && (
              <div className="flex items-center justify-center gap-4 mt-6">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="btn-ghost py-2"
                >
                  Previous
                </button>
                <span className="font-mono text-micro uppercase tracking-eyebrow text-ink-400">
                  Page {currentPage} of {Math.ceil(results.length / PAGE_SIZE)}
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(Math.ceil(results.length / PAGE_SIZE), p + 1))}
                  disabled={currentPage >= Math.ceil(results.length / PAGE_SIZE)}
                  className="btn-ghost py-2"
                >
                  Next
                </button>
              </div>
            )}
          </section>
        )}
      </div>

      <Footer />
    </div>
  );
}
