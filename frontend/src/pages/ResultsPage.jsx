import React, { useEffect, useState, useContext } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';
import AuthContext from '../context/AuthContext';
import Footer from '../components/Footer';
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
    <div className="flex flex-col min-h-screen bg-zinc-950 text-zinc-100">
      <div className="flex-1 p-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
          <h2 className="text-2xl font-bold">IOC Search Results — Submission #{submissionId}</h2>
          <button
            onClick={() => navigate('/')}
            className="px-4 py-2 bg-zinc-700 text-white rounded-md hover:bg-zinc-600 transition focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            Back to Home
          </button>
        </div>

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
          <div className="flex flex-col items-center justify-center py-16 text-zinc-400">
            <svg className="animate-spin h-8 w-8 text-indigo-500 mb-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" aria-hidden="true">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            <p>Loading results...</p>
          </div>
        ) : results.length === 0 ? (
          /* Empty State */
          <div className="text-center py-16 bg-zinc-900 rounded-lg border border-zinc-700">
            <svg className="mx-auto h-12 w-12 text-zinc-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 9.75l4.5 4.5m0-4.5l-4.5 4.5M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-zinc-400 text-lg">No results found for this submission.</p>
            <p className="text-zinc-500 text-sm mt-1">The search may not have returned any matches.</p>
          </div>
        ) : (
          <>
            {/* Action Bar */}
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm text-zinc-400">{results.length} result{results.length !== 1 ? 's' : ''} found</p>
              <button
                onClick={downloadCSV}
                className="px-5 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 focus:ring-offset-zinc-950"
                aria-label="Download results as CSV"
              >
                Download CSV
              </button>
            </div>

            {/* Results Table - Paginated */}
            <div className="overflow-x-auto bg-zinc-900 border border-zinc-700 rounded-lg">
              <table className="min-w-full text-sm" aria-label="IOC search results">
                <thead className="bg-zinc-800/50 text-zinc-300">
                  <tr>
                    <th scope="col" className="text-left px-4 py-3 font-medium">IOC</th>
                    <th scope="col" className="text-left px-4 py-3 font-medium">Type</th>
                    <th scope="col" className="text-left px-4 py-3 font-medium">Hit</th>
                    <th scope="col" className="text-left px-4 py-3 font-medium">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {results.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE).map((r) => (
                    <tr key={r.id} className={`transition-colors ${r.hit ? 'bg-red-900/10 hover:bg-red-900/20' : 'hover:bg-zinc-800/50'}`}>
                      <td className="px-4 py-3 font-mono text-sm text-zinc-200 break-all">{r.ioc}</td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-1 rounded text-xs bg-indigo-900/50 text-indigo-300 border border-indigo-700">{r.iocType}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          r.hit
                            ? 'bg-red-900/50 text-red-300 border border-red-700'
                            : 'bg-green-900/50 text-green-300 border border-green-700'
                        }`}>
                          {r.hit ? 'Hit' : 'No Hit'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-zinc-400 max-w-md truncate">{r.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            {results.length > PAGE_SIZE && (
              <div className="flex items-center justify-center gap-4 mt-4">
                <button
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  className="px-4 py-2 bg-zinc-700 text-white rounded-md hover:bg-zinc-600 transition disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  Previous
                </button>
                <span className="text-sm text-zinc-400">
                  Page {currentPage} of {Math.ceil(results.length / PAGE_SIZE)}
                </span>
                <button
                  onClick={() => setCurrentPage(p => Math.min(Math.ceil(results.length / PAGE_SIZE), p + 1))}
                  disabled={currentPage >= Math.ceil(results.length / PAGE_SIZE)}
                  className="px-4 py-2 bg-zinc-700 text-white rounded-md hover:bg-zinc-600 transition disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>

      <Footer />
    </div>
  );
}
