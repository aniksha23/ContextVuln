import React, { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';

import {
  checkBackendHealth,
  scanGithubRepository,
  scanUploadedArchive,
} from './api';

import ScanForm from './components/ScanForm';
import MetricsSummary from './components/MetricsSummary';
import VulnTable from './components/VulnTable';

export default function App() {
  const [backendOnline, setBackendOnline] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Check backend connection when the application loads
  useEffect(() => {
    checkBackendHealth().then(setBackendOnline);
  }, []);

  // Handle GitHub repository scan or uploaded ZIP scan
  const handleScan = async ({ mode, repoUrl, zipFile, criticality }) => {
    setLoading(true);
    setError('');
    setReport(null);

    try {
      const data =
        mode === 'github'
          ? await scanGithubRepository(repoUrl, criticality)
          : await scanUploadedArchive(zipFile, criticality);

      setReport(data);
      setBackendOnline(true);
    } catch (err) {
      const msg =
        err.response?.data?.detail ||
        'Could not reach FastAPI backend on http://localhost:8000. Ensure uvicorn is running.';

      setError(msg);
      setBackendOnline(false);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#f1f5f9',
        fontFamily: 'system-ui, -apple-system, sans-serif',
      }}
    >
      {/* Top Navbar */}
      <header
        style={{
          background: '#0f172a',
          color: '#ffffff',
          padding: '1rem 2rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
        }}
      >
        {/* Brand */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.65rem',
          }}
        >
          <Shield size={24} color="#38bdf8" />

          <div>
            <div
              style={{
                fontWeight: 700,
                fontSize: '1.1rem',
                letterSpacing: '-0.01em',
              }}
            >
              ContextVuln
            </div>

            <div
              style={{
                fontSize: '0.75rem',
                color: '#94a3b8',
              }}
            >
              AST Reachability & Multi-Attribute Utility Prioritizer
            </div>
          </div>
        </div>

        {/* Backend Status */}
        <div
          style={{
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45rem',
          }}
        >
          <span
            style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background:
                backendOnline === null
                  ? '#eab308'
                  : backendOnline
                    ? '#22c55e'
                    : '#ef4444',
            }}
          />

          <span style={{ color: '#cbd5e1' }}>
            {backendOnline === null
              ? 'Checking API...'
              : backendOnline
                ? 'FastAPI Connected'
                : 'Backend Offline'}
          </span>
        </div>
      </header>

      {/* Main Content */}
      <main
        style={{
          maxWidth: '1180px',
          margin: '0 auto',
          padding: '2rem 1.5rem',
        }}
      >
        <ScanForm onScan={handleScan} loading={loading} />

        {/* Error Message */}
        {error && (
          <div
            style={{
              background: '#fef2f2',
              border: '1px solid #fecaca',
              color: '#991b1b',
              padding: '0.9rem 1.1rem',
              borderRadius: '8px',
              marginBottom: '1.5rem',
              fontSize: '0.9rem',
            }}
          >
            {error}
          </div>
        )}

        {/* Scan Results */}
        {report && (
          <>
            <MetricsSummary report={report} />
            <VulnTable findings={report.findings} />
          </>
        )}
      </main>
    </div>
  );
}
