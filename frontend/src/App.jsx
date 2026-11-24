import React, { useEffect, useRef, useState } from "react";
import {
  demoScan,
  scanGithubWithJob,
  scanZipWithJob,
  checkBackendHealth,
  exportReportJson,
  exportReportMarkdown,
} from "./api.js";
import Icon from "./components/Icon.jsx";
import ScanForm from "./components/ScanForm.jsx";
import JobProgress from "./components/JobProgress.jsx";
import VulnerabilityTable from "./components/VulnerabilityTable.jsx";
import FindingDetails from "./components/FindingDetails.jsx";
import ScoringMethodView from "./components/ScoringMethodView.jsx";

export default function App() {
  const [report, setReport] = useState(null);
  const [busy, setBusy] = useState(false);
  const [jobState, setJobState] = useState(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const [view, setView] = useState("overview"); // overview | method
  const [backendHealth, setBackendHealth] = useState({ online: false, checking: true });
  const [exportMenuOpen, setExportMenuOpen] = useState(false);

  const abortControllerRef = useRef(null);

  // Check backend health periodically
  useEffect(() => {
    async function checkHealth() {
      const health = await checkBackendHealth();
      setBackendHealth({ ...health, checking: false });
    }
    checkHealth();
    const interval = setInterval(checkHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  // Initial load: demo scan fixture
  useEffect(() => {
    runScan(() => demoScan());
  }, []);

  async function runScan(scanFn) {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setBusy(true);
    setError("");
    setJobState({ status: "running", stage: "Initializing pipeline...", progress: 0.05 });

    try {
      const result = await scanFn(
        (progressUpdate) => {
          setJobState(progressUpdate);
        },
        controller.signal
      );
      setReport(result);
      setSelected(null);
      setJobState(null);
    } catch (e) {
      if (e.message !== "Scan was cancelled.") {
        setError(e.message || "An unexpected error occurred during scan execution.");
      }
      setJobState(null);
    } finally {
      setBusy(false);
      abortControllerRef.current = null;
    }
  }

  function handleCancelScan() {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      setBusy(false);
      setJobState(null);
    }
  }

  const summary = report?.summary;
  const tierCounts = report?.tier_counts || {};

  return (
    <div className="shell">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setView("overview");
          }}
        >
          <span className="brand-mark">
            <Icon name="shield" size={24} />
          </span>
          <span>
            Context<span className="brand-light">Vuln</span>
            <small>SECURITY IN CONTEXT</small>
          </span>
        </a>

        {/* Backend Connectivity Status Pill */}
        <div className={`workspace ${backendHealth.online ? "workspace-online" : "workspace-offline"}`}>
          <span className="workspace-icon">
            <Icon name="server" size={15} />
          </span>
          <div>
            <span>
              {backendHealth.checking
                ? "Checking Backend..."
                : backendHealth.online
                  ? "Backend Connected"
                  : "Backend Offline"}
            </span>
            <small>
              {backendHealth.online
                ? `${backendHealth.intelMode.toUpperCase()} Intel ${backendHealth.llmConfigured ? " " : ""}`
                : "Using offline demo fixtures"}
            </small>
          </div>
          <span className={`live-dot ${backendHealth.online ? "dot-online" : "dot-offline"}`} />
        </div>

        <div className="nav-label">NAVIGATION</div>
        <nav>
          <button
            type="button"
            className={view === "overview" ? "nav-active" : ""}
            onClick={() => setView("overview")}
          >
            <Icon name="grid" size={17} />
            <span>Triage & Overview</span>
            <span className="nav-badge">{report?.findings?.length || 0}</span>
          </button>
          <button
            type="button"
            className={view === "method" ? "nav-active" : ""}
            onClick={() => setView("method")}
          >
            <Icon name="graph" size={17} />
            <span>Method & Scoring</span>
          </button>
        </nav>

        {/* Sidebar Info Card */}
        <div className="sidebar-note">
          <span className="eyebrow">MULTI-AGENT SAST</span>
          <h3>
            Evidence over
            <br />
            raw urgency.
          </h3>
          <p>
            AST call-graph reachability + CISA KEV exploitation + FIRST EPSS probabilities eliminate alert fatigue.
          </p>
          <div className="agent-dots">
            <span title="Abstract Syntax Tree reachability">AST AGENT</span>
            <span title="Threat intelligence correlation">INTEL AGENT</span>
            <span title="Multi-attribute utility prioritization">UTILITY AGENT</span>
          </div>
        </div>

        <div className="sidebar-bottom">
          <Icon name="shield" size={16} />
          <span>
            Static Analysis Only
            <small>Code parsed in-memory, never executed</small>
          </span>
        </div>
      </aside>

      {/* Main Content Area */}
      <main>
        {/* Topbar */}
        <header className="topbar">
          <div className="breadcrumbs">
            <span>ContextVuln</span>
            <b>/</b>
            <strong>
              {view === "overview" ? "Vulnerability Triage Dashboard" : "Scoring Formula & Architecture"}
            </strong>
          </div>
          <div className="topbar-actions">
            <span className={`service-status-chip ${backendHealth.online ? "chip-online" : "chip-offline"}`}>
              <i />
              {backendHealth.online
                ? `127.0.0.1:8000 (${backendHealth.intelMode})`
                : "Offline Fixture Mode"}
            </span>
          </div>
        </header>

        <div className="content">
          {/* Page Title & Action Bar */}
          <div className="page-title">
            <div>
              <span className="eyebrow">DEPENDENCY RISK PRIORITIZATION</span>
              <h1>
                {view === "overview"
                  ? "Every alert needs code context."
                  : "Transparent prioritization mathematics."}
              </h1>
              <p>
                Evaluate call paths, verify real exploitability, and eliminate dead-code noise with deterministic utility scores.
              </p>
            </div>

            {/* Export Menu */}
            <div className="export-btn-group">
              <button
                type="button"
                className="secondary"
                disabled={!report || busy}
                onClick={() => setExportMenuOpen(!exportMenuOpen)}
              >
                <Icon name="download" size={16} />
                Export Report
                <Icon name="chevronDown" size={12} />
              </button>
              {exportMenuOpen && (
                <div className="export-dropdown" onMouseLeave={() => setExportMenuOpen(false)}>
                  <button
                    type="button"
                    onClick={() => {
                      exportReportMarkdown(report);
                      setExportMenuOpen(false);
                    }}
                  >
                    <Icon name="code" size={14} />
                    <span>Executive Markdown (.md)</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      exportReportJson(report);
                      setExportMenuOpen(false);
                    }}
                  >
                    <Icon name="download" size={14} />
                    <span>Raw JSON Data (.json)</span>
                  </button>
                </div>
              )}
            </div>
          </div>

          {view === "overview" ? (
            <>
              {/* Scan Initiator Panel */}
              <ScanForm
                busy={busy}
                onPath={(data) => runScan((onProgress, signal) => scanGithubWithJob(data, onProgress, signal))}
                onZip={(file, crit) => runScan((onProgress, signal) => scanZipWithJob(file, crit, onProgress, signal))}
              />

              {/* Progress & Error Alerts */}
              <div aria-live="polite">
                {busy && jobState && (
                  <JobProgress jobState={jobState} onCancel={handleCancelScan} />
                )}

                {error && (
                  <div className="error-banner" role="alert">
                    <Icon name="alert" size={20} />
                    <div className="error-body">
                      <strong>Scan Failed:</strong>
                      <p>{error}</p>
                      <small>
                        Ensure the backend is running at <code>http://127.0.0.1:8000</code> or run the offline demo below.
                      </small>
                    </div>
                  </div>
                )}
              </div>

              {/* Scan Metadata Header */}
              <div className="report-heading">
                <div className="report-label">
                  <Icon name="clock" size={15} />
                  <span>
                    {report
                      ? `${report.project} · Scanned ${new Date(report.created_at).toLocaleString()}`
                      : "No scan loaded"}
                  </span>
                  {report?.duration_s > 0 && (
                    <span className="duration-tag">({report.duration_s.toFixed(2)}s)</span>
                  )}
                </div>
                <button
                  type="button"
                  className="text-button"
                  disabled={busy}
                  onClick={() => runScan(() => demoScan())}
                >
                  <Icon name="refresh" size={14} />
                  Load Offline Demo Fixture
                </button>
              </div>

              {/* Demo Mode Notice */}
              {report?.mode === "demo" && (
                <div className="demo-banner">
                  <Icon name="shield" size={16} />
                  <div>
                    <strong>DEMO DATA:</strong> Synthetic security advisories and multi-criteria call graph
                    demonstrating the complete Schema v2 pipeline. Start a repository scan for live analysis.
                  </div>
                </div>
              )}

              {/* Summary Stats Cards */}
              {summary && (
                <>
                  <div className="stats">
                    <article className="stat-card">
                      <span>TOTAL ALERTS</span>
                      <strong>
                        {summary.total}
                        <Icon name="shield" size={24} />
                      </strong>
                      <p>Across {report.dependencies.length} pinned dependencies</p>
                    </article>

                    <article className="stat-card stat-critical">
                      <span>CRITICAL ACTION</span>
                      <strong>
                        {tierCounts.CRITICAL_ACTION || summary.high || 0}
                        <span className="stat-indicator alert-badge">!</span>
                      </strong>
                      <p>Reachable or CISA KEV active exploits</p>
                    </article>

                    <article className="stat-card stat-review">
                      <span>NEEDS REVIEW</span>
                      <strong>
                        {tierCounts.NEEDS_REVIEW || summary.unknown || 0}
                        <Icon name="help" size={22} />
                      </strong>
                      <p>Inconclusive (never auto-suppressed)</p>
                    </article>

                    <article className="stat-card stat-suppressed">
                      <span>SUPPRESSED NOISE</span>
                      <strong>
                        {tierCounts.SUPPRESSED_NOISE || summary.suppressed || 0}
                        <Icon name="check" size={24} />
                      </strong>
                      <p>Confirmed dead code eliminated</p>
                    </article>

                    <article className="stat-card stat-reduction">
                      <span>NOISE REDUCTION</span>
                      <strong>
                        {summary.noise_reduction_pct || Math.round((summary.alert_reduction_rate || 0) * 100)}
                        <small>%</small>
                        <Icon name="zap" size={24} />
                      </strong>
                      <p>Safe workload reduction</p>
                    </article>
                  </div>

                  {/* Coverage Strip */}
                  <div className="coverage-strip">
                    <span>
                      <i />
                      Pipeline Complete
                    </span>
                    <span>{report.files_analyzed} files parsed</span>
                    <span>{report.graph_nodes} call nodes</span>
                    <span>{report.graph_edges} edges</span>
                    <span>Intel: {report.intel_mode.toUpperCase()}</span>
                    <span>MAUT Scoring Engine v2</span>
                  </div>

                  {/* Vulnerability Findings Table */}
                  <VulnerabilityTable
                    findings={report.findings}
                    selected={selected}
                    onSelect={setSelected}
                  />

                  {/* Evidence & Remediation Drawer */}
                  <FindingDetails
                    finding={selected}
                    onClose={() => setSelected(null)}
                  />

                  {/* Coverage Warnings */}
                  {report.warnings && report.warnings.length > 0 && (
                    <details className="warnings-drawer">
                      <summary>
                        <Icon name="alert" size={14} />
                        Coverage Notes & Scope Limitations ({report.warnings.length})
                      </summary>
                      <ul className="plain-list">
                        {report.warnings.map((w, i) => (
                          <li key={i}>{w}</li>
                        ))}
                      </ul>
                    </details>
                  )}
                </>
              )}
            </>
          ) : (
            <ScoringMethodView />
          )}

          {/* Footer */}
          <footer>
            <div className="footer-brand">
              <Icon name="shield" size={15} />
              <span>ContextVuln</span>
            </div>
            <span>Evidence-Based Reachability Prioritization · Human-Reviewed Remediation</span>
            <a
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
            >
              Open API Swagger Docs ↗
            </a>
          </footer>
        </div>
      </main>
    </div>
  );
}
