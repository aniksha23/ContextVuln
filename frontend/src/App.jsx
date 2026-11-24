import React, { useEffect, useState } from "react";
import { demoScan, scanPath, scanZip, exportReport } from "./api.js";
import Icon from "./components/Icon.jsx";
import ScanForm from "./components/ScanForm.jsx";
import VulnerabilityTable from "./components/VulnerabilityTable.jsx";
import FindingDetails from "./components/FindingDetails.jsx";

export default function App() {
  const [report, setReport] = useState(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [selected, setSelected] = useState(null),
    [view, setView] = useState("overview");
  async function run(operation) {
    setBusy(true);
    setError("");
    try {
      const result = await operation();
      setReport(result);
      setSelected(null);
    } catch (e) {
      setError(
        e.name === "TimeoutError"
          ? "Scan timed out. Please retry a smaller project."
          : e.message,
      );
    } finally {
      setBusy(false);
    }
  }
  useEffect(() => {
    run(demoScan);
  }, []);
  const summary = report?.summary;
  return (
    <div className="shell">
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
            <Icon name="shield" size={26} />
          </span>
          <span>
            Context<span className="brand-light">Vuln</span>
            <small>SECURITY IN CONTEXT</small>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-icon">C</span>
          <div>
            Research workspace<small>Local development</small>
          </div>
          <span className="live-dot" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {[
            ["overview", "grid", "Overview"],
            ["method", "graph", "Method & scoring"],
          ].map(([id, icon, label]) => (
            <button
              className={view === id ? "nav-active" : ""}
              key={id}
              onClick={() => setView(id)}
            >
              <Icon name={icon} />
              {label}
              {id === "overview" && <span>01</span>}
            </button>
          ))}
        </nav>
        <div className="sidebar-note">
          <span className="eyebrow">THREE AGENTS. ONE VIEW.</span>
          <h3>
            Less noise.
            <br />
            More signal.
          </h3>
          <p>Connect source evidence with the threats that matter.</p>
          <div className="agent-dots">
            <span>AST</span>
            <span>INTEL</span>
            <span>UTILITY</span>
          </div>
        </div>
        <div className="sidebar-bottom">
          <Icon name="shield" size={16} />
          <span>
            Source stays on your machine<small>LLM sharing is optional</small>
          </span>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div>
            <span>Workspace</span>
            <b>/</b>
            <strong>
              {view === "overview"
                ? "Vulnerability overview"
                : "Method & scoring"}
            </strong>
          </div>
          <span className="local-badge">
            <i />
            LOCAL ANALYSIS
          </span>
        </header>
        <div className="content">
          <div className="page-title">
            <div>
              <span className="eyebrow">
                APPLICATION SECURITY / DEPENDENCY TRIAGE
              </span>
              <h1>
                {view === "overview"
                  ? "Every alert needs context."
                  : "Evidence before urgency."}
              </h1>
              <p>
                Know what’s reachable. Understand the risk. Prioritize with
                evidence.
              </p>
            </div>
            <button
              className="secondary"
              disabled={!report || busy}
              onClick={() => exportReport(report)}
            >
              <Icon name="download" size={17} />
              Export JSON
            </button>
          </div>
          {view === "overview" ? (
            <>
              <ScanForm
                busy={busy}
                onPath={(data) => run(() => scanPath(data))}
                onZip={(file) => run(() => scanZip(file))}
              />
              <div aria-live="polite">
                {busy && (
                  <div className="status-banner">
                    <span className="spinner" />
                    Analyzing dependencies, call paths and threat evidence… live
                    scans may take several minutes.
                  </div>
                )}
                {error && (
                  <div className="error" role="alert">
                    {error}
                    <p>
                      Start the backend on port 8000 and check its terminal
                      output.
                    </p>
                  </div>
                )}
              </div>
              <div className="report-heading">
                <div className="report-label">
                  <Icon name="clock" size={16} />
                  {report
                    ? `${report.project} · ${new Date(report.created_at).toLocaleString()}`
                    : "No completed scan"}
                </div>
                <button
                  className="text-button"
                  disabled={busy}
                  onClick={() => run(demoScan)}
                >
                  Run offline demo <Icon name="arrow" size={15} />
                </button>
              </div>
              {report?.mode === "demo" && (
                <div className="demo-banner">
                  <b>DEMO DATA</b> Synthetic advisories and metrics for
                  demonstrating the pipeline. Run a repository scan for live
                  intelligence.
                </div>
              )}
              {summary && (
                <>
                  <div className="stats">
                    <article>
                      <span>DEPENDENCY ALERTS</span>
                      <strong>
                        {summary.total}
                        <Icon name="shield" size={24} />
                      </strong>
                      <p>
                        Across {report.dependencies.length} pinned dependencies
                      </p>
                    </article>
                    <article className="accent">
                      <span>HIGH PRIORITY</span>
                      <strong>
                        {summary.high}
                        <span className="stat-indicator">!</span>
                      </strong>
                      <p>Review these findings first</p>
                    </article>
                    <article>
                      <span>REACHABLE CALL PATHS</span>
                      <strong>
                        {summary.reachable}
                        <Icon name="graph" size={24} />
                      </strong>
                      <p>{summary.unknown} require more analysis</p>
                    </article>
                    <article>
                      <span>ALERT REDUCTION</span>
                      <strong>
                        {Math.round(summary.alert_reduction_rate * 100)}
                        <small>%</small>
                        <Icon name="check" size={24} />
                      </strong>
                      <p>Low-priority findings / total alerts</p>
                    </article>
                  </div>
                  <div className="coverage-strip">
                    <span>
                      <i />
                      Analysis complete
                    </span>
                    <span>{report.files_analyzed} source files</span>
                    <span>{report.graph_nodes} graph nodes</span>
                    <span>{report.graph_edges} call edges</span>
                    <span>MAUT scoring engine</span>
                  </div>
                  <VulnerabilityTable
                    findings={report.findings}
                    selected={selected}
                    onSelect={setSelected}
                  />
                  <FindingDetails
                    finding={selected}
                    onClose={() => setSelected(null)}
                  />
                  <details className="warnings">
                    <summary>
                      Coverage notes & warnings ({report.warnings.length})
                    </summary>
                    <ul className="plain-list">
                      {report.warnings.map((w, i) => (
                        <li key={i}>{w}</li>
                      ))}
                    </ul>
                  </details>
                </>
              )}
            </>
          ) : (
            <section className="info-panel">
              <h2>Three agents, shared evidence</h2>
              <div className="method-grid">
                <article>
                  <b>01 / REACHABILITY</b>
                  <h3>Follow the code</h3>
                  <p>
                    Python ast and Babel build a directed call graph. Graph
                    search returns file and line evidence for matched vulnerable
                    symbols. Explicit entry points improve framework coverage.
                  </p>
                </article>
                <article>
                  <b>02 / INTELLIGENCE</b>
                  <h3>Correlate the threat</h3>
                  <p>
                    OSV matches pinned versions. FIRST supplies EPSS. CISA
                    supplies KEV. NVD fills missing CVSS metrics. Each record
                    retains provenance and timestamps.
                  </p>
                </article>
                <article>
                  <b>03 / PRIORITIZATION</b>
                  <h3>Make the tradeoff visible</h3>
                  <p>
                    Deterministic utility scoring combines five criteria.
                    Optional LLM prose supports review; it never determines the
                    score or automatically patches dependencies.
                  </p>
                </article>
              </div>
              <h3>Utility score, 0–100</h3>
              <pre>
                100 × (0.30 × CVSS/10 + 0.25 × EPSS + 0.25 × reachability + 0.15
                × KEV + 0.05 × business criticality)
              </pre>
              <p>
                Reachability: reachable = 1.0; not observed = 0.2; unknown =
                0.7. Missing CVSS, EPSS and KEV use 0.7, 0.5 and 0.5 review
                defaults. These choices are heuristics requiring calibration.
              </p>
              <p>
                High: score ≥65 or KEV listed. Medium: score ≥35 or reachability
                unknown. Low: remaining findings. Alert reduction means low
                priority / total; it is not proof that an alert is false.
              </p>
              <h3>Limits are part of the result</h3>
              <p>
                No call path found means only that a path was absent from the
                modeled graph. Dynamic dispatch, callbacks, reflection,
                decorators and missing mappings can require further analysis.
                Node analysis currently resolves basic ES-module named imports
                and direct calls; CommonJS and complex dataflow remain unknown.
              </p>
            </section>
          )}
          <footer>
            <span>
              <Icon name="shield" size={15} />
              ContextVuln
            </span>
            <span>
              Evidence-based prioritization · Human-reviewed remediation
            </span>
            <a
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
            >
              API documentation ↗
            </a>
          </footer>
        </div>
      </main>
    </div>
  );
}