import React, { useState } from "react";
import Icon from "./Icon.jsx";

export default function FindingDetails({ finding: f, onClose }) {
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [copiedPr, setCopiedPr] = useState(false);

  if (!f) return null;

  const v = f.vulnerability;
  const meta = f.tier_meta;
  const rem = f.remediation || {};
  const sb = f.score_breakdown || {};
  const trace = f.call_trace || [];

  function handleCopyDiff() {
    if (!rem.requirements_diff) return;
    navigator.clipboard.writeText(rem.requirements_diff);
    setCopiedDiff(true);
    setTimeout(() => setCopiedDiff(false), 2000);
  }

  function handleCopyPrTitle() {
    if (!rem.pr_title) return;
    navigator.clipboard.writeText(rem.pr_title);
    setCopiedPr(true);
    setTimeout(() => setCopiedPr(false), 2000);
  }

  return (
    <section className="finding-details" aria-label="Finding evidence and remediation">
      {/* Header */}
      <div className="section-heading details-header">
        <div className="header-meta-group">
          <div className="cve-title-line">
            <span className={`badge ${meta.badgeClass}`}>
              <i /> {meta.label}
            </span>
            <h2>{f.cve_id}</h2>
            {rem.quick_win && (
              <span className="quick-win-badge" title="Patch or minor upgrade with validated fix">
                <Icon name="zap" size={13} /> Quick Win
              </span>
            )}
            {rem.upgrade_effort && (
              <span className={`effort-badge effort-${rem.upgrade_effort}`}>
                {rem.upgrade_effort} upgrade
              </span>
            )}
          </div>
          <p className="finding-summary-text">
            <strong>{f.package_name}@{f.installed_version}</strong>
            {rem.upgrade_to && (
              <span className="upgrade-arrow-target">
                <Icon name="arrow" size={13} />
                <code>{rem.upgrade_to}</code>
              </span>
            )}
            {" · "}
            {f.summary}
          </p>
        </div>
        <button
          type="button"
          className="icon-button close-details-btn"
          onClick={onClose}
          aria-label="Close details"
        >
          <Icon name="close" size={16} />
        </button>
      </div>

      {/* Main Grid */}
      <div className="detail-columns">
        {/* Left Column: AST & Code Evidence */}
        <div className="detail-pane">
          <div className="pane-section-header">
            <Icon name="graph" size={18} />
            <h3>AST Reachability & Execution Evidence</h3>
          </div>

          <div className="reach-status-card">
            <div className="reach-status-line">
              <span className="label-dim">Analysis Verdict:</span>
              <strong className={`reach-verdict status-${f.reachability_status}`}>
                {f.reachability_status === "reachable"
                  ? "Confirmed Reachable in Call Graph"
                  : f.priority_tier === "NEEDS_REVIEW"
                    ? "Inconclusive (Needs Human Review)"
                    : "Unreachable (Safely Suppressed Dead Code)"}
              </strong>
            </div>
            <div className="reach-meta-row">
              <span>Confidence: <strong>{Math.round(f.reachability_confidence * 100)}%</strong></span>
              <span>Search Depth: <strong>{f.search_depth} hops</strong></span>
              <span>Ecosystem: <strong>{f.ecosystem}</strong></span>
            </div>
          </div>

          {/* AST Call Trace */}
          <h4>Modeled Execution Trace ({trace.length} steps)</h4>
          {trace.length > 0 ? (
            <ol className="trace-list">
              {trace.map((step, idx) => (
                <li key={idx} className="trace-item">
                  <span className="trace-index">{idx + 1}</span>
                  <div className="trace-content">
                    <div className="trace-caller-callee">
                      <code className="caller-code">{step.caller}</code>
                      <Icon name="arrow" size={13} />
                      <code className="callee-code">{step.callee}</code>
                    </div>
                    <div className="trace-file-loc">
                      <Icon name="code" size={12} />
                      <span>{step.file}:{step.line}</span>
                    </div>
                    {step.call_expression && (
                      <div className="trace-code-snippet">
                        <small>Call site:</small>
                        <pre><code>{step.call_expression}</code></pre>
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <div className="empty-trace-box">
              <Icon name="shield" size={18} />
              <p>
                {f.priority_tier === "SUPPRESSED_NOISE"
                  ? "Zero invocation paths detected from any modeled entrypoint to vulnerable symbols in this repository."
                  : "No direct static call path observed. See limitations below for potential indirect dispatch."}
              </p>
            </div>
          )}

          {/* Dependency Lineage */}
          <h4>Dependency Lineage & Symbols</h4>
          <div className="lineage-card">
            <div className="lineage-row">
              <span className="lineage-label">Origin:</span>
              <span>
                {f.is_direct_dependency ? (
                  <span className="tag-direct">Direct Project Dependency</span>
                ) : (
                  <span className="tag-transitive">
                    Transitive (Introduced via: {f.introduced_via.join(", ") || "parent package"})
                  </span>
                )}
              </span>
            </div>
            <div className="lineage-row">
              <span className="lineage-label">Symbol Source:</span>
              <span>{f.symbol_source}</span>
            </div>
            <div className="lineage-row">
              <span className="lineage-label">Target Symbols:</span>
              <code className="symbols-code">
                {f.vulnerable_symbols.length > 0
                  ? f.vulnerable_symbols.join(", ")
                  : "Package-level mapping (no function target listed in advisory)"}
              </code>
            </div>
          </div>

          {/* Limitations and Review Reasons */}
          {(f.limitations.length > 0 || f.uncertainty_reasons.length > 0) && (
            <div className="limitations-box">
              <h4>Safety Caveats & Blind Spots</h4>
              <ul className="plain-list">
                {f.uncertainty_reasons.map((reason, i) => (
                  <li key={`unc-${i}`} className="uncertainty-item">
                    <Icon name="alert" size={13} />
                    <span>{reason}</span>
                  </li>
                ))}
                {f.limitations.map((lim, i) => (
                  <li key={`lim-${i}`}>
                    <span>{lim}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Right Column: MAUT Scoring & Remediation */}
        <div className="detail-pane">
          <div className="pane-section-header">
            <Icon name="zap" size={18} />
            <h3>Multi-Criteria MAUT Prioritization</h3>
          </div>

          <div className="score-hero-box">
            <div className="score-hero-top">
              <div>
                <span className="score-hero-label">Utility Score</span>
                <div className="score-number-group">
                  <span className="score-large">{f.utility_score.toFixed(1)}</span>
                  <span className="score-out">/100</span>
                </div>
              </div>
              <div className="score-tier-flag">
                <span className={`badge ${meta.badgeClass}`}>
                  <i /> {meta.label}
                </span>
                {sb.floor_applied && (
                  <span className="score-floor-badge" title={sb.floor_applied}>
                    Floor override
                  </span>
                )}
              </div>
            </div>

            <p className="ai-reasoning-prose">{f.ai_reasoning}</p>

            {/* Score Factor Breakdown */}
            <div className="contributions-grid">
              <div className="contrib-item">
                <div className="contrib-labels">
                  <span>CVSS Severity</span>
                  <strong>{f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}</strong>
                </div>
                <div className="bar">
                  <i style={{ width: `${Math.min(100, (f.cvss_score || 0) * 10)}%` }} />
                </div>
                {f.cvss_vector && <small className="cvss-vector-str">{f.cvss_vector}</small>}
              </div>

              <div className="contrib-item">
                <div className="contrib-labels">
                  <span>EPSS Exploitability</span>
                  <strong>{f.epss_score != null ? `${(f.epss_score * 100).toFixed(2)}%` : "—"}</strong>
                </div>
                <div className="bar">
                  <i style={{ width: `${Math.min(100, (f.epss_score || 0) * 100)}%` }} />
                </div>
                {f.epss_percentile != null && (
                  <small className="percentile-text">
                    Top {Math.max(1, Math.round((1 - f.epss_percentile) * 100))}% of all CVEs
                  </small>
                )}
              </div>

              <div className="contrib-item">
                <div className="contrib-labels">
                  <span>CISA KEV Status</span>
                  <strong className={f.is_in_kev ? "kev-highlight" : "muted"}>
                    {f.is_in_kev ? "Listed (Active Threat)" : "Not Listed"}
                  </strong>
                </div>
                <div className="bar">
                  <i style={{ width: f.is_in_kev ? "100%" : "0%" }} />
                </div>
              </div>

              <div className="contrib-item">
                <div className="contrib-labels">
                  <span>Reachability Weight</span>
                  <strong>{f.reachability_status.replace("_", " ")}</strong>
                </div>
                <div className="bar">
                  <i
                    style={{
                      width:
                        f.reachability_status === "reachable"
                          ? "100%"
                          : f.reachability_status === "unknown"
                            ? "60%"
                            : "20%",
                    }}
                  />
                </div>
              </div>
            </div>

            {sb.notes && sb.notes.length > 0 && (
              <div className="score-notes">
                {sb.notes.map((n, i) => (
                  <span key={i} className="score-note-pill">
                    ● {n}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Remediation Plan */}
          <div className="remediation-section">
            <div className="remediation-header">
              <Icon name="check" size={17} />
              <h4>Remediation Plan</h4>
            </div>
            <p className="remediation-text">{f.remediation_advice}</p>

            {/* Unified Requirements Diff */}
            {rem.requirements_diff ? (
              <div className="diff-card">
                <div className="diff-header">
                  <span className="diff-title">
                    <Icon name="code" size={13} />
                    requirements.txt patch
                  </span>
                  <button
                    type="button"
                    className="diff-copy-btn"
                    onClick={handleCopyDiff}
                  >
                    <Icon name="copy" size={12} />
                    {copiedDiff ? "Copied Diff!" : "Copy Diff"}
                  </button>
                </div>
                <pre className="diff-viewer">
                  <code>
                    {rem.requirements_diff.split("\n").map((line, lIdx) => {
                      const isAdd = line.startsWith("+");
                      const isDel = line.startsWith("-");
                      const isHunk = line.startsWith("@@");
                      return (
                        <div
                          key={lIdx}
                          className={`diff-line ${isAdd ? "diff-add" : isDel ? "diff-del" : isHunk ? "diff-hunk" : ""}`}
                        >
                          {line}
                        </div>
                      );
                    })}
                  </code>
                </pre>
              </div>
            ) : null}

            {/* PR Title */}
            {rem.pr_title && (
              <div className="pr-title-box">
                <div className="pr-title-header">
                  <span>Suggested PR Title:</span>
                  <button
                    type="button"
                    className="diff-copy-btn"
                    onClick={handleCopyPrTitle}
                  >
                    <Icon name="copy" size={12} />
                    {copiedPr ? "Copied!" : "Copy Title"}
                  </button>
                </div>
                <code>{rem.pr_title}</code>
              </div>
            )}

            {/* Mitigations */}
            {rem.mitigations && rem.mitigations.length > 0 && (
              <div className="mitigations-block">
                <h5>Immediate Workarounds & Mitigations:</h5>
                <ul className="plain-list">
                  {rem.mitigations.map((m, i) => (
                    <li key={i}>{m}</li>
                  ))}
                </ul>
              </div>
            )}

            {/* LLM Report if present */}
            {rem.code_patch && (
              <details className="llm-patch-drawer">
                <summary>
                  <Icon name="sparkles" size={13} />
                  Gemini Code Patch Draft (Human Review Required)
                </summary>
                <pre className="llm-code-view">
                  <code>{rem.code_patch}</code>
                </pre>
              </details>
            )}
          </div>
        </div>
      </div>

      {/* Threat Provenance & Agent Trace */}
      <details className="provenance-collapsible">
        <summary>
          <span>
            <Icon name="shield" size={14} />
            Data Provenance & Multi-Agent Execution Trace ({v.evidence?.length || 1} sources)
          </span>
        </summary>
        <div className="provenance-body">
          {f.agent_trace && f.agent_trace.length > 0 && (
            <div className="agent-timeline">
              <strong>Pipeline Execution Log:</strong>
              <div className="agent-log-steps">
                {f.agent_trace.map((step, sIdx) => (
                  <div key={sIdx} className="agent-step-item">
                    <span className="agent-step-num">{sIdx + 1}</span>
                    <code>{step}</code>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="sources-list">
            <strong>Threat Intelligence Feeds:</strong>
            <ul className="plain-list">
              {(v.evidence || []).map((e, idx) => (
                <li key={idx}>
                  <strong>{e.source}</strong> · Status: {e.status} ·{" "}
                  {e.retrieved_at ? new Date(e.retrieved_at).toLocaleString() : "Live"} {e.detail}
                </li>
              ))}
            </ul>
          </div>

          {v.references && v.references.length > 0 && (
            <div className="references-list">
              <strong>Advisory References:</strong>
              <ul>
                {v.references
                  .filter((url) => typeof url === "string" && url.startsWith("http"))
                  .map((url) => (
                    <li key={url}>
                      <a href={url} target="_blank" rel="noreferrer">
                        {url} <Icon name="external" size={11} />
                      </a>
                    </li>
                  ))}
              </ul>
            </div>
          )}
        </div>
      </details>
    </section>
  );
}
