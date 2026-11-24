import React, { useEffect, useState } from "react";
import Icon from "./Icon.jsx";

const STAGES = [
  { id: "load", label: "Source Extraction", pattern: /clon|extract|load/i },
  { id: "ast", label: "AST Call Graph", pattern: /call graph|ast/i },
  { id: "intel", label: "Threat Intelligence", pattern: /intelligence|osv|epss|kev/i },
  { id: "dep", label: "Dependency Graph", pattern: /dependency/i },
  { id: "triage", label: "MAUT Prioritization", pattern: /analys|triage|score/i },
];

export default function JobProgress({ jobState, onCancel }) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const progressPercent = Math.min(100, Math.max(5, Math.round((jobState.progress || 0.05) * 100)));
  const stageName = jobState.stage || "Initializing multi-agent pipeline...";

  // Determine current active stage index
  let activeIndex = 0;
  STAGES.forEach((st, idx) => {
    if (st.pattern.test(stageName)) {
      activeIndex = idx;
    }
  });

  return (
    <div className="job-progress-card" role="status" aria-live="polite">
      <div className="job-progress-header">
        <div className="job-title-group">
          <span className="job-pulse-dot" />
          <div>
            <h3 className="job-title">Contextual Scan in Progress</h3>
            <p className="job-stage-text">
              <strong>{stageName}</strong>
            </p>
          </div>
        </div>
        <div className="job-metrics">
          <span className="job-timer">
            <Icon name="clock" size={14} />
            {elapsed}s elapsed
          </span>
          {onCancel && (
            <button className="job-cancel-btn" onClick={onCancel} title="Abort scan">
              <Icon name="close" size={13} />
              Cancel
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      <div className="job-bar-container">
        <div className="job-bar-fill" style={{ width: `${progressPercent}%` }}>
          <span className="job-bar-glow" />
        </div>
      </div>
      <div className="job-bar-labels">
        <span>AST & Threat Pipeline</span>
        <strong className="job-pct">{progressPercent}%</strong>
      </div>

      {/* Stage Stepper */}
      <div className="job-stepper">
        {STAGES.map((st, idx) => {
          const isDone = idx < activeIndex;
          const isCurrent = idx === activeIndex;
          return (
            <div
              key={st.id}
              className={`job-step ${isDone ? "step-done" : ""} ${isCurrent ? "step-active" : ""}`}
            >
              <div className="step-bullet">
                {isDone ? <Icon name="check" size={12} /> : idx + 1}
              </div>
              <span className="step-name">{st.label}</span>
            </div>
          );
        })}
      </div>

      <div className="job-footer-note">
        <Icon name="shield" size={13} />
        <span>Source code is safely inspected via AST parsing on your machine — zero code is executed.</span>
      </div>
    </div>
  );
}
