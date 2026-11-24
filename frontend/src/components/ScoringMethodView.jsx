import React, { useEffect, useState } from "react";
import Icon from "./Icon.jsx";
import { fetchScoringConfig } from "../api.js";

const DEFAULT_CONFIG = {
  weights: { epss: 0.4, cvss: 0.35, kev: 0.25 },
  epss_exponent: 0.5,
  reachability_confidence: { direct: 1.0, transitive: 0.7, needs_review_prior: 0.5 },
  criticality_band: [0.7, 1.5],
  tiers: { critical: 65.0, monitor: 35.0 },
  floors: { kev: 60.0, "cvss>=": 9.0, high_cvss: 30.0 },
};

export default function ScoringMethodView() {
  const [config, setConfig] = useState(DEFAULT_CONFIG);
  const [loading, setLoading] = useState(false);
  const [isLive, setIsLive] = useState(false);

  // Simulator states
  const [simCvss, setSimCvss] = useState(8.5);
  const [simEpss, setSimEpss] = useState(0.45);
  const [simKev, setSimKev] = useState(false);
  const [simReach, setSimReach] = useState("direct"); // direct | transitive | unknown | suppressed
  const [simCrit, setSimCrit] = useState(1.0);

  useEffect(() => {
    setLoading(true);
    fetchScoringConfig()
      .then((cfg) => {
        if (cfg && cfg.weights) {
          setConfig(cfg);
          setIsLive(true);
        }
      })
      .catch(() => {
        setIsLive(false);
      })
      .finally(() => setLoading(false));
  }, []);

  // Compute simulated score using active config formula
  const w = config.weights || DEFAULT_CONFIG.weights;
  const epssExp = config.epss_exponent ?? 0.5;
  const epssTerm = Math.pow(Math.max(0, Math.min(1, simEpss)), epssExp);
  const cvssTerm = Math.max(0, Math.min(10, simCvss)) / 10;
  const kevTerm = simKev ? 1.0 : 0.0;

  const threatSignal = (w.epss * epssTerm + w.cvss * cvssTerm + w.kev * kevTerm) * 100;

  let reachFactor = 0.2;
  if (simReach === "direct") reachFactor = config.reachability_confidence?.direct ?? 1.0;
  else if (simReach === "transitive") reachFactor = config.reachability_confidence?.transitive ?? 0.7;
  else if (simReach === "unknown") reachFactor = config.reachability_confidence?.needs_review_prior ?? 0.5;

  const clampedCrit = Math.max(
    config.criticality_band?.[0] ?? 0.7,
    Math.min(config.criticality_band?.[1] ?? 1.5, simCrit)
  );

  let rawScore = threatSignal * reachFactor * clampedCrit;
  let floorApplied = null;

  if (simKev && rawScore < (config.floors?.kev ?? 60.0)) {
    rawScore = config.floors?.kev ?? 60.0;
    floorApplied = "KEV Floor Override (min 60.0)";
  } else if (simCvss >= (config.floors?.["cvss>="] ?? 9.0) && rawScore < (config.floors?.high_cvss ?? 30.0)) {
    rawScore = config.floors?.high_cvss ?? 30.0;
    floorApplied = "High CVSS Floor Override (min 30.0)";
  }

  const finalScore = Math.min(100, Math.max(0, rawScore));

  let simTier = "LOW_RISK";
  if (finalScore >= (config.tiers?.critical ?? 65.0) || simKev) simTier = "CRITICAL_ACTION";
  else if (finalScore >= (config.tiers?.monitor ?? 35.0)) simTier = "MONITOR";
  else if (simReach === "suppressed") simTier = "SUPPRESSED_NOISE";
  else if (simReach === "unknown") simTier = "NEEDS_REVIEW";

  return (
    <div className="method-view-container">
      {/* Overview Banner */}
      <div className="method-banner">
        <div>
          <span className="eyebrow">DETERMINISTIC MULTI-CRITERIA DECISION ANALYSIS (MAUT)</span>
          <h2>Evidence-Based Prioritization Engine</h2>
          <p>
            ContextVuln replaces arbitrary urgency with transparent mathematical scoring. Scores represent
            actionable remediation utility, not just raw theoretical severity.
          </p>
        </div>
        <div className="config-sync-badge">
          <Icon name="server" size={14} />
          <span>{isLive ? "Live Config Synced from Backend" : "Default Scoring Model"}</span>
        </div>
      </div>

      {/* Three Pillars Grid */}
      <div className="method-grid">
        <article className="pillar-card">
          <div className="pillar-tag">AGENT 1 / AST REACHABILITY</div>
          <h3>Follow the Real Execution Graph</h3>
          <p>
            Parses Python abstract syntax trees into an in-memory directed call graph. Recursively traces from
            framework entry points to vulnerable dependency symbol sinks. Differentiates direct calls (1.0)
            from transitive helper delegation (0.7).
          </p>
          <div className="pillar-stat">
            <span>Direct confidence: <strong>100%</strong></span>
            <span>Transitive: <strong>70%</strong></span>
          </div>
        </article>

        <article className="pillar-card">
          <div className="pillar-tag">AGENT 2 / THREAT INTELLIGENCE</div>
          <h3>Correlate Global Threat Signals</h3>
          <p>
            Queries Open Source Vulnerabilities (OSV), FIRST Exploit Prediction Scoring System (EPSS), and CISA
            Known Exploited Vulnerabilities (KEV). Applies a square-root power transform (<code>epss^0.5</code>) to
            appropriately weigh low base-rate probabilities.
          </p>
          <div className="pillar-stat">
            <span>KEV Weight: <strong>{Math.round((w.kev || 0.25) * 100)}%</strong></span>
            <span>EPSS Weight: <strong>{Math.round((w.epss || 0.4) * 100)}%</strong></span>
          </div>
        </article>

        <article className="pillar-card">
          <div className="pillar-tag">AGENT 3 / REMEDIATION AGENT</div>
          <h3>Safe Suppression & Action Plans</h3>
          <p>
            Computes unified diffs in <code>requirements.txt</code> deterministically. Never auto-suppresses
            transitive vulnerabilities whose parent libraries are active. Gemini LLM provides optional prose
            and human-reviewed code patch proposals.
          </p>
          <div className="pillar-stat">
            <span>Transitive Protection: <strong>Strict</strong></span>
            <span>PR Title Generation: <strong>Automated</strong></span>
          </div>
        </article>
      </div>

      {/* Interactive Scoring Simulator */}
      <section className="simulator-section">
        <div className="simulator-header">
          <div>
            <span className="eyebrow">INTERACTIVE MODEL SIMULATOR</span>
            <h3>Test the Prioritization Formula</h3>
            <p>Adjust threat signals and reachability to observe how the active backend engine scores findings.</p>
          </div>
          <div className="sim-result-card">
            <span className="sim-label">Computed Utility Score</span>
            <div className="sim-score-row">
              <strong className="sim-score-num">{finalScore.toFixed(1)}</strong>
              <span className="sim-score-max">/100</span>
            </div>
            <div className={`sim-tier-badge tier-${simTier.toLowerCase().replace("_", "-")}`}>
              {simTier.replace("_", " ")}
            </div>
            {floorApplied && <small className="sim-floor-note">{floorApplied}</small>}
          </div>
        </div>

        <div className="sim-controls-grid">
          <div className="sim-control-group">
            <label>
              CVSS Base Severity: <strong>{simCvss.toFixed(1)}</strong>
              <input
                type="range"
                min="0"
                max="10"
                step="0.1"
                value={simCvss}
                onChange={(e) => setSimCvss(Number(e.target.value))}
              />
            </label>
          </div>

          <div className="sim-control-group">
            <label>
              EPSS Exploit Probability: <strong>{(simEpss * 100).toFixed(1)}%</strong>
              <input
                type="range"
                min="0"
                max="1"
                step="0.01"
                value={simEpss}
                onChange={(e) => setSimEpss(Number(e.target.value))}
              />
            </label>
          </div>

          <div className="sim-control-group">
            <label>
              AST Reachability Status:
              <select value={simReach} onChange={(e) => setSimReach(e.target.value)}>
                <option value="direct">Direct Call Path (Factor 1.0)</option>
                <option value="transitive">Transitive Call Path (Factor 0.7)</option>
                <option value="unknown">Inconclusive / Needs Review (Factor 0.5)</option>
                <option value="suppressed">Confirmed Dead Code (Factor 0.2)</option>
              </select>
            </label>
          </div>

          <div className="sim-control-group">
            <label>
              Business Criticality: <strong>{simCrit.toFixed(1)}x</strong>
              <input
                type="range"
                min="0.7"
                max="1.5"
                step="0.1"
                value={simCrit}
                onChange={(e) => setSimCrit(Number(e.target.value))}
              />
            </label>
          </div>

          <div className="sim-control-group checkbox-group">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={simKev}
                onChange={(e) => setSimKev(e.target.checked)}
              />
              <strong>CISA KEV Active Exploitation (Triggers min 60.0 floor)</strong>
            </label>
          </div>
        </div>
      </section>

      {/* Safety Rules & Philosophy */}
      <div className="method-details-columns">
        <div>
          <h3>Safe Suppression Safeguards</h3>
          <p>
            An alert is classified as <code>SUPPRESSED_NOISE</code> <em>only</em> when AST analysis proves that:
          </p>
          <ul className="plain-list">
            <li>The package is directly imported, but the vulnerable symbols are completely absent from the call graph.</li>
            <li>No dynamic reflection (<code>getattr</code>, <code>__import__</code>) is present in files importing that package.</li>
            <li>The package is not a runtime server host (e.g., <code>gunicorn</code>, <code>uvicorn</code>, <code>flask</code>).</li>
          </ul>
        </div>
        <div>
          <h3>Why NEEDS_REVIEW is Essential</h3>
          <p>
            Standard SAST tools produce false negatives by silently dropping transitive vulnerabilities.
            ContextVuln treats ambiguous cases as <code>NEEDS_REVIEW</code>:
          </p>
          <ul className="plain-list">
            <li>Transitive dependencies (e.g. <code>urllib3</code> via <code>requests</code>) whose parent package is in use.</li>
            <li>Dynamic imports or unverified symbol mappings.</li>
            <li>Non-PyPI dependencies or missing version pins.</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
