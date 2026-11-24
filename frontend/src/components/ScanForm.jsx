import React, { useState } from "react";
import Icon from "./Icon.jsx";

const CRITICALITY_PRESETS = [
  { value: 0.7, label: "0.7x Internal Tool", desc: "Non-critical internal utilities" },
  { value: 1.0, label: "1.0x Standard Service", desc: "Default backend application" },
  { value: 1.4, label: "1.4x Public Production", desc: "Internet-facing production API" },
  { value: 2.0, label: "2.0x Mission-Critical", desc: "High-compliance core infrastructure" },
];

const REPO_PRESETS = [
  {
    name: "FastAPI / Requests App (Vulnerable)",
    url: "https://github.com/tiangolo/fastapi",
    criticality: 1.4,
    entries: "main.app",
  },
  {
    name: "Flask Microservice (Demo Target)",
    url: "https://github.com/pallets/flask",
    criticality: 1.0,
    entries: "app.create_app",
  },
];

export default function ScanForm({ onPath, onZip, busy }) {
  const [mode, setMode] = useState("path");
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState("");
  const [criticality, setCriticality] = useState(1.0);
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [apiKey, setApiKey] = useState(localStorage.getItem("contextvuln_api_key") || "");
  const [showKeyInput, setShowKeyInput] = useState(false);

  function handleSaveApiKey(val) {
    setApiKey(val);
    if (val.trim()) {
      localStorage.setItem("contextvuln_api_key", val.trim());
    } else {
      localStorage.removeItem("contextvuln_api_key");
    }
  }

  function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith(".zip")) {
        setSelectedFile(file);
      } else {
        alert("Please upload a .zip archive of your project repository.");
      }
    }
  }

  function handleDrag(e) {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }

  return (
    <section className="scan-panel" aria-labelledby="scan-title">
      <div className="section-heading">
        <div>
          <span className="eyebrow">AUTOMATED REACHABILITY & THREAT TRIAGE</span>
          <h2 id="scan-title">Start a Context-Aware Security Scan</h2>
          <p>
            Pinpoint vulnerable dependencies, trace AST execution call paths, and separate true threats from dead code.
          </p>
        </div>
        <div className="scan-icon-pill">
          <Icon name="scan" size={24} />
        </div>
      </div>

      {/* Mode Navigation Tabs */}
      <div className="tabs" role="tablist" aria-label="Scan input type">
        <button
          role="tab"
          aria-selected={mode === "path"}
          className={mode === "path" ? "active" : ""}
          onClick={() => setMode("path")}
        >
          <Icon name="code" size={15} />
          GitHub Repository
        </button>
        <button
          role="tab"
          aria-selected={mode === "zip"}
          className={mode === "zip" ? "active" : ""}
          onClick={() => setMode("zip")}
        >
          <Icon name="layers" size={15} />
          Upload Source Archive (.zip)
        </button>
        <button
          type="button"
          className="api-key-toggle-btn"
          onClick={() => setShowKeyInput(!showKeyInput)}
          title="Configure optional API key"
        >
          <Icon name="shield" size={13} />
          {apiKey ? "API Key Set" : "API Key"}
        </button>
      </div>

      {showKeyInput && (
        <div className="api-key-drawer">
          <label htmlFor="api-key-input">
            Optional Backend API Key (Header: <code>X-API-Key</code>):
          </label>
          <div className="input-row">
            <input
              id="api-key-input"
              type="password"
              value={apiKey}
              onChange={(e) => handleSaveApiKey(e.target.value)}
              placeholder="Paste backend API key if configured in .env"
            />
            {apiKey && (
              <button
                type="button"
                className="secondary"
                onClick={() => handleSaveApiKey("")}
              >
                Clear
              </button>
            )}
          </div>
          <p className="hint">
            Stored in your browser local storage. Only required if <code>API_KEY</code> is set in the backend environment.
          </p>
        </div>
      )}

      {mode === "path" ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!path.trim()) return;
            onPath({
              path: path.trim(),
              entry_points: entries
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
              criticality: Number(criticality),
            });
          }}
        >
          <label htmlFor="repo-path">
            Public GitHub Repository URL
          </label>
          <div className="input-row">
            <input
              id="repo-path"
              required
              disabled={busy}
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="https://github.com/owner/repository"
            />
            <button className="primary" disabled={busy || !path.trim()}>
              <Icon name="scan" size={16} />
              {busy ? "Scanning..." : "Analyze Repository"}
            </button>
          </div>

          {/* Quick Repositories Presets */}
          <div className="quick-presets">
            <span className="preset-label">Quick sample targets:</span>
            {REPO_PRESETS.map((p) => (
              <button
                type="button"
                key={p.name}
                className="preset-chip"
                disabled={busy}
                onClick={() => {
                  setPath(p.url);
                  setCriticality(p.criticality);
                  setEntries(p.entries);
                }}
              >
                {p.name}
              </button>
            ))}
          </div>

          {/* Criticality & Advanced Controls */}
          <div className="scan-controls-grid">
            <div className="criticality-section">
              <div className="criticality-header">
                <label>Business Criticality Multiplier:</label>
                <span className="criticality-badge">{Number(criticality).toFixed(1)}x</span>
              </div>
              <div className="criticality-pills">
                {CRITICALITY_PRESETS.map((cp) => (
                  <button
                    type="button"
                    key={cp.value}
                    disabled={busy}
                    className={`crit-pill ${Math.abs(criticality - cp.value) < 0.05 ? "active" : ""}`}
                    onClick={() => setCriticality(cp.value)}
                    title={cp.desc}
                  >
                    {cp.label}
                  </button>
                ))}
              </div>
              <input
                type="range"
                min="0.1"
                max="2.0"
                step="0.1"
                disabled={busy}
                value={criticality}
                onChange={(e) => setCriticality(Number(e.target.value))}
                className="criticality-slider"
              />
            </div>
          </div>

          <details
            className="advanced"
            open={showAdvanced}
            onToggle={(e) => setShowAdvanced(e.target.open)}
          >
            <summary>
              <span>Framework Entry Points & Scope Options</span>
            </summary>
            <div className="options">
              <label>
                Application Entry Points (optional, comma-separated)
                <input
                  value={entries}
                  disabled={busy}
                  onChange={(e) => setEntries(e.target.value)}
                  placeholder="e.g. main.app, api.routes.handler, app.create_app"
                />
                <span className="field-hint">
                  Guides the AST reachability crawler when framework routers or factory patterns are used.
                </span>
              </label>
            </div>
          </details>

          <p className="hint">
            Supports Python (PyPI) dependencies with requirements.txt or setup.cfg · Static AST call-graph reachability · Source is parsed, never executed
          </p>
        </form>
      ) : (
        <div className="upload-container">
          <div
            className={`dropzone ${dragActive ? "drag-active" : ""} ${selectedFile ? "has-file" : ""}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              id="source-zip"
              type="file"
              accept=".zip"
              disabled={busy}
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  setSelectedFile(e.target.files[0]);
                }
              }}
              style={{ display: "none" }}
            />

            {selectedFile ? (
              <div className="dropzone-file-selected">
                <div className="file-info-row">
                  <Icon name="layers" size={28} />
                  <div>
                    <strong>{selectedFile.name}</strong>
                    <span>{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB archive</span>
                  </div>
                  <button
                    type="button"
                    className="icon-button"
                    onClick={() => setSelectedFile(null)}
                    disabled={busy}
                    title="Remove file"
                  >
                    <Icon name="close" size={14} />
                  </button>
                </div>
                <div className="criticality-compact">
                  <label>Business Criticality:</label>
                  <select
                    value={criticality}
                    onChange={(e) => setCriticality(Number(e.target.value))}
                    disabled={busy}
                  >
                    {CRITICALITY_PRESETS.map((p) => (
                      <option key={p.value} value={p.value}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </div>
                <button
                  type="button"
                  className="primary upload-submit-btn"
                  disabled={busy}
                  onClick={() => onZip(selectedFile, criticality)}
                >
                  <Icon name="scan" size={16} />
                  {busy ? "Analyzing Archive..." : "Scan Uploaded Archive"}
                </button>
              </div>
            ) : (
              <label htmlFor="source-zip" className="dropzone-label">
                <Icon name="download" size={32} />
                <strong>Click to choose or drag & drop project ZIP archive</strong>
                <span>Contains source files and requirements.txt (Max 15MB compressed)</span>
              </label>
            )}
          </div>
          <p className="hint">
            Archive is processed in an isolated in-memory scratch environment and discarded immediately after reachability graph generation.
          </p>
        </div>
      )}
    </section>
  );
}
