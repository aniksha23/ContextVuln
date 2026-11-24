import React, { useState } from "react";
import Icon from "./Icon.jsx";
export default function ScanForm({ onPath, onZip, busy }) {
  const [mode, setMode] = useState("path"),
    [path, setPath] = useState(""),
    [entries, setEntries] = useState(""),
    [criticality, setCriticality] = useState(0.5),
    [llm, setLlm] = useState(false);
  return (
    <section className="scan-panel" aria-labelledby="scan-title">
      <div className="section-heading">
        <div>
          <span className="eyebrow">START AN INVESTIGATION</span>
          <h2 id="scan-title">Put your dependencies in context.</h2>
        </div>
        <Icon name="scan" size={28} />
      </div>
      <div className="tabs" role="group" aria-label="Scan input type">
        <button
          className={mode === "path" ? "active" : ""}
          onClick={() => setMode("path")}
        >
          GitHub link
        </button>
        <button
          className={mode === "zip" ? "active" : ""}
          onClick={() => setMode("zip")}
        >
          Upload source ZIP
        </button>
      </div>
      {mode === "path" ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            onPath({
              path,
              entry_points: entries
                .split(",")
                .map((s) => s.trim())
                .filter(Boolean),
              criticality: Number(criticality),
              use_llm: llm,
            });
          }}
        >
          <label htmlFor="repo-path">
            GitHub repository URL
          </label>
          <div className="input-row">
            <input
              id="repo-path"
              required
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="https://github.com/owner/repository"
            />
            <button className="primary" disabled={busy || !path.trim()}>
              <Icon name="scan" />
              Analyze repository
            </button>
          </div>
          <details className="advanced">
            <summary>Entry points & analysis options</summary>
            <div className="options">
              <label>
                Entry points (optional, comma separated)
                <input
                  value={entries}
                  onChange={(e) => setEntries(e.target.value)}
                  placeholder="main.main, api.handle_request"
                />
              </label>
              <label>
                Business criticality: {Number(criticality).toFixed(1)}
                <input
                  type="range"
                  min="0"
                  max="1"
                  step=".1"
                  value={criticality}
                  onChange={(e) => setCriticality(e.target.value)}
                />
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={llm}
                  onChange={(e) => setLlm(e.target.checked)}
                />
                Request optional LLM draft (sends structured findings to OpenAI;
                server key required)
              </label>
            </div>
          </details>
          <p className="hint">
            Python & Node.js · Exact dependency versions · Source is parsed,
            never executed
          </p>
        </form>
      ) : (
        <div className="upload">
          <label htmlFor="source-zip">
            Upload a ZIP containing source and requirements.txt or
            package-lock.json.
          </label>
          <input
            id="source-zip"
            type="file"
            accept=".zip"
            disabled={busy}
            onChange={(e) => {
              if (e.target.files[0]) onZip(e.target.files[0]);
              e.target.value = "";
            }}
          />
          <p className="hint">
            15 MB compressed / 30 MB expanded. Uploaded source is removed after
            analysis.
          </p>
        </div>
      )}
    </section>
  );
}