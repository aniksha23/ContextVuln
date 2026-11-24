import React from "react";
import Icon from "./Icon.jsx";
export default function FindingDetails({ finding: f, onClose }) {
  if (!f) return null;
  const v = f.vulnerability,
    r = f.reachability;
  return (
    <section className="finding-details" aria-label="Finding evidence">
      <div className="section-heading">
        <div>
          <span className="eyebrow">EVIDENCE EXPLORER</span>
          <h2>{v.id}</h2>
          <p>
            {v.package}@{v.version} · {v.summary}
          </p>
        </div>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label="Close finding details"
        >
          <Icon name="close" />
        </button>
      </div>
      <div className="detail-columns">
        <div>
          <h3>
            Call-path evidence{" "}
            <span className={`badge ${r.status}`}>
              {r.status.replace("_", " ")}
            </span>
          </h3>
          {r.trace.length ? (
            <ol className="trace">
              {r.trace.map((step, i) => (
                <li key={i}>
                  <span className="trace-index">{i + 1}</span>
                  <div>
                    <code>{step.caller}</code>
                    <Icon name="arrow" size={15} />
                    <code>{step.callee}</code>
                    <small>
                      {step.file}:{step.line}
                    </small>
                  </div>
                </li>
              ))}
            </ol>
          ) : (
            <p className="muted">
              No modeled call path. Review the limitations below.
            </p>
          )}
          <p className="hint">
            Trace depth {r.depth} · Evidence confidence{" "}
            {Math.round(r.confidence * 100)}% (a heuristic, not a statistical
            probability)
          </p>
          <h3>Analysis limits</h3>
          <ul className="plain-list">
            {r.limitations.map((x, i) => (
              <li key={i}>{x}</li>
            ))}
          </ul>
          <h3>Function mapping</h3>
          <p className="muted">{v.mapping_source}</p>
          <code>{v.symbols.join(", ") || "No verified symbol mapping"}</code>
        </div>
        <div>
          <h3>Why this priority?</h3>
          <p>{f.explanation}</p>
          <div className="contributions">
            {Object.entries(f.contributions).map(([key, value]) => (
              <div key={key}>
                <span>{key.replaceAll("_", " ")}</span>
                <div className="bar">
                  <i style={{ width: `${Math.min(value * 2.5, 100)}%` }} />
                </div>
                <b>{value.toFixed(1)}</b>
              </div>
            ))}
          </div>
          <h3>Remediation plan</h3>
          <p>{f.remediation}</p>
          {f.review_required.length > 0 && (
            <ul className="plain-list">
              {f.review_required.map((x, i) => (
                <li key={i}>{x}</li>
              ))}
            </ul>
          )}
          {f.llm_report && (
            <details>
              <summary>LLM draft · review required</summary>
              <p className="llm-copy">{f.llm_report}</p>
            </details>
          )}
        </div>
      </div>
      <details className="provenance">
        <summary>
          Threat data & provenance ({v.evidence.length} sources)
        </summary>
        <ul className="plain-list">
          {v.evidence.map((e, i) => (
            <li key={i}>
              <b>{e.source}</b> · {e.status} ·{" "}
              {new Date(e.retrieved_at).toLocaleString()} {e.detail}
            </li>
          ))}
        </ul>
        <p>EPSS date: {v.epss_date || "Unavailable"}</p>
        {v.references
          .filter((url) => url.startsWith("https://"))
          .map((url) => (
            <p key={url}>
              <a href={url} target="_blank" rel="noreferrer">
                {url}
              </a>
            </p>
          ))}
      </details>
    </section>
  );
}
