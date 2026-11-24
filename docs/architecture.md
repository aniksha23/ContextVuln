# Architecture

React dashboard → FastAPI routes → repository loader → dependency parser → threat intelligence agent → AST reachability agent → utility agent → structured JSON report.

## Contracts

Pydantic models in backend/app/core/schemas.py define Dependency, Vulnerability, Evidence, Reachability, Finding, ScanRequest and ScanReport. The orchestrator passes structured records between three deterministic agents. The optional language model only drafts prose; it never decides reachability or risk scores. Unknown mappings and incomplete evidence request review through review_required and report warnings.

## Agent 1: AST and call graph

Python ast and a trusted Babel subprocess parse source without importing it. NetworkX stores caller→callee edges with source references. A synthetic entry node connects configured entry points or all module initializers. Breadth-first shortest-path traversal produces an evidence trace, search depth and the document's confidence heuristic (1.0 direct, 0.7 transitive, 0 for no observed path). Branches are conservatively included, but callbacks and dynamic dataflow are incomplete. No-path findings are not_observed only with mappings and no known analysis gaps; otherwise unknown.

## Agent 2: threat intelligence

Pinned PyPI/npm versions query paginated OSV. FIRST enriches CVE aliases with EPSS (the maximum matching alias score). CISA KEV membership is tri-state: listed, not listed, or unavailable. OSV CVSS v3/v4 vectors supply severity; missing severity can fall back to NVD. Disk caching uses request hashes and explicit timestamps; successful responses only. Retries handle temporary failures. OSV fixed events yield newer release candidates; they do not establish application compatibility. Reviewed mapping overrides require advisory, package, ecosystem and a provenance URL.

Primary API references:
- OSV: https://google.github.io/osv.dev/post-v1-query/
- EPSS: https://api.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://nvd.nist.gov/developers/vulnerabilities
- Babel parser: https://babeljs.io/docs/babel-parser
- Optional OpenAI reporting: https://developers.openai.com/api/reference/resources/chat

## Agent 3: utility and remediation

Score = 100 × (0.30×CVSS/10 + 0.25×EPSS + 0.25×reachability + 0.15×KEV + 0.05×criticality).

Reachability values: reachable 1.0, not_observed 0.2, unknown 0.7. Missing CVSS uses 0.7 normalized, EPSS 0.5 and KEV 0.5. These are configurable research heuristics, not calibrated probabilities. Weights are nonnegative and sum to 1. Business criticality is 0–1. High ≥65 or KEV listed; medium ≥35 or unknown reachability; otherwise low. Remediation candidates and human compatibility review are reported separately from urgency, so ease of patching does not reduce the risk of a difficult vulnerability.

The optional LLM receives minimal structured evidence and supplies labeled review text. Provider errors fall back to deterministic explanations. No raw source is sent. Generated prose cannot edit scores or apply changes.

## API

- GET /api/health: liveness.
- POST /api/scans: {path, entry_points:[], criticality:0.5, use_llm:false}.
- POST /api/scans/demo: offline synthetic demonstration.
- POST /api/scans/upload: multipart ZIP file; default analysis options.

Each scan returns a complete ScanReport. One scan runs at a time; concurrent requests receive 409. A five-minute timeout returns 504. Uploads have bounded compressed/expanded size and paths are validated before extraction. Local paths must stay inside the configured allowed root. Production job queues, persistent report databases, accounts, git cloning and automatic PRs are outside this local application.

## Frontend

React + Vite, with API requests proxied to the local backend. Components provide scan inputs, summary cards, searchable/sortable/filterable findings, selected evidence traces and report export. Responsive layouts support smaller screens. Semantic tables, labels, keyboard focus and reduced-motion preferences are included. Google Fonts is optional; local fallbacks keep the dashboard usable offline.
