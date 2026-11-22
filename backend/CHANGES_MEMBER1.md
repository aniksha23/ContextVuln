# Member 1 patch - what changed and how to apply it

Drop these files over your repo (same paths). `ast_agent.py` (Member 2) and `intel_agent.py` (Member 3) are **not touched**.
Then: `pip install -r requirements.txt` (adds `packaging`) and `python -m pytest` -> **89 passed**.

## Files

| File | Status | What |
|---|---|---|
| `app/core/config.py` | rewritten | Every tunable number (weights, thresholds, limits, LLM, intel mode) in one place, env-overridable |
| `app/core/schemas.py` | rewritten (additive) | Schema v2: all v1 fields kept, all new fields have defaults |
| `app/core/scoring.py` | rewritten | New formula + floors + `ScoreBreakdown`; `compute_utility_score()` signature still works |
| `app/core/remediation.py` | NEW | Upgrade effort, requirements.txt unified diff, PyPI check - no LLM |
| `app/services/orchestrator.py` | rewritten | Safe-suppression rules, scoped limitations, per-CVE error isolation, threads, progress |
| `app/services/repo_loader.py` | rewritten | Zip-bomb / zip-slip / symlink limits, git timeout, project-root detection |
| `app/services/jobs.py` | NEW | Background scan jobs + polling |
| `app/services/mock_intel.py` | NEW | Offline intel that actually reads `requirements.txt` |
| `app/agents/utility_agent.py` | rewritten | Structured remediation, retry/backoff, key in header, prompt fencing, caching |
| `app/api/routes.py`, `app/main.py` | rewritten | Job endpoints, safe errors, optional API key, validation, logging |
| `tests/*`, `demo_project/` | new/rewritten | `test_utility.py` was a copy of config.py - now real tests |
| `requirements.txt`, `.gitignore`, `.env.example` | new/updated | |

## Behaviour changes you should know about

1. **Suppression is now safe.** A CVE is `SUPPRESSED_NOISE` only if it is confirmed unreachable AND no blind spot applies:
   - dynamic constructs only count if they are in a file that imports *that* package (dynamic `import` counts globally);
   - transitive CVEs (`is_direct_dependency=False`) whose parent package is used -> `NEEDS_REVIEW`;
   - runtime packages (gunicorn, uvicorn, flask, ...) are never suppressed for "not imported";
   - no vulnerable symbols + package imported -> `NEEDS_REVIEW`.
2. **Scoring**: EPSS uses `epss ** 0.5` (or percentile if provided); criticality clamped to 0.7-1.5; reachable+KEV => at least 60 (CRITICAL);
   reachable+CVSS>=9 => at least 30 (MONITOR). Set `EPSS_EXPONENT=1` for the old linear behaviour.
3. **Zip uploads** descend through the wrapper folder (`my_project/app/...`) so `from app.x import y` resolves.
4. **`INTEL_MODE=mock` is the default** until Member 3 is done. Then set `INTEL_MODE=live` in `.env`.
5. `ScanRequest.repo_path` is now `repo_url` (old name still accepted as an alias).

## New / changed API

```
GET  /api/health                      open (never needs a key)
GET  /api/config                      active scoring model
POST /api/scan/github      {repo_url, business_criticality}   -> ScanReport   (blocking)
POST /api/scan/upload      multipart file + business_criticality (0.1-2.0) -> ScanReport
POST /api/jobs/github | /api/jobs/upload   -> 202 {scan_id, status}
GET  /api/jobs/{scan_id}   -> {status: queued|running|done|failed, stage, progress 0-1, report?, error?}
```
If `API_KEY` is set, all `/api/*` except health need header `X-API-Key`.

## Send these to the team

**Member 2** - `ast_agent.py` misses these real calls (each produces a false "unreachable"; probes in the chat):
1. Module-level assignment: `cfg = yaml.load(...)` (only bare `Expr` calls at module level are visited).
2. Variables typed inside `with` / `if` / `for` blocks (`pm = urllib3.PoolManager()` inside `with`), because `local_vars` is only filled for top-level statements of the function.
3. Instance calls: `S().run()`, `obj = S(); obj.run()`, and `self.helper()` chains resolve to `S.run` instead of `<module>.S.run`.
4. `src/` layout and package roots: `from app.x import y` vs module name `src.app.x`.
5. `IGNORED_DIRS` contains `build`, `env`, `test`, `dist` - real package names are skipped.
6. Return `ExtendedReachabilityResult.limitations` with the file in the text (`... at path.py:LINE`) - the orchestrator uses it to scope blind spots.

**Member 3** - fill these in `RawVulnerability` (all optional, but the safety rules need them):
`is_direct_dependency`, `introduced_via` (parent package names), `epss_percentile`, `cvss_vector`, `fetched_at`, `source`, `aliases`.
Use `INTEL_MODE=live` to switch the orchestrator over to your `ThreatIntelAgent`. Contract test: `mock_intel.py` shows the expected shape.

**Member 4** - use the job endpoints (start -> poll `/api/jobs/{id}` every ~500 ms). New fields to render:
`call_trace[]` (file, line_number, caller, callee, call_expression), `limitations`, `uncertainty_reasons`, `agent_trace`,
`score_breakdown`, `remediation.requirements_diff` / `pr_title` / `quick_win`, `tier_counts`, `needs_review_cves`.
Tiers: `CRITICAL_ACTION | MONITOR | LOW_RISK | NEEDS_REVIEW | SUPPRESSED_NOISE`. Report `needs_review_cves` separately in the benchmark:
`NEEDS_REVIEW` is NOT counted as noise reduction.

## Still open (not in Member 1's files)
- Node.js support (spec mentions it) - needs a tree-sitter based agent.
- Library-internal call graphs (real transitive reachability) - currently handled conservatively via `NEEDS_REVIEW`.
- SQLite persistence for jobs / EPSS cache (jobs are in-memory now).
- `benchmark/evaluate.py` and `ground_truth.json` are still empty placeholders.

---
# Update 2 - integration with Member 3's intel agent

Found by running M3's agent (HTTP mocked) through the orchestrator. Fixed on the orchestrator side so nothing depends on M3 first:

| Scenario | Before | After |
|---|---|---|
| pip-freeze file pins `requests` + `urllib3`; app imports only `requests` | urllib3 CVE **SUPPRESSED** | `NEEDS_REVIEW`, `introduced_via=["requests"]` (via PyPI `requires_dist`, `app/services/dep_graph.py`) |
| `package-lock.json` (npm) CVEs | all **SUPPRESSED** | `NEEDS_REVIEW` "Unsupported ecosystem" |
| `pyyaml>=5.1` style requirements | 0 CVEs, no hint | report.warnings: "N requirement line(s) NOT scanned" |
| bare advisory symbol `parse_url` vs the app's own `parse_url()` | falsely "reachable" | suppressed (sink must belong to the package) |
| advisory names no function (tier-d fallback) | full-confidence "reachable" | x0.6 confidence + caveat in `uncertainty_reasons` |
| EPSS / KEV feed down | silently 0.0 / not-KEV | needs M3 patch below (orchestrator already shows `analyze_with_warnings` output) |

New: `dep_graph_mode` (auto = online when INTEL_MODE=live), `conf_package_level`, `RawVulnerability.ecosystem` + `.symbol_source`, `pytest.ini`, requirements (+cvss, respx, pytest-asyncio).

## Member 3: apply `member3_intel_agent.patch` (backward compatible; all 21 of your tests still pass)
`git apply member3_intel_agent.patch`
1. Sets `ecosystem`, `symbol_source` (tier used), `source`, `fetched_at`, `aliases`, `cvss_vector` on every RawVulnerability.
2. New `analyze_with_warnings()` -> (vulns, warnings). Reports failed OSV lookups, EPSS/KEV outages, offline-fixture mode. `analyze_dependencies()` still works.
3. A failed OSV lookup is no longer cached for 24h as "no vulnerabilities".
Please also check that `app/agents/data/known_symbols.json` is committed (tier b silently does nothing without it).
Optional next: store EPSS `percentile` (the scoring already uses `epss_percentile` when present) and pick `fixed_version` for the branch the installed version is on (currently the first `fixed` event).
