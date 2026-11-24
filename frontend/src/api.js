async function request(path, options = {}) {
  const response = await fetch(`/api${path}`, {
    ...options,
    signal: AbortSignal.timeout(310000),
  });
  const data = await response
    .json()
    .catch(() => ({ detail: "Server returned an unreadable response." }));
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail),
    );
  return data;
}

function mapTierToPriority(tier) {
  if (!tier) return "medium";
  if (tier === "CRITICAL_ACTION") return "high";
  if (tier === "LOW_RISK" || tier === "SUPPRESSED_NOISE") return "low";
  return "medium";
}

function mapReachabilityStatus(f) {
  if (f.is_reachable) return "reachable";
  if (f.priority_tier === "NEEDS_REVIEW") return "unknown";
  return "not_observed";
}

function adaptBackendReport(raw) {
  if (!raw || raw.summary) return raw;

  const findings = (raw.findings || []).map((f) => {
    const priority = mapTierToPriority(f.priority_tier);
    const status = mapReachabilityStatus(f);
    const sb = f.score_breakdown || {};
    const trace =
      f.call_trace && f.call_trace.length > 0
        ? f.call_trace.map((step) => ({
            caller: step.caller || "entry",
            callee: step.callee || step.call_expression || "target",
            file: step.file || "source.py",
            line: step.line || step.lineno || 1,
          }))
        : (f.call_path || []).map((node) => ({
            caller: node,
            callee: "->",
            file: "call_graph",
            line: 1,
          }));

    return {
      id: `${f.cve_id}-${f.package_name}`,
      priority,
      score: Number(f.utility_score || 0),
      explanation:
        f.ai_reasoning || "Prioritized via MAUT threat and reachability signals.",
      remediation:
        f.remediation_advice ||
        (f.fixed_version
          ? `Upgrade ${f.package_name} to ${f.fixed_version}.`
          : "Review dependency usage."),
      review_required: f.uncertainty_reasons || [],
      llm_report: f.remediation?.code_patch || null,
      contributions: {
        epss_signal: Number(sb.epss_signal || 0) * 10,
        cvss_signal: Number(sb.cvss_signal || 0) * 10,
        kev_signal: Number(sb.kev_signal || 0) * 10,
        reachability:
          Number(sb.reachability_factor || f.reachability_confidence || 0) * 10,
      },
      vulnerability: {
        id: f.cve_id,
        aliases: [],
        package: f.package_name,
        version: f.installed_version,
        summary: f.summary || `${f.package_name} vulnerability (${f.cve_id})`,
        cvss: f.cvss_score ?? null,
        epss: f.epss_score ?? null,
        kev: Boolean(f.is_in_kev),
        mapping_source: f.symbol_source || "OSV / Curated Symbol Map",
        symbols: f.vulnerable_symbols || [],
        epss_date: f.data_fetched_at ? f.data_fetched_at.slice(0, 10) : null,
        references: [],
        evidence: [
          {
            source: f.data_source || "OSV + FIRST EPSS + CISA KEV",
            status: "verified",
            retrieved_at:
              f.data_fetched_at || raw.scanned_at || new Date().toISOString(),
            detail: f.fixed_version
              ? `Fixed in ${f.fixed_version}`
              : "No fixed version listed",
          },
        ],
      },
      reachability: {
        status,
        confidence: Number(f.reachability_confidence || 0),
        depth: Number(f.search_depth || trace.length || 0),
        trace,
        limitations: f.limitations || [],
      },
    };
  });

  const uniquePackages = new Set(findings.map((f) => f.vulnerability.package));
  const total = Number(raw.total_cves_found ?? findings.length);
  const lowCount = findings.filter((f) => f.priority === "low").length;

  return {
    id: raw.scan_id || `scan-${Date.now()}`,
    mode: "live",
    project: raw.repo_path || "GitHub Repository",
    created_at: raw.scanned_at || new Date().toISOString(),
    dependencies: Array.from(uniquePackages),
    files_analyzed: raw.files_analyzed || 0,
    graph_nodes: findings.length * 3,
    graph_edges: findings.length * 2,
    warnings: raw.warnings || [],
    summary: {
      total,
      high: findings.filter((f) => f.priority === "high").length,
      reachable: Number(
        raw.reachable_cves ??
          findings.filter((f) => f.reachability.status === "reachable").length,
      ),
      unknown: Number(
        raw.needs_review_cves ??
          findings.filter((f) => f.reachability.status === "unknown").length,
      ),
      alert_reduction_rate:
        raw.noise_reduction_pct != null
          ? Number(raw.noise_reduction_pct) / 100
          : total > 0
            ? lowCount / total
            : 0,
    },
    findings,
  };
}

export const demoScan = () =>
  fetch("/report.json")
    .then((r) => r.json())
    .then(adaptBackendReport);

export const scanPath = (data) =>
  request("/scan/github", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo_url: data.path,
      business_criticality: Number(data.criticality || 1.0),
    }),
  }).then(adaptBackendReport);

export const scanZip = (file, criticality = 1.0) => {
  const form = new FormData();
  form.append("file", file);
  form.append("business_criticality", String(criticality));
  return request("/scan/upload", { method: "POST", body: form }).then(
    adaptBackendReport,
  );
};

export function exportReport(report) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `contextvuln-${report.id || "report"}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
