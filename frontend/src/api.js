/**
 * ContextVuln API Client & Data Adapter (Schema v2)
 */

const API_BASE = '/api';

/**
 * Perform a fetch request to the backend with error extraction.
 */
async function request(path, options = {}) {
  const apiKey = localStorage.getItem('contextvuln_api_key') || '';
  const headers = {
    ...(options.headers || {}),
  };
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => ({
    detail: 'Server returned an unreadable response.',
  }));

  if (!response.ok) {
    const errorMsg =
      typeof data.detail === 'string'
        ? data.detail
        : typeof data.message === 'string'
          ? data.message
          : JSON.stringify(data.detail || data);
    const err = new Error(errorMsg);
    err.status = response.status;
    throw err;
  }
  return data;
}

/**
 * Check backend health & capabilities.
 */
export async function checkBackendHealth() {
  try {
    const data = await request('/health');
    return {
      online: true,
      service: data.service || 'contextvuln-backend',
      intelMode: data.intel_mode || 'mock',
      llmConfigured: Boolean(data.llm_configured),
    };
  } catch (e) {
    return {
      online: false,
      error: e.message,
      intelMode: 'unknown',
      llmConfigured: false,
    };
  }
}

/**
 * Fetch active scoring model & weights configuration.
 */
export async function fetchScoringConfig() {
  return request('/config');
}

/**
 * Maps backend Tier enum to display metadata.
 */
export function getTierMeta(tier) {
  switch (tier) {
    case 'CRITICAL_ACTION':
      return {
        id: 'CRITICAL_ACTION',
        label: 'Critical Action',
        shortLabel: 'Critical',
        badgeClass: 'tier-critical',
        description: 'Verified reachable or active in CISA KEV. Requires immediate remediation.',
        color: '#b91c1c',
        bg: '#fef2f2',
        border: '#fecaca',
      };
    case 'MONITOR':
      return {
        id: 'MONITOR',
        label: 'Monitor',
        shortLabel: 'Monitor',
        badgeClass: 'tier-monitor',
        description: 'Moderate threat or high CVSS. Monitored for active exploitation.',
        color: '#b45309',
        bg: '#fffbeb',
        border: '#fde68a',
      };
    case 'LOW_RISK':
      return {
        id: 'LOW_RISK',
        label: 'Low Risk',
        shortLabel: 'Low',
        badgeClass: 'tier-low',
        description: 'Reachable code path but low severity and negligible EPSS probability.',
        color: '#15803d',
        bg: '#f0fdf4',
        border: '#bbf7d0',
      };
    case 'NEEDS_REVIEW':
      return {
        id: 'NEEDS_REVIEW',
        label: 'Needs Review',
        shortLabel: 'Review',
        badgeClass: 'tier-review',
        description: 'Inconclusive reachability (dynamic imports, transitive call, or missing symbol map). NEVER auto-suppressed.',
        color: '#6d28d9',
        bg: '#f5f3ff',
        border: '#ddd6fe',
      };
    case 'SUPPRESSED_NOISE':
      return {
        id: 'SUPPRESSED_NOISE',
        label: 'Suppressed Noise',
        shortLabel: 'Suppressed',
        badgeClass: 'tier-suppressed',
        description: 'Confirmed unreachable dead code in this repository. Safely filtered from triage.',
        color: '#475569',
        bg: '#f1f5f9',
        border: '#cbd5e1',
      };
    default:
      return {
        id: tier || 'UNKNOWN',
        label: tier || 'Unknown',
        shortLabel: tier || 'Unknown',
        badgeClass: 'tier-default',
        description: 'Unclassified tier.',
        color: '#64748b',
        bg: '#f8fafc',
        border: '#e2e8f0',
      };
  }
}

/**
 * Adapter ensuring consistent Schema v2 structures for both live backend and demo fixtures.
 */
export function adaptBackendReport(raw) {
  if (!raw) return null;

  const rawFindings = raw.findings || [];

  const findings = rawFindings.map((f) => {
    // Determine canonical tier
    let tier = f.priority_tier;
    if (!tier) {
      if (f.priority === 'high') tier = 'CRITICAL_ACTION';
      else if (f.priority === 'low') tier = 'SUPPRESSED_NOISE';
      else if (f.reachability?.status === 'unknown') tier = 'NEEDS_REVIEW';
      else tier = 'MONITOR';
    }

    const tierMeta = getTierMeta(tier);

    // Reachability
    const isReachable =
      f.is_reachable ??
      (f.reachability?.status === 'reachable' || tier === 'CRITICAL_ACTION');

    const reachabilityStatus =
      f.reachability?.status ||
      (isReachable
        ? 'reachable'
        : tier === 'NEEDS_REVIEW'
          ? 'unknown'
          : 'not_observed');

    // Call trace parsing with line, caller, callee, and call_expression
    const rawTrace = f.call_trace || f.reachability?.trace || [];
    const callTrace = rawTrace.map((step, idx) => ({
      caller: step.caller || (idx === 0 ? 'entry' : 'function'),
      callee: step.callee || step.call_expression || 'target',
      file: step.file || 'source.py',
      line: step.line || step.lineno || 1,
      call_expression: step.call_expression || step.expression || null,
    }));

    // Remediation plan
    const rawRemediation = f.remediation || {};
    const remediationPlan = {
      upgrade_to: rawRemediation.upgrade_to || f.fixed_version || (f.vulnerability?.fixed_versions?.[0] ?? null),
      upgrade_effort: rawRemediation.upgrade_effort || 'unknown',
      requirements_diff: rawRemediation.requirements_diff || '',
      pr_title: rawRemediation.pr_title || '',
      code_patch: rawRemediation.code_patch || f.llm_report || null,
      mitigations: rawRemediation.mitigations || [],
      quick_win: Boolean(rawRemediation.quick_win),
      version_validated: rawRemediation.version_validated ?? null,
    };

    // Score breakdown
    const rawSb = f.score_breakdown || {};
    const rawContribs = f.contributions || {};
    const scoreBreakdown = {
      epss_signal: Number(rawSb.epss_signal ?? rawContribs.exploitability ?? 0),
      cvss_signal: Number(rawSb.cvss_signal ?? rawContribs.severity ?? 0),
      kev_signal: Number(rawSb.kev_signal ?? rawContribs.known_exploitation ?? 0),
      reachability_factor: Number(rawSb.reachability_factor ?? rawContribs.reachability ?? 0),
      criticality_factor: Number(rawSb.criticality_factor ?? rawContribs.criticality ?? 1.0),
      weighted_threat: Number(rawSb.weighted_threat ?? 0),
      raw_score: Number(rawSb.raw_score ?? f.utility_score ?? f.score ?? 0),
      floor_applied: rawSb.floor_applied || null,
      notes: rawSb.notes || [],
    };

    const cveId = f.cve_id || f.vulnerability?.id || 'CVE-UNKNOWN';
    const pkg = f.package_name || f.vulnerability?.package || 'package';
    const installedVer = f.installed_version || f.vulnerability?.version || '0.0.0';

    return {
      id: `${cveId}-${pkg}-${installedVer}`,
      cve_id: cveId,
      package_name: pkg,
      installed_version: installedVer,
      fixed_version: remediationPlan.upgrade_to,
      vulnerable_symbols: f.vulnerable_symbols || f.vulnerability?.symbols || [],
      is_direct_dependency: f.is_direct_dependency ?? true,
      introduced_via: f.introduced_via || [],
      ecosystem: f.ecosystem || f.vulnerability?.ecosystem || 'PyPI',
      symbol_source: f.symbol_source || f.vulnerability?.mapping_source || 'OSV',
      data_source: f.data_source || 'OSV + FIRST EPSS + CISA KEV',
      data_fetched_at: f.data_fetched_at || null,

      // Reachability
      is_reachable: isReachable,
      reachability_confidence: Number(f.reachability_confidence ?? f.reachability?.confidence ?? 0),
      reachability_status: reachabilityStatus,
      call_path: f.call_path || (callTrace.length ? callTrace.map((c) => c.caller) : []),
      call_trace: callTrace,
      search_depth: Number(f.search_depth ?? f.reachability?.depth ?? callTrace.length),
      limitations: f.limitations || f.reachability?.limitations || [],
      uncertainty_reasons: f.uncertainty_reasons || f.review_required || [],

      // Threat metrics
      cvss_score: f.cvss_score ?? f.vulnerability?.cvss ?? null,
      cvss_vector: f.cvss_vector || null,
      epss_score: f.epss_score ?? f.vulnerability?.epss ?? null,
      epss_percentile: f.epss_percentile ?? null,
      is_in_kev: Boolean(f.is_in_kev ?? f.vulnerability?.kev),

      // Prioritization
      utility_score: Number(f.utility_score ?? f.score ?? 0),
      priority_tier: tier,
      tier_meta: tierMeta,
      summary: f.summary || f.vulnerability?.summary || `${pkg} vulnerability (${cveId})`,
      ai_reasoning: f.ai_reasoning || f.explanation || 'Prioritized based on reachability and threat indicators.',
      remediation_advice: f.remediation_advice || f.remediation || 'Upgrade dependency to safe version.',
      agent_trace: f.agent_trace || [],
      score_breakdown: scoreBreakdown,
      remediation: remediationPlan,

      // Legacy compatibility mappings
      priority: tierMeta.shortLabel.toLowerCase(),
      score: Number(f.utility_score ?? f.score ?? 0),
      explanation: f.ai_reasoning || f.explanation || '',
      vulnerability: {
        id: cveId,
        package: pkg,
        version: installedVer,
        summary: f.summary || f.vulnerability?.summary || '',
        cvss: f.cvss_score ?? f.vulnerability?.cvss ?? null,
        epss: f.epss_score ?? f.vulnerability?.epss ?? null,
        kev: Boolean(f.is_in_kev ?? f.vulnerability?.kev),
        symbols: f.vulnerable_symbols || f.vulnerability?.symbols || [],
        aliases: f.aliases || f.vulnerability?.aliases || [],
        mapping_source: f.symbol_source || f.vulnerability?.mapping_source || 'OSV',
        references: f.references || f.vulnerability?.references || [],
        evidence: f.vulnerability?.evidence || [
          {
            source: f.data_source || 'OSV + FIRST EPSS + CISA KEV',
            status: 'verified',
            retrieved_at: f.data_fetched_at || raw.scanned_at || new Date().toISOString(),
            detail: remediationPlan.upgrade_to ? `Fixed in ${remediationPlan.upgrade_to}` : 'No fixed version listed',
          },
        ],
      },
      reachability: {
        status: reachabilityStatus,
        confidence: Number(f.reachability_confidence ?? f.reachability?.confidence ?? 0),
        depth: Number(f.search_depth ?? f.reachability?.depth ?? callTrace.length),
        trace: callTrace,
        limitations: f.limitations || f.reachability?.limitations || [],
      },
      contributions: {
        severity: scoreBreakdown.cvss_signal,
        exploitability: scoreBreakdown.epss_signal,
        reachability: scoreBreakdown.reachability_factor,
        known_exploitation: scoreBreakdown.kev_signal,
        criticality: scoreBreakdown.criticality_factor,
      },
    };
  });

  // Calculate tier counts
  const tierCounts = {
    CRITICAL_ACTION: 0,
    MONITOR: 0,
    LOW_RISK: 0,
    NEEDS_REVIEW: 0,
    SUPPRESSED_NOISE: 0,
    ...(raw.tier_counts || {}),
  };

  if (!raw.tier_counts) {
    findings.forEach((f) => {
      if (tierCounts[f.priority_tier] !== undefined) {
        tierCounts[f.priority_tier]++;
      }
    });
  }

  const total = Number(raw.total_cves_found ?? findings.length);
  const reachableCount = Number(
    raw.reachable_cves ??
      findings.filter((f) => f.reachability_status === 'reachable').length
  );
  const suppressedCount = Number(
    raw.suppressed_cves ??
      tierCounts.SUPPRESSED_NOISE ??
      findings.filter((f) => f.priority_tier === 'SUPPRESSED_NOISE').length
  );
  const needsReviewCount = Number(
    raw.needs_review_cves ??
      tierCounts.NEEDS_REVIEW ??
      findings.filter((f) => f.priority_tier === 'NEEDS_REVIEW').length
  );

  const noiseReductionPct =
    raw.noise_reduction_pct != null
      ? Number(raw.noise_reduction_pct)
      : total > 0
        ? Math.round((suppressedCount / total) * 100)
        : 0;

  const uniquePackages = Array.from(
    new Set(findings.map((f) => f.package_name))
  );

  return {
    id: raw.scan_id || `scan-${Date.now()}`,
    mode: raw.mode || (raw.intel_mode === 'mock' ? 'mock' : 'live'),
    project: raw.repo_path || raw.project || 'Project Scan',
    created_at: raw.scanned_at || raw.created_at || new Date().toISOString(),
    duration_s: Number(raw.duration_s || 0),
    files_analyzed: Number(raw.files_analyzed || 0),
    graph_nodes: Number(raw.graph_nodes || findings.length * 3),
    graph_edges: Number(raw.graph_edges || findings.length * 2),
    intel_mode: raw.intel_mode || 'mock',
    llm_used: Boolean(raw.llm_used),
    warnings: raw.warnings || [],
    dependencies: uniquePackages,
    tier_counts: tierCounts,
    summary: {
      total,
      reachable: reachableCount,
      suppressed: suppressedCount,
      unknown: needsReviewCount,
      high: tierCounts.CRITICAL_ACTION,
      noise_reduction_pct: noiseReductionPct,
      alert_reduction_rate: noiseReductionPct / 100,
    },
    findings,
  };
}

/**
 * Poll background scan job until completion.
 */
export async function pollJob(scanId, onProgress, signal) {
  const pollIntervalMs = 500;
  while (!signal?.aborted) {
    const job = await request(`/jobs/${scanId}`);

    if (onProgress && typeof onProgress === 'function') {
      onProgress({
        scanId: job.scan_id,
        status: job.status,
        stage: job.stage || 'scanning',
        progress: job.progress || 0.0,
      });
    }

    if (job.status === 'done') {
      if (!job.report) {
        throw new Error('Scan finished but no report payload was returned.');
      }
      return adaptBackendReport(job.report);
    }

    if (job.status === 'failed') {
      throw new Error(job.error || 'Scan job failed on the backend.');
    }

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
  throw new Error('Scan was cancelled.');
}

/**
 * Scan GitHub repository using Job API (with graceful fallback).
 */
export async function scanGithubWithJob(data, onProgress, signal) {
  try {
    const job = await request('/jobs/github', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo_url: data.path,
        business_criticality: Number(data.criticality || 1.0),
      }),
    });
    return await pollJob(job.scan_id, onProgress, signal);
  } catch (err) {
    // If jobs endpoint is not implemented or 404, fallback to direct scan
    if (err.status === 404 || err.status === 405) {
      if (onProgress) onProgress({ status: 'running', stage: 'scanning repository...', progress: 0.5 });
      const raw = await request('/scan/github', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: data.path,
          business_criticality: Number(data.criticality || 1.0),
        }),
      });
      return adaptBackendReport(raw);
    }
    throw err;
  }
}

/**
 * Scan uploaded zip archive using Job API (with graceful fallback).
 */
export async function scanZipWithJob(file, criticality = 1.0, onProgress, signal) {
  const form = new FormData();
  form.append('file', file);
  form.append('business_criticality', String(criticality));

  try {
    const job = await request('/jobs/upload', {
      method: 'POST',
      body: form,
    });
    return await pollJob(job.scan_id, onProgress, signal);
  } catch (err) {
    if (err.status === 404 || err.status === 405) {
      if (onProgress) onProgress({ status: 'running', stage: 'analyzing uploaded archive...', progress: 0.5 });
      const raw = await request('/scan/upload', {
        method: 'POST',
        body: form,
      });
      return adaptBackendReport(raw);
    }
    throw err;
  }
}

/**
 * Offline demo scan loader.
 */
export async function demoScan() {
  const res = await fetch('/report.json');
  if (!res.ok) {
    throw new Error('Failed to load demo report fixture.');
  }
  const raw = await res.json();
  return adaptBackendReport(raw);
}

/**
 * Export JSON report.
 */
export function exportReportJson(report) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
  );
  const a = document.createElement('a');
  a.href = url;
  a.download = `contextvuln-${report.id || 'report'}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/**
 * Export formatted Markdown report for AppSec triage & PR tickets.
 */
export function exportReportMarkdown(report) {
  const s = report.summary || {};
  const tc = report.tier_counts || {};

  let md = `# ContextVuln Security Triage Report\n\n`;
  md += `**Target:** \`${report.project}\`  \n`;
  md += `**Scan Date:** ${new Date(report.created_at).toUTCString()}  \n`;
  md += `**Scan Duration:** ${report.duration_s ? `${report.duration_s.toFixed(2)}s` : 'N/A'}  \n`;
  md += `**Intel Mode:** \`${report.intel_mode}\` | **LLM Reasoning:** ${report.llm_used ? 'Enabled (Gemini)' : 'Disabled'}  \n\n`;

  md += `## Executive Summary\n\n`;
  md += `ContextVuln parsed **${report.files_analyzed}** source files and evaluated **${s.total}** dependency alerts.\n\n`;
  md += `| Metric | Count | Description |\n`;
  md += `| :--- | :--- | :--- |\n`;
  md += `| **Critical Action** | ${tc.CRITICAL_ACTION || s.high || 0} | Verified reachable or active in CISA KEV |\n`;
  md += `| **Monitor** | ${tc.MONITOR || 0} | Reachable / high CVSS advisories requiring attention |\n`;
  md += `| **Needs Review** | ${tc.NEEDS_REVIEW || s.unknown || 0} | Inconclusive reachability (never auto-suppressed) |\n`;
  md += `| **Low Risk** | ${tc.LOW_RISK || 0} | Low exploitability / severity |\n`;
  md += `| **Suppressed Noise** | ${tc.SUPPRESSED_NOISE || s.suppressed || 0} | Confirmed unreachable dead code |\n`;
  md += `| **Noise Reduction** | **${s.noise_reduction_pct || 0}%** | Irrelevant alerts safely eliminated |\n\n`;

  md += `## Prioritized Vulnerability Findings\n\n`;

  report.findings.forEach((f, idx) => {
    md += `### ${idx + 1}. [${f.tier_meta.label.toUpperCase()}] ${f.cve_id} - ${f.package_name} \`${f.installed_version}\`\n\n`;
    md += `- **Utility Score:** **${f.utility_score.toFixed(1)} / 100**\n`;
    md += `- **CVSS Severity:** ${f.cvss_score ?? 'N/A'}${f.cvss_vector ? ` (\`${f.cvss_vector}\`)` : ''}\n`;
    md += `- **EPSS Exploitability:** ${f.epss_score != null ? `${(f.epss_score * 100).toFixed(2)}%` : 'N/A'}${f.epss_percentile ? ` (${Math.round(f.epss_percentile * 100)}th percentile)` : ''}\n`;
    md += `- **CISA KEV Listed:** ${f.is_in_kev ? '🚨 **YES (Active In-The-Wild Exploitation)**' : 'No'}\n`;
    md += `- **AST Reachability:** \`${f.reachability_status}\` (Confidence: ${Math.round(f.reachability_confidence * 100)}%)\n`;
    md += `- **Dependency Lineage:** ${f.is_direct_dependency ? 'Direct Dependency' : `Transitive (introduced via ${f.introduced_via.join(', ') || 'parent'})`}\n\n`;

    md += `**Summary:** ${f.summary}\n\n`;
    md += `**Triage Analysis:** ${f.ai_reasoning}\n\n`;

    if (f.call_trace && f.call_trace.length > 0) {
      md += `**AST Call Trace:**\n\`\`\`\n`;
      f.call_trace.forEach((step, stepIdx) => {
        md += `${stepIdx + 1}. ${step.caller} -> ${step.callee} (${step.file}:${step.line})\n`;
        if (step.call_expression) {
          md += `   Expression: ${step.call_expression}\n`;
        }
      });
      md += `\`\`\`\n\n`;
    }

    if (f.remediation?.requirements_diff) {
      md += `**Remediation Requirements Diff:**\n\`\`\`diff\n${f.remediation.requirements_diff}\n\`\`\`\n\n`;
    }

    if (f.remediation?.pr_title) {
      md += `**Recommended PR Title:** \`${f.remediation.pr_title}\`\n\n`;
    }

    if (f.uncertainty_reasons?.length > 0) {
      md += `**Review Required / Limitations:**\n`;
      f.uncertainty_reasons.forEach((r) => {
        md += `- ${r}\n`;
      });
      md += `\n`;
    }

    md += `---\n\n`;
  });

  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `contextvuln-triage-${report.id || 'report'}.md`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
