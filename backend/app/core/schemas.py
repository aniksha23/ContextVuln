"""
ContextVuln data contracts  -  SCHEMA v2.

Rules for teammates:
  * v2 is ADDITIVE: every v1 field is still here with the same meaning, every new
    field has a default, so Member 2 / 3 / 4 code written against v1 keeps working.
  * Member 3 returns RawVulnerability, Member 2 returns ReachabilityResult.
  * The frontend (Member 4) consumes ScanReport / VulnerabilityFinding / ScanJob.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import AliasChoices, BaseModel, Field


class Tier(str, Enum):
    CRITICAL_ACTION = "CRITICAL_ACTION"
    MONITOR = "MONITOR"
    LOW_RISK = "LOW_RISK"
    NEEDS_REVIEW = "NEEDS_REVIEW"          # analysis inconclusive -> never auto-suppressed
    SUPPRESSED_NOISE = "SUPPRESSED_NOISE"  # confirmed unreachable


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ----------------------------------------------------------------------------
# Requests
# ----------------------------------------------------------------------------
class ScanRequest(BaseModel):
    # `repo_path` is still accepted as an alias so old clients keep working.
    repo_url: str = Field(
        ...,
        validation_alias=AliasChoices("repo_url", "repo_path"),
        description="Public GitHub repository URL, e.g. https://github.com/org/repo",
    )
    business_criticality: float = Field(
        default=1.0,
        ge=0.1,
        le=2.0,
        description="Multiplier: 0.7 (Internal), 1.0 (Standard), 1.4 (Public Production)",
    )


# ----------------------------------------------------------------------------
# Agent 2 (Threat Intel, Member 3) -> orchestrator
# ----------------------------------------------------------------------------
class RawVulnerability(BaseModel):
    """Output contract from Member 3 (Threat Intel Agent)."""
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    vulnerable_symbols: List[str] = Field(default_factory=list)
    cvss_score: float = 0.0
    epss_score: float = 0.0
    is_in_kev: bool = False
    summary: str = ""

    # ---- v2 additions (all optional) ----
    cvss_vector: Optional[str] = None
    epss_percentile: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # False => package is only pulled in by another package (e.g. urllib3 via requests).
    # Library internals are NOT analysed by the AST agent, so such CVEs are never auto-suppressed
    # when the parent package is used by the app.
    is_direct_dependency: bool = True
    introduced_via: List[str] = Field(default_factory=list)  # parent package names
    aliases: List[str] = Field(default_factory=list)         # GHSA-..., PYSEC-...
    references: List[str] = Field(default_factory=list)
    source: str = ""                                          # "osv.dev", "mock", ...
    fetched_at: Optional[datetime] = None                     # provenance timestamp


# ----------------------------------------------------------------------------
# Agent 1 (AST, Member 2) -> orchestrator
# ----------------------------------------------------------------------------
class ReachabilityResult(BaseModel):
    """Output contract from Member 2 (AST Reachability Agent)."""
    is_reachable: bool
    confidence: float  # 1.0 = direct call, 0.7 = transitive call, 0.0 = unreachable
    call_path: List[str] = Field(default_factory=list)


# ----------------------------------------------------------------------------
# Agent 3 output pieces
# ----------------------------------------------------------------------------
class RemediationPlan(BaseModel):
    upgrade_to: Optional[str] = None
    upgrade_effort: str = "unknown"            # patch | minor | major | unknown
    requirements_diff: str = ""                # unified diff, built deterministically
    pr_title: str = ""
    code_patch: str = ""                       # optional, LLM-written, reachable CVEs only
    mitigations: List[str] = Field(default_factory=list)
    version_validated: Optional[bool] = None   # None = not checked / unknown
    quick_win: bool = False                    # reachable + patch/minor upgrade available


class ScoreBreakdown(BaseModel):
    """Makes the utility score explainable (and testable)."""
    epss_signal: float = 0.0
    cvss_signal: float = 0.0
    kev_signal: float = 0.0
    weighted_threat: float = 0.0
    reachability_factor: float = 0.0
    criticality_factor: float = 1.0
    raw_score: float = 0.0
    floor_applied: Optional[str] = None
    notes: List[str] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    """Final enriched finding returned to Frontend."""
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    vulnerable_symbols: List[str]

    # Reachability (Agent 1)
    is_reachable: bool
    reachability_confidence: float
    call_path: List[str]

    # Threat Intel (Agent 2)
    cvss_score: float
    epss_score: float
    is_in_kev: bool

    # Prioritization & Remediation (Agent 3)
    utility_score: float      # 0.0 to 100.0
    priority_tier: str        # value of Tier
    ai_reasoning: str
    remediation_advice: str

    # ---- v2 additions ----
    summary: str = ""
    call_trace: List[Dict[str, Any]] = Field(default_factory=list)   # file / line / caller / callee / expression
    search_depth: int = 0
    limitations: List[str] = Field(default_factory=list)             # AST blind spots relevant to this package
    uncertainty_reasons: List[str] = Field(default_factory=list)
    agent_trace: List[str] = Field(default_factory=list)             # e.g. ast_check -> investigate_ambiguity -> ...
    score_breakdown: Optional[ScoreBreakdown] = None
    remediation: Optional[RemediationPlan] = None
    is_direct_dependency: bool = True
    introduced_via: List[str] = Field(default_factory=list)
    epss_percentile: Optional[float] = None
    data_source: str = ""
    data_fetched_at: Optional[datetime] = None


class ScanReport(BaseModel):
    repo_path: str
    total_cves_found: int
    reachable_cves: int
    suppressed_cves: int
    noise_reduction_pct: float
    findings: List[VulnerabilityFinding]

    # ---- v2 additions ----
    scan_id: str = ""
    scanned_at: datetime = Field(default_factory=utcnow)
    duration_s: float = 0.0
    needs_review_cves: int = 0
    tier_counts: Dict[str, int] = Field(default_factory=dict)
    files_analyzed: int = 0
    warnings: List[str] = Field(default_factory=list)
    intel_mode: str = ""
    llm_used: bool = False


# ----------------------------------------------------------------------------
# Background job model (for the polling API)
# ----------------------------------------------------------------------------
class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class ScanJob(BaseModel):
    scan_id: str
    status: JobStatus = JobStatus.QUEUED
    stage: str = "queued"
    progress: float = 0.0              # 0.0 - 1.0
    created_at: datetime = Field(default_factory=utcnow)
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    report: Optional[ScanReport] = None
