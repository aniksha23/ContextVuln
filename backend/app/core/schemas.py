from pydantic import BaseModel, Field
from typing import List, Optional

class ScanRequest(BaseModel):
    repo_path: str = Field(..., description="Local filesystem path or cloned directory of target repository")
    business_criticality: float = Field(
        default=1.0,
        ge=0.1,
        le=2.0,
        description="Multiplier: 0.7 (Internal), 1.0 (Standard), 1.4 (Public Production)"
    )

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

class ReachabilityResult(BaseModel):
    """Output contract from Member 2 (AST Reachability Agent)."""
    is_reachable: bool
    confidence: float  # 1.0 = direct call, 0.75 = transitive call, 0.0 = unreachable
    call_path: List[str] = Field(default_factory=list)

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
    priority_tier: str        # "CRITICAL_ACTION", "MONITOR", "LOW_RISK", "SUPPRESSED_NOISE"
    ai_reasoning: str
    remediation_advice: str

class ScanReport(BaseModel):
    repo_path: str
    total_cves_found: int
    reachable_cves: int
    suppressed_cves: int
    noise_reduction_pct: float
    findings: List[VulnerabilityFinding]