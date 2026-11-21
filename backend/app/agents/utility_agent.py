from app.core.schemas import RawVulnerability, ReachabilityResult, VulnerabilityFinding
from app.core.scoring import compute_utility_score

class UtilityPrioritizationAgent:
    async def prioritize_and_explain(
        self,
        vuln: RawVulnerability,
        reachability: ReachabilityResult,
        business_criticality: float = 1.0,
    ) -> VulnerabilityFinding:
        score, tier = compute_utility_score(
            reachability_conf=reachability.confidence,
            epss_score=vuln.epss_score,
            cvss_score=vuln.cvss_score,
            is_in_kev=vuln.is_in_kev,
            business_criticality=business_criticality,
        )

        # Day-1 deterministic reasoning (can be enriched with Gemini API in Phase 2)
        if reachability.is_reachable:
            hop_type = "Direct" if reachability.confidence >= 0.9 else "Transitive"
            reasoning = (
                f"{hop_type} execution path confirmed to vulnerable symbol(s) "
                f"{', '.join(vuln.vulnerable_symbols)}. EPSS exploit probability is "
                f"{vuln.epss_score * 100:.1f}%."
            )
            fix_target = vuln.fixed_version or "latest patched release"
            advice = f"Immediate upgrade required: bump {vuln.package_name} to {fix_target} and audit call sites."
        else:
            reasoning = (
                f"Vulnerable symbol(s) {', '.join(vuln.vulnerable_symbols)} are never "
                f"imported or invoked in the application AST call graph."
            )
            advice = f"Defer patch to routine maintenance; no reachable attack surface detected."

        return VulnerabilityFinding(
            cve_id=vuln.cve_id,
            package_name=vuln.package_name,
            installed_version=vuln.installed_version,
            fixed_version=vuln.fixed_version,
            vulnerable_symbols=vuln.vulnerable_symbols,
            is_reachable=reachability.is_reachable,
            reachability_confidence=reachability.confidence,
            call_path=reachability.call_path,
            cvss_score=vuln.cvss_score,
            epss_score=vuln.epss_score,
            is_in_kev=vuln.is_in_kev,
            utility_score=score,
            priority_tier=tier,
            ai_reasoning=reasoning,
            remediation_advice=advice,
        )