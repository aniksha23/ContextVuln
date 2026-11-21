from app.core.schemas import ScanRequest, ScanReport, VulnerabilityFinding
from app.services.repo_loader import validate_repo_path
from app.agents.intel_agent import ThreatIntelAgent
from app.agents.ast_agent import ASTReachabilityAgent
from app.agents.utility_agent import UtilityPrioritizationAgent

class ScanOrchestrator:
    def __init__(self):
        self.intel_agent = ThreatIntelAgent()
        self.utility_agent = UtilityPrioritizationAgent()

    async def execute_scan(self, request: ScanRequest) -> ScanReport:
        target_dir = validate_repo_path(request.repo_path)

        # Step 1: Agent 2 extracts dependencies & fetches CVEs + EPSS + vulnerable symbols
        raw_vulns = await self.intel_agent.analyze_dependencies(target_dir)

        # Step 2: Agent 1 parses AST and builds the repository call graph
        ast_agent = ASTReachabilityAgent(target_dir)
        ast_agent.build_graph()

        # Step 3: Evaluate reachability per CVE and prioritize via Agent 3
        findings: list[VulnerabilityFinding] = []
        for vuln in raw_vulns:
            reachability = ast_agent.check_reachability(vuln.vulnerable_symbols)
            finding = await self.utility_agent.prioritize_and_explain(
                vuln=vuln,
                reachability=reachability,
                business_criticality=request.business_criticality,
            )
            findings.append(finding)

        # Sort highest utility score first
        findings.sort(key=lambda f: f.utility_score, reverse=True)

        total = len(findings)
        reachable_count = sum(1 for f in findings if f.is_reachable)
        suppressed_count = total - reachable_count
        noise_reduction = round((suppressed_count / total) * 100.0, 1) if total > 0 else 0.0

        return ScanReport(
            repo_path=request.repo_path,
            total_cves_found=total,
            reachable_cves=reachable_count,
            suppressed_cves=suppressed_count,
            noise_reduction_pct=noise_reduction,
            findings=findings,
        )