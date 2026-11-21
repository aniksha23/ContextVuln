from fastapi import UploadFile
from app.core.schemas import ScanRequest, ScanReport, VulnerabilityFinding
from app.services.repo_loader import load_github_repo, load_uploaded_zip
from app.agents.intel_agent import ThreatIntelAgent
from app.agents.ast_agent import ASTReachabilityAgent
from app.agents.utility_agent import UtilityPrioritizationAgent


class ScanOrchestrator:
    def __init__(self):
        self.intel_agent = ThreatIntelAgent()
        self.utility_agent = UtilityPrioritizationAgent()

    async def scan_github(self, request: ScanRequest) -> ScanReport:
        with load_github_repo(request.repo_path) as target_dir:
            return await self._run_pipeline(
                target_dir=target_dir,
                display_name=request.repo_path,
                business_criticality=request.business_criticality,
            )

    async def scan_zip_upload(
        self, file: UploadFile, business_criticality: float = 1.0
    ) -> ScanReport:
        with load_uploaded_zip(file) as target_dir:
            return await self._run_pipeline(
                target_dir=target_dir,
                display_name=file.filename or "uploaded_archive.zip",
                business_criticality=business_criticality,
            )

    async def _run_pipeline(
        self, target_dir: str, display_name: str, business_criticality: float
    ) -> ScanReport:
        # Step 1: Agent 2 extracts dependencies & fetches CVEs + EPSS + symbols
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
                business_criticality=business_criticality,
                repo_path=target_dir,
            )
            findings.append(finding)

        findings.sort(key=lambda f: f.utility_score, reverse=True)

        total = len(findings)
        reachable_count = sum(1 for f in findings if f.is_reachable)
        suppressed_count = total - reachable_count
        noise_reduction = round((suppressed_count / total) * 100.0, 1) if total > 0 else 0.0

        return ScanReport(
            repo_path=display_name,
            total_cves_found=total,
            reachable_cves=reachable_count,
            suppressed_cves=suppressed_count,
            noise_reduction_pct=noise_reduction,
            findings=findings,
        )