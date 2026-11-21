import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable, Dict, List, Optional
from fastapi import UploadFile

from app.core.schemas import (
    RawVulnerability,
    ReachabilityResult,
    ScanRequest,
    ScanReport,
    VulnerabilityFinding,
)
from app.core.scoring import compute_utility_score
from app.services.repo_loader import load_github_repo, load_uploaded_zip
from app.agents.intel_agent import ThreatIntelAgent
from app.agents.ast_agent import ASTReachabilityAgent
from app.agents.utility_agent import UtilityPrioritizationAgent

logger = logging.getLogger(__name__)


class NodeName(str, Enum):
    AST_CHECK = "ast_check"
    INVESTIGATE_AMBIGUITY = "investigate_ambiguity"
    DEEP_UTILITY = "deep_utility"
    NEEDS_REVIEW = "needs_review"
    FAST_PATH_SUPPRESS = "fast_path_suppress"
    END = "end"


@dataclass
class CVEState:
    """Shared mutable state passed across nodes in the cyclic CVE state machine."""
    repo_path: str
    business_criticality: float
    vuln: RawVulnerability
    candidate_symbols: List[str] = field(default_factory=list)
    reachability: Optional[ReachabilityResult] = None
    limitations: List[str] = field(default_factory=list)
    has_uncertainty: bool = False
    uncertainty_reasons: List[str] = field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 1
    no_new_symbols_found: bool = False
    trace: List[str] = field(default_factory=list)
    finding: Optional[VulnerabilityFinding] = None


class ScanOrchestrator:
    """
    Pure-Python Cyclic Multi-Agent State Machine Orchestrator.

    Graph Topology per CVE:
      AST_CHECK
        ├── reachable == True                      -> DEEP_UTILITY -> END
        ├── uncertain & retries left               -> INVESTIGATE_AMBIGUITY -> AST_CHECK (cycle)
        ├── uncertain & retries exhausted/no leads -> NEEDS_REVIEW -> END
        └── confirmed unreachable (0 limitations)  -> FAST_PATH_SUPPRESS -> END
    """

    def __init__(self, max_retries: int = 1, max_concurrency: int = 6):
        self.intel_agent = ThreatIntelAgent()
        self.utility_agent = UtilityPrioritizationAgent()
        self.max_retries = max_retries
        self.max_concurrency = max_concurrency

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

    # ------------------------------------------------------------------
    # State Machine Nodes
    # ------------------------------------------------------------------

    async def _node_ast_check(
        self, state: CVEState, ast_agent: ASTReachabilityAgent
    ) -> NodeName:
        """Node 1: Deterministic AST reachability verification (Member 2 / Agent 1)."""
        symbols = state.candidate_symbols

        if not symbols:
            reason = "No vulnerable symbols extracted from advisory."
            if reason not in state.uncertainty_reasons:
                state.uncertainty_reasons.append(reason)
            state.reachability = ReachabilityResult(
                is_reachable=False, confidence=0.0, call_path=[]
            )
            state.limitations = list(getattr(ast_agent, "limitations", []))
            state.has_uncertainty = True
        else:
            result = ast_agent.check_reachability(symbols)
            dynamic_limitations = list(getattr(result, "limitations", []))

            if dynamic_limitations:
                reason = (
                    f"Dynamic constructs detected ({len(dynamic_limitations)}): "
                    f"{dynamic_limitations[0]}"
                )
                if reason not in state.uncertainty_reasons:
                    state.uncertainty_reasons.append(reason)

            state.reachability = result
            state.limitations = dynamic_limitations
            state.has_uncertainty = state.has_uncertainty or len(dynamic_limitations) > 0

        return self._route_after_ast(state)

    def _route_after_ast(self, state: CVEState) -> NodeName:
        """4-way conditional router deciding the next agent transition."""
        if state.reachability and state.reachability.is_reachable:
            return NodeName.DEEP_UTILITY

        if state.has_uncertainty:
            if state.retry_count < state.max_retries and not state.no_new_symbols_found:
                return NodeName.INVESTIGATE_AMBIGUITY
            return NodeName.NEEDS_REVIEW

        return NodeName.FAST_PATH_SUPPRESS

    async def _node_investigate_ambiguity(
        self, state: CVEState, _ast_agent: ASTReachabilityAgent
    ) -> NodeName:
        """Node 2: Cyclic Gemini candidate symbol discovery -> loops back to AST_CHECK."""
        previous_set = set(state.candidate_symbols)
        expanded = await self.utility_agent.resolve_ambiguous_symbols(
            vuln=state.vuln,
            existing_symbols=state.candidate_symbols,
            limitations=state.limitations,
        )
        state.retry_count += 1
        state.candidate_symbols = expanded

        # Short-circuit directly to NEEDS_REVIEW if Gemini produced no new candidate symbols
        if set(expanded) == previous_set:
            state.no_new_symbols_found = True
            return NodeName.NEEDS_REVIEW

        # Cycle back to Agent 1 to deterministically verify the new candidate symbols
        return NodeName.AST_CHECK

    async def _node_deep_utility(
        self, state: CVEState, _ast_agent: ASTReachabilityAgent
    ) -> NodeName:
        """Node 3A: Confirmed reachable -> Utility scoring + Gemini exploit/fix analysis."""
        enriched_vuln = state.vuln.model_copy(
            update={"vulnerable_symbols": state.candidate_symbols}
        )
        state.finding = await self.utility_agent.prioritize_and_explain(
            vuln=enriched_vuln,
            reachability=state.reachability,
            business_criticality=state.business_criticality,
            repo_path=state.repo_path,
        )
        return NodeName.END

    async def _node_needs_review(
        self, state: CVEState, _ast_agent: ASTReachabilityAgent
    ) -> NodeName:
        """Node 3B: Unresolved uncertainty -> Safe NEEDS_REVIEW flag (never suppressed)."""
        vuln = state.vuln
        # Conservative 0.5 reachability prior keeps unresolved high-EPSS/KEV risks visible
        score, _ = compute_utility_score(
            reachability_conf=0.5,
            epss_score=vuln.epss_score,
            cvss_score=vuln.cvss_score,
            is_in_kev=vuln.is_in_kev,
            business_criticality=state.business_criticality,
        )
        reason_summary = (
            "; ".join(state.uncertainty_reasons) or "Static AST analysis inconclusive."
        )
        fix_target = vuln.fixed_version or "latest patched release"

        state.finding = VulnerabilityFinding(
            cve_id=vuln.cve_id,
            package_name=vuln.package_name,
            installed_version=vuln.installed_version,
            fixed_version=vuln.fixed_version,
            vulnerable_symbols=state.candidate_symbols,
            is_reachable=False,
            reachability_confidence=0.0,
            call_path=[],
            cvss_score=vuln.cvss_score,
            epss_score=vuln.epss_score,
            is_in_kev=vuln.is_in_kev,
            utility_score=score,
            priority_tier="NEEDS_REVIEW",
            ai_reasoning=(
                f"Manual review required (not safely suppressible): {reason_summary} "
                f"Candidate symbols checked: {', '.join(state.candidate_symbols) or 'None'}."
            ),
            remediation_advice=(
                f"Audit dynamic imports/calls for {vuln.package_name} or proactively "
                f"upgrade to {fix_target}."
            ),
        )
        return NodeName.END

    async def _node_fast_path_suppress(
        self, state: CVEState, _ast_agent: ASTReachabilityAgent
    ) -> NodeName:
        """Node 3C: Confirmed unreachable with zero dynamic blind spots -> 0 LLM tokens."""
        vuln = state.vuln
        score, tier = compute_utility_score(
            reachability_conf=0.0,
            epss_score=vuln.epss_score,
            cvss_score=vuln.cvss_score,
            is_in_kev=vuln.is_in_kev,
            business_criticality=state.business_criticality,
        )
        state.finding = VulnerabilityFinding(
            cve_id=vuln.cve_id,
            package_name=vuln.package_name,
            installed_version=vuln.installed_version,
            fixed_version=vuln.fixed_version,
            vulnerable_symbols=state.candidate_symbols,
            is_reachable=False,
            reachability_confidence=0.0,
            call_path=[],
            cvss_score=vuln.cvss_score,
            epss_score=vuln.epss_score,
            is_in_kev=vuln.is_in_kev,
            utility_score=score,
            priority_tier=tier,
            ai_reasoning=(
                f"Confirmed unreachable in static AST with no dynamic dispatch blind spots: "
                f"symbol(s) {', '.join(state.candidate_symbols)} are never invoked."
            ),
            remediation_advice="Defer patch to routine maintenance; no reachable attack surface.",
        )
        return NodeName.END

    # ------------------------------------------------------------------
    # State Machine Execution Engine
    # ------------------------------------------------------------------

    async def _execute_cve_graph(
        self, state: CVEState, ast_agent: ASTReachabilityAgent
    ) -> VulnerabilityFinding:
        """Runs the cyclic state machine for a single CVE with a hard step guard."""
        handlers: Dict[NodeName, Callable[[CVEState, ASTReachabilityAgent], Awaitable[NodeName]]] = {
            NodeName.AST_CHECK: self._node_ast_check,
            NodeName.INVESTIGATE_AMBIGUITY: self._node_investigate_ambiguity,
            NodeName.DEEP_UTILITY: self._node_deep_utility,
            NodeName.NEEDS_REVIEW: self._node_needs_review,
            NodeName.FAST_PATH_SUPPRESS: self._node_fast_path_suppress,
        }

        current_node = NodeName.AST_CHECK
        max_steps = (state.max_retries * 2) + 4  # Hard guard against accidental infinite cycles

        for _ in range(max_steps):
            if current_node == NodeName.END:
                break
            state.trace.append(current_node.value)
            handler = handlers[current_node]
            current_node = await handler(state, ast_agent)

        logger.info("CVE %s agent trace: %s", state.vuln.cve_id, " -> ".join(state.trace))

        if state.finding is None:
            # Failsafe: never drop a CVE if step guard trips
            await self._node_needs_review(state, ast_agent)

        return state.finding

    async def _run_pipeline(
        self, target_dir: str, display_name: str, business_criticality: float
    ) -> ScanReport:
        # Step 1: Agent 2 extracts dependencies & fetches CVEs + EPSS
        raw_vulns = await self.intel_agent.analyze_dependencies(target_dir)

        # Step 2: Agent 1 builds the repository AST call graph once
        ast_agent = ASTReachabilityAgent(target_dir)
        ast_agent.build_graph()

        # Step 3: Run the cyclic state machine concurrently across CVEs (bounded semaphore)
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def evaluate_one(vuln: RawVulnerability) -> VulnerabilityFinding:
            async with semaphore:
                state = CVEState(
                    repo_path=target_dir,
                    business_criticality=business_criticality,
                    vuln=vuln,
                    candidate_symbols=list(vuln.vulnerable_symbols),
                    max_retries=self.max_retries,
                )
                return await self._execute_cve_graph(state, ast_agent)

        findings = list(await asyncio.gather(*(evaluate_one(v) for v in raw_vulns)))
        findings.sort(key=lambda f: f.utility_score, reverse=True)

        total = len(findings)
        reachable_count = sum(1 for f in findings if f.is_reachable)
        # Only confirmed SUPPRESSED_NOISE counts toward noise reduction (excludes NEEDS_REVIEW)
        suppressed_count = sum(1 for f in findings if f.priority_tier == "SUPPRESSED_NOISE")
        noise_reduction = round((suppressed_count / total) * 100.0, 1) if total > 0 else 0.0

        return ScanReport(
            repo_path=display_name,
            total_cves_found=total,
            reachable_cves=reachable_count,
            suppressed_cves=suppressed_count,
            noise_reduction_pct=noise_reduction,
            findings=findings,
        )