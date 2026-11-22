import ast
import asyncio
import io
import logging
import re
import sys
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable, Dict, List, Optional, Set

from fastapi import UploadFile

from app.agents.ast_agent import ASTReachabilityAgent
from app.agents.intel_agent import ThreatIntelAgent
from app.agents.utility_agent import UtilityPrioritizationAgent
from app.core.config import Settings, settings as default_settings
from app.core.remediation import build_remediation_plan
from app.core.schemas import (
    RawVulnerability,
    ReachabilityResult,
    ScanReport,
    ScanRequest,
    Tier,
    VulnerabilityFinding,
)
from app.core.scoring import explain_utility_score
from app.services.dep_graph import (
    Exposure,
    RequiresProvider,
    compute_exposure,
    norm as norm_pkg,
    pypi_requires_provider,
    read_all_pins,
    requirement_coverage_warnings,
)
from app.services.mock_intel import MockThreatIntelAgent
from app.services.repo_loader import (
    load_github_repo,
    find_project_root,
    load_zip_stream,
    read_upload_limited,
)

logger = logging.getLogger(__name__)

ProgressCb = Callable[[str, float], None]

# pip name -> import name, when they differ
IMPORT_NAME_ALIASES: Dict[str, str] = {
    "pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn",
    "opencv-python": "cv2", "opencv-python-headless": "cv2", "python-dateutil": "dateutil",
    "pyjwt": "jwt", "protobuf": "google", "attrs": "attr", "msgpack-python": "msgpack",
    "pycryptodome": "Crypto", "python-jose": "jose", "pymysql": "pymysql", "psycopg2-binary": "psycopg2",
}

# Packages that run the app / are exercised through the network or CLI WITHOUT being imported by it.
# "never imported" proves nothing for these, so they are never auto-suppressed on that basis.
RUNTIME_HOSTED_PACKAGES = {
    "gunicorn", "uvicorn", "hypercorn", "daphne", "waitress", "gevent", "celery", "uwsgi",
    "werkzeug", "starlette", "django", "flask", "fastapi", "tornado", "aiohttp",
}

_LIMITATION_FILE_RE = re.compile(r"\bat (\S+?\.py):\d+")


class NodeName(str, Enum):
    AST_CHECK = "ast_check"
    INVESTIGATE_AMBIGUITY = "investigate_ambiguity"
    DEEP_UTILITY = "deep_utility"
    NEEDS_REVIEW = "needs_review"
    FAST_PATH_SUPPRESS = "fast_path_suppress"
    END = "end"


@dataclass
class ImportIndex:
    """Which third-party roots are imported anywhere in the app, and from which files."""
    root_to_files: Dict[str, Set[str]] = field(default_factory=dict)
    file_to_roots: Dict[str, Set[str]] = field(default_factory=dict)
    exposure: Optional[Exposure] = None   # filled by the pipeline when dependency metadata is available

    @classmethod
    def build(cls, ast_agent: ASTReachabilityAgent) -> "ImportIndex":
        idx = cls()
        for mod, tree in ast_agent.parsed_asts.items():
            rel = ast_agent.module_to_file.get(mod, mod)
            for node in ast.walk(tree):  # includes function-local imports
                names: List[str] = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for n in names:
                    root = n.split(".")[0].lower()
                    idx.root_to_files.setdefault(root, set()).add(rel)
                    idx.file_to_roots.setdefault(rel, set()).add(root)
        return idx

    def is_imported(self, roots: Set[str]) -> bool:
        return any(r in self.root_to_files for r in roots)


def import_roots_for(package_name: str, symbols: List[str]) -> Set[str]:
    norm = package_name.lower().replace("_", "-")
    roots = {norm.replace("-", "_"), norm}
    if norm in IMPORT_NAME_ALIASES:
        roots.add(IMPORT_NAME_ALIASES[norm].lower())
    for s in symbols:
        if s:
            roots.add(s.split(".")[0].lower())
    return roots


@dataclass
class CVEState:
    """Shared mutable state passed across nodes in the cyclic CVE state machine."""
    repo_path: str
    business_criticality: float
    vuln: RawVulnerability
    candidate_symbols: List[str] = field(default_factory=list)
    reachability: Optional[ReachabilityResult] = None
    limitations: List[str] = field(default_factory=list)          # ONLY those relevant to this package
    has_uncertainty: bool = False
    uncertainty_reasons: List[str] = field(default_factory=list)
    structural_uncertainty: bool = False                           # symbol guessing cannot fix it
    retry_count: int = 0
    max_retries: int = 1
    no_new_symbols_found: bool = False
    trace: List[str] = field(default_factory=list)
    finding: Optional[VulnerabilityFinding] = None


@asynccontextmanager
async def _threaded(cm):
    """Runs a blocking context manager's enter/exit in a worker thread so the event loop stays free."""
    value = await asyncio.to_thread(cm.__enter__)
    try:
        yield value
    except BaseException:
        await asyncio.to_thread(cm.__exit__, *sys.exc_info())
        raise
    else:
        await asyncio.to_thread(cm.__exit__, None, None, None)


class ScanOrchestrator:
    """
    Pure-Python cyclic multi-agent state machine.

    Graph topology per CVE:
      AST_CHECK
        |- reachable                                        -> DEEP_UTILITY -> END
        |- uncertain & fixable by new symbols & retries left -> INVESTIGATE_AMBIGUITY -> AST_CHECK (cycle)
        |- uncertain otherwise                               -> NEEDS_REVIEW -> END
        '- confirmed unreachable, no relevant blind spots     -> FAST_PATH_SUPPRESS -> END

    Suppression safety rules (a wrongly suppressed CVE is worse than noise):
      1. Only dynamic constructs that can touch THIS package count as blind spots (not the whole repo).
      2. A transitive CVE (e.g. urllib3 via requests) is never suppressed while its parent package is
         used by the app, because library internals are not part of the AST call graph.
      3. Runtime-hosted packages (gunicorn, uvicorn, ...) are never suppressed for "not imported".
      4. No known vulnerable symbols  ->  NEEDS_REVIEW, never suppressed.
    """

    def __init__(
        self,
        max_retries: Optional[int] = None,
        max_concurrency: Optional[int] = None,
        intel_agent=None,
        utility_agent: Optional[UtilityPrioritizationAgent] = None,
        cfg: Settings = default_settings,
        requires_provider: Optional[RequiresProvider] = None,
    ):
        self.cfg = cfg
        self.requires_provider = requires_provider or pypi_requires_provider
        if intel_agent is not None:
            self.intel_agent = intel_agent
        elif cfg.intel_mode == "live":
            self.intel_agent = ThreatIntelAgent()
        else:
            self.intel_agent = MockThreatIntelAgent()
        self.utility_agent = utility_agent or UtilityPrioritizationAgent(cfg)
        self.max_retries = cfg.max_retries if max_retries is None else max_retries
        self.max_concurrency = cfg.max_concurrency if max_concurrency is None else max_concurrency

    # ------------------------------------------------------------------ public entry points
    async def scan_github(
        self, request: ScanRequest, scan_id: Optional[str] = None, on_progress: Optional[ProgressCb] = None
    ) -> ScanReport:
        self._emit(on_progress, "cloning repository", 0.02)
        async with _threaded(load_github_repo(request.repo_url)) as target_dir:
            return await self._run_pipeline(
                target_dir, request.repo_url, request.business_criticality, scan_id, on_progress
            )

    async def scan_zip_bytes(
        self,
        data: bytes,
        filename: str,
        business_criticality: float = 1.0,
        scan_id: Optional[str] = None,
        on_progress: Optional[ProgressCb] = None,
    ) -> ScanReport:
        self._emit(on_progress, "extracting archive", 0.02)
        async with _threaded(load_zip_stream(io.BytesIO(data), filename)) as target_dir:
            return await self._run_pipeline(
                target_dir, filename or "uploaded_archive.zip", business_criticality, scan_id, on_progress
            )

    async def scan_zip_upload(
        self, file: UploadFile, business_criticality: float = 1.0,
        scan_id: Optional[str] = None, on_progress: Optional[ProgressCb] = None,
    ) -> ScanReport:
        if not file.filename or not file.filename.lower().endswith(".zip"):
            raise ValueError("Please upload a .zip archive of your project folder.")
        data = await asyncio.to_thread(read_upload_limited, file)
        return await self.scan_zip_bytes(data, file.filename, business_criticality, scan_id, on_progress)

    @staticmethod
    def _emit(cb: Optional[ProgressCb], stage: str, frac: float) -> None:
        if cb:
            try:
                cb(stage, frac)
            except Exception:  # progress reporting must never break a scan
                logger.debug("progress callback failed", exc_info=True)

    # ------------------------------------------------------------------ analysis helpers
    @staticmethod
    def _relevant_limitations(
        limitations: List[str], index: ImportIndex, roots: Set[str]
    ) -> List[str]:
        """Keeps only blind spots that could hide a call to this package."""
        relevant: List[str] = []
        for lim in limitations:
            if "Dynamic import" in lim or "__import__" in lim:  # can load ANY package by name
                relevant.append(lim)
                continue
            m = _LIMITATION_FILE_RE.search(lim)
            if not m:                              # cannot tell where it is -> be conservative
                relevant.append(lim)
                continue
            if index.file_to_roots.get(m.group(1), set()) & roots:
                relevant.append(lim)
        return relevant

    def _assess_unreachable(
        self, state: CVEState, index: ImportIndex, ast_limitations: List[str]
    ) -> None:
        """Decides whether an 'unreachable' verdict is trustworthy; fills uncertainty fields."""
        vuln = state.vuln
        roots = import_roots_for(vuln.package_name, state.candidate_symbols)
        reasons: List[str] = []
        structural = False

        imported = index.is_imported(roots)
        parents_imported = any(
            index.is_imported(import_roots_for(p, [])) for p in vuln.introduced_via
        )

        if not imported:
            if vuln.package_name.lower() in RUNTIME_HOSTED_PACKAGES:
                reasons.append(
                    f"{vuln.package_name} is a runtime/framework package: it can be exposed without "
                    f"being imported by application code."
                )
                structural = True
            elif not vuln.is_direct_dependency and (parents_imported or not vuln.introduced_via):
                via = ", ".join(vuln.introduced_via) or "unknown parent"
                reasons.append(
                    f"Transitive dependency (via {via}): library internals are not analysed, so a call "
                    f"into the parent package could still reach {vuln.package_name}."
                )
                structural = True
            elif index.exposure is not None and (
                not index.exposure.complete or norm_pkg(vuln.package_name) not in index.exposure.pinned
            ):
                reasons.append(
                    f"Could not verify that no imported package depends on {vuln.package_name} "
                    f"(dependency metadata incomplete), so it is not suppressed."
                )
                structural = True
            # else: direct dep never imported, or transitive of an unused parent -> safe to suppress
        else:
            if not state.candidate_symbols:
                reasons.append("No vulnerable symbols extracted from advisory.")
            state.limitations = self._relevant_limitations(ast_limitations, index, roots)
            if state.limitations:
                reasons.append(
                    f"Dynamic constructs near code that uses {vuln.package_name} "
                    f"({len(state.limitations)}): {state.limitations[0]}"
                )

        state.uncertainty_reasons = reasons
        state.has_uncertainty = bool(reasons)
        state.structural_uncertainty = structural

    # ------------------------------------------------------------------ state machine nodes
    async def _node_ast_check(
        self, state: CVEState, ast_agent: ASTReachabilityAgent, index: ImportIndex
    ) -> NodeName:
        """Node 1: deterministic AST reachability verification (Member 2 / Agent 1)."""
        if (state.vuln.ecosystem or "PyPI").lower() != "pypi":
            state.reachability = ReachabilityResult(is_reachable=False, confidence=0.0, call_path=[])
            state.uncertainty_reasons = [
                f"Unsupported ecosystem ({state.vuln.ecosystem}): only Python code is analysed, "
                f"so reachability cannot be determined."
            ]
            state.has_uncertainty = state.structural_uncertainty = True
            return NodeName.NEEDS_REVIEW
        symbols = state.candidate_symbols
        if symbols:
            result = await asyncio.to_thread(ast_agent.check_reachability, symbols)
            if result.is_reachable and not self._sink_in_package(state, result):
                # A bare advisory name (e.g. "parse_url") matched the project's OWN function of that name.
                # Keep only package-qualified symbols and ask again.
                roots = import_roots_for(state.vuln.package_name, [])
                qualified = [x for x in symbols if "." in x and x.split(".")[0].lower() in roots]
                result = (
                    await asyncio.to_thread(ast_agent.check_reachability, qualified)
                    if qualified else ReachabilityResult(is_reachable=False, confidence=0.0, call_path=[])
                )
        else:
            result = ReachabilityResult(is_reachable=False, confidence=0.0, call_path=[])
        state.reachability = result

        if not result.is_reachable:
            self._assess_unreachable(state, index, list(getattr(result, "limitations", []) or ast_agent.limitations))
        else:
            state.has_uncertainty = False
            state.uncertainty_reasons = []
            state.limitations = self._relevant_limitations(
                list(getattr(result, "limitations", []) or []),
                index, import_roots_for(state.vuln.package_name, symbols),
            )
        return self._route_after_ast(state)

    @staticmethod
    def _sink_in_package(state: CVEState, result: ReachabilityResult) -> bool:
        """The last node of a reachable path must be a function of the vulnerable package, not app code."""
        if not result.call_path:
            return True
        sink = result.call_path[-1].split("(")[0]
        roots = import_roots_for(state.vuln.package_name, [x for x in state.candidate_symbols if "." in x])
        return sink.split(".")[0].lower() in roots

    def _route_after_ast(self, state: CVEState) -> NodeName:
        if state.reachability and state.reachability.is_reachable:
            return NodeName.DEEP_UTILITY
        if state.has_uncertainty:
            can_investigate = (
                not state.structural_uncertainty
                and state.retry_count < state.max_retries
                and not state.no_new_symbols_found
            )
            return NodeName.INVESTIGATE_AMBIGUITY if can_investigate else NodeName.NEEDS_REVIEW
        return NodeName.FAST_PATH_SUPPRESS

    async def _node_investigate_ambiguity(self, state: CVEState, *_) -> NodeName:
        """Node 2: LLM proposes candidate symbols -> loop back so Agent 1 verifies them deterministically."""
        previous = set(state.candidate_symbols)
        expanded = await self.utility_agent.resolve_ambiguous_symbols(
            vuln=state.vuln, existing_symbols=state.candidate_symbols, limitations=state.limitations
        )
        state.retry_count += 1
        state.candidate_symbols = expanded
        if set(expanded) == previous:
            state.no_new_symbols_found = True
            return NodeName.NEEDS_REVIEW
        return NodeName.AST_CHECK

    async def _node_deep_utility(self, state: CVEState, *_) -> NodeName:
        """Node 3A: confirmed reachable -> utility scoring + LLM exploit/fix analysis."""
        enriched = state.vuln.model_copy(update={"vulnerable_symbols": state.candidate_symbols})
        if state.vuln.symbol_source == "fallback":
            state.uncertainty_reasons.append(
                "Advisory names no vulnerable function: 'reachable' means the package is used, "
                "not that the vulnerable code path is."
            )
        state.finding = await self.utility_agent.prioritize_and_explain(
            vuln=enriched,
            reachability=state.reachability,
            business_criticality=state.business_criticality,
            repo_path=state.repo_path,
        )
        return NodeName.END

    def _base_finding(
        self, state: CVEState, tier: str, conf_for_score: float, reasoning: str, advice: str
    ) -> VulnerabilityFinding:
        v = state.vuln
        score, _, breakdown = explain_utility_score(
            conf_for_score, v.epss_score, v.cvss_score, v.is_in_kev,
            state.business_criticality, v.epss_percentile, self.cfg,
        )
        plan = build_remediation_plan(
            state.repo_path, v.package_name, v.installed_version, v.fixed_version, v.cve_id, reachable=False
        )
        return VulnerabilityFinding(
            cve_id=v.cve_id, package_name=v.package_name, installed_version=v.installed_version,
            fixed_version=v.fixed_version, vulnerable_symbols=state.candidate_symbols,
            is_reachable=False, reachability_confidence=0.0, call_path=[],
            cvss_score=v.cvss_score, epss_score=v.epss_score, is_in_kev=v.is_in_kev,
            utility_score=score, priority_tier=tier, ai_reasoning=reasoning, remediation_advice=advice,
            summary=v.summary, score_breakdown=breakdown, remediation=plan,
            is_direct_dependency=v.is_direct_dependency, introduced_via=v.introduced_via,
            epss_percentile=v.epss_percentile, data_source=v.source, data_fetched_at=v.fetched_at,
        )

    async def _node_needs_review(self, state: CVEState, *_) -> NodeName:
        """Node 3B: unresolved uncertainty -> NEEDS_REVIEW (never suppressed)."""
        v = state.vuln
        reason = "; ".join(state.uncertainty_reasons) or "Static AST analysis inconclusive."
        fix = v.fixed_version or "the latest patched release"
        state.finding = self._base_finding(
            state, Tier.NEEDS_REVIEW.value, self.cfg.conf_needs_review,
            reasoning=(
                f"Manual review required (not safely suppressible): {reason} "
                f"Candidate symbols checked: {', '.join(state.candidate_symbols) or 'none'}."
            ),
            advice=f"Audit how {v.package_name} is used, or upgrade to {fix}.",
        )
        # keep the prior-based score but make it clear this is a review item, not a confirmed risk
        state.finding.score_breakdown.notes.append(
            f"Inconclusive analysis: scored with reachability prior {self.cfg.conf_needs_review}."
        )
        return NodeName.END

    async def _node_fast_path_suppress(self, state: CVEState, *_) -> NodeName:
        """Node 3C: confirmed unreachable with no relevant blind spots -> zero LLM tokens."""
        v = state.vuln
        syms = ", ".join(state.candidate_symbols)
        state.finding = self._base_finding(
            state, Tier.SUPPRESSED_NOISE.value, 0.0,
            reasoning=(
                f"Not reachable: symbol(s) {syms} are never invoked from any application entry point, "
                f"and no dynamic construct near {v.package_name} usage could hide a call."
                if state.candidate_symbols else
                f"{v.package_name} is never imported by the application."
            ),
            advice="Defer to routine maintenance; no reachable attack surface detected.",
        )
        return NodeName.END

    # ------------------------------------------------------------------ execution engine
    async def _execute_cve_graph(
        self, state: CVEState, ast_agent: ASTReachabilityAgent, index: ImportIndex
    ) -> VulnerabilityFinding:
        handlers: Dict[NodeName, Callable[..., Awaitable[NodeName]]] = {
            NodeName.AST_CHECK: self._node_ast_check,
            NodeName.INVESTIGATE_AMBIGUITY: self._node_investigate_ambiguity,
            NodeName.DEEP_UTILITY: self._node_deep_utility,
            NodeName.NEEDS_REVIEW: self._node_needs_review,
            NodeName.FAST_PATH_SUPPRESS: self._node_fast_path_suppress,
        }
        current = NodeName.AST_CHECK
        max_steps = (state.max_retries * 2) + 4  # hard guard against accidental infinite cycles

        for _ in range(max_steps):
            if current == NodeName.END:
                break
            state.trace.append(current.value)
            current = await handlers[current](state, ast_agent, index)

        logger.info("CVE %s agent trace: %s", state.vuln.cve_id, " -> ".join(state.trace))

        if state.finding is None:  # failsafe: never drop a CVE
            state.uncertainty_reasons.append("Step guard tripped before a verdict was reached.")
            await self._node_needs_review(state)

        f = state.finding
        f.agent_trace = list(state.trace)
        f.uncertainty_reasons = list(state.uncertainty_reasons)
        if not f.limitations:
            f.limitations = list(state.limitations)
        return f

    @staticmethod
    def _apply_exposure(vuln: RawVulnerability, index: ImportIndex) -> RawVulnerability:
        """Marks a pinned-but-never-imported package as transitive when an imported package requires it."""
        ex = index.exposure
        if ex is None or index.is_imported(import_roots_for(vuln.package_name, vuln.vulnerable_symbols)):
            return vuln
        ancestors = ex.ancestors.get(norm_pkg(vuln.package_name), [])
        if not ancestors:
            return vuln
        return vuln.model_copy(update={
            "is_direct_dependency": False,
            "introduced_via": sorted(set(vuln.introduced_via) | set(ancestors)),
        })

    async def _evaluate_safely(
        self, vuln: RawVulnerability, target_dir: str, crit: float,
        ast_agent: ASTReachabilityAgent, index: ImportIndex,
    ) -> VulnerabilityFinding:
        """One bad CVE must never take the whole scan down: degrade it to NEEDS_REVIEW instead."""
        vuln = self._apply_exposure(vuln, index)
        state = CVEState(
            repo_path=target_dir, business_criticality=crit, vuln=vuln,
            candidate_symbols=list(vuln.vulnerable_symbols), max_retries=self.max_retries,
        )
        try:
            return await self._execute_cve_graph(state, ast_agent, index)
        except Exception as e:
            logger.exception("Evaluation of %s failed", vuln.cve_id)
            state.uncertainty_reasons.append(f"Internal analysis error ({type(e).__name__}).")
            state.finding = None
            await self._node_needs_review(state)
            state.finding.agent_trace = list(state.trace) + ["error"]
            state.finding.uncertainty_reasons = list(state.uncertainty_reasons)
            return state.finding

    async def _run_pipeline(
        self, target_dir: str, display_name: str, business_criticality: float,
        scan_id: Optional[str] = None, on_progress: Optional[ProgressCb] = None,
    ) -> ScanReport:
        started = time.perf_counter()
        scan_id = scan_id or uuid.uuid4().hex[:12]
        target_dir = find_project_root(target_dir)  # skip zip wrapper folders so imports resolve

        # Step 1: Agent 2 - dependencies, CVEs, EPSS
        self._emit(on_progress, "collecting vulnerability intelligence", 0.10)
        warnings: List[str] = []
        with_warnings = getattr(self.intel_agent, "analyze_with_warnings", None)
        if with_warnings is not None:   # optional hook: agent reports what it skipped / which feeds failed
            raw_vulns, intel_warnings = await with_warnings(target_dir)
            warnings.extend(intel_warnings)
        else:
            raw_vulns = await self.intel_agent.analyze_dependencies(target_dir)
        warnings.extend(await asyncio.to_thread(requirement_coverage_warnings, target_dir))

        # Step 2: Agent 1 - build the AST call graph once (CPU bound -> worker thread)
        self._emit(on_progress, "building call graph", 0.30)
        ast_agent = ASTReachabilityAgent(target_dir)
        await asyncio.to_thread(ast_agent.build_graph)
        index = await asyncio.to_thread(ImportIndex.build, ast_agent)

        # Which pinned packages are really pulled in by something the app imports?
        if self.cfg.dep_graph_enabled and any(
            not index.is_imported(import_roots_for(v.package_name, v.vulnerable_symbols))
            and (v.ecosystem or "PyPI").lower() == "pypi"
            for v in raw_vulns
        ):
            self._emit(on_progress, "resolving dependency graph", 0.33)
            pins = await asyncio.to_thread(read_all_pins, target_dir)
            imported_pins = {p for p in pins if index.is_imported(import_roots_for(p, []))}
            index.exposure = await compute_exposure(
                pins, imported_pins, self.requires_provider, self.cfg.max_dep_lookups
            )
            warnings.extend(index.exposure.notes[:3])

        # Step 3: cyclic state machine per CVE, bounded concurrency
        semaphore = asyncio.Semaphore(self.max_concurrency)
        done = 0
        total_work = max(1, len(raw_vulns))

        async def evaluate_one(vuln: RawVulnerability) -> VulnerabilityFinding:
            nonlocal done
            async with semaphore:
                finding = await self._evaluate_safely(vuln, target_dir, business_criticality, ast_agent, index)
            done += 1
            self._emit(on_progress, f"analysed {done}/{len(raw_vulns)} CVEs", 0.35 + 0.60 * done / total_work)
            return finding

        findings = list(await asyncio.gather(*(evaluate_one(v) for v in raw_vulns)))
        findings.sort(key=lambda f: f.utility_score, reverse=True)

        tiers = Counter(f.priority_tier for f in findings)
        total = len(findings)
        suppressed = tiers.get(Tier.SUPPRESSED_NOISE.value, 0)
        self._emit(on_progress, "done", 1.0)

        return ScanReport(
            repo_path=display_name,
            total_cves_found=total,
            reachable_cves=sum(1 for f in findings if f.is_reachable),
            suppressed_cves=suppressed,
            noise_reduction_pct=round(suppressed / total * 100.0, 1) if total else 0.0,
            findings=findings,
            scan_id=scan_id,
            duration_s=round(time.perf_counter() - started, 3),
            needs_review_cves=tiers.get(Tier.NEEDS_REVIEW.value, 0),
            tier_counts=dict(tiers),
            files_analyzed=len(ast_agent.parsed_asts),
            warnings=(warnings + list(ast_agent.warnings))[:50],
            intel_mode=self.cfg.intel_mode,
            llm_used=self.utility_agent.llm_calls > 0,
        )
