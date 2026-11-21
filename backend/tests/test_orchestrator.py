import asyncio

import pytest

from app.agents.utility_agent import UtilityPrioritizationAgent
from app.core.schemas import RawVulnerability
from app.services.mock_intel import MockThreatIntelAgent
from app.services.orchestrator import ScanOrchestrator, import_roots_for


class FakeIntel:
    def __init__(self, vulns):
        self.vulns = vulns

    async def analyze_dependencies(self, repo_path):
        return self.vulns


def vuln(pkg="pyyaml", syms=("yaml.load",), direct=True, via=(), cve="CVE-T-1", fixed="5.4",
         cvss=9.8, epss=0.89, kev=True, ver="5.3.1"):
    return RawVulnerability(cve_id=cve, package_name=pkg, installed_version=ver, fixed_version=fixed,
                            vulnerable_symbols=list(syms), cvss_score=cvss, epss_score=epss, is_in_kev=kev,
                            is_direct_dependency=direct, introduced_via=list(via))


def scan(cfg, root, vulns, utility=None, **kw):
    orch = ScanOrchestrator(intel_agent=FakeIntel(vulns), utility_agent=utility, cfg=cfg, **kw)
    return asyncio.run(orch._run_pipeline(root, "t", 1.0))


REACHABLE_YAML = {"app.py": """
    import yaml
    def load(p):
        return yaml.load(open(p))
    if __name__ == '__main__':
        load('x')
    """}


def only(report):
    assert len(report.findings) == 1
    return report.findings[0]


def test_reachable_cve_is_critical_with_full_evidence(cfg, make_project):
    f = only(scan(cfg, make_project(REACHABLE_YAML), [vuln()]))
    assert f.priority_tier == "CRITICAL_ACTION" and f.is_reachable
    assert f.agent_trace == ["ast_check", "deep_utility"]
    assert f.call_trace and f.call_trace[0]["file_path"] == "app.py" and f.search_depth >= 1
    assert f.score_breakdown and f.remediation


def test_package_used_but_symbol_never_called_is_suppressed(cfg, make_project):
    root = make_project({"app.py": """
        import yaml
        def a(): return yaml.safe_load('a')
        if __name__ == '__main__':
            a()
        """})
    f = only(scan(cfg, root, [vuln()]))
    assert f.priority_tier == "SUPPRESSED_NOISE" and f.agent_trace == ["ast_check", "fast_path_suppress"]


def test_unrelated_dynamic_code_does_not_block_suppression(cfg, make_project):
    """Regression: one getattr anywhere used to push EVERY unreachable CVE to NEEDS_REVIEW."""
    root = make_project({
        "app.py": "import yaml\ndef a(): return yaml.safe_load('x')\nif __name__=='__main__':\n    a()\n",
        "plugins.py": "def pick(o, n):\n    return getattr(o, n)\nif __name__=='__main__':\n    pick(1,'x')\n",
    })
    assert only(scan(cfg, root, [vuln()])).priority_tier == "SUPPRESSED_NOISE"


def test_dynamic_code_in_a_file_that_uses_the_package_blocks_suppression(cfg, make_project):
    root = make_project({"app.py": """
        import yaml
        def a(o, n):
            getattr(yaml, n)(o)
        if __name__ == '__main__':
            a(1, 'load')
        """})
    f = only(scan(cfg, root, [vuln()], max_retries=0))
    assert f.priority_tier == "NEEDS_REVIEW" and f.limitations


def test_dynamic_import_is_treated_as_global_blind_spot(cfg, make_project):
    root = make_project({
        "app.py": "import yaml\ndef a(): return yaml.safe_load('x')\nif __name__=='__main__':\n    a()\n",
        "loader.py": "import importlib\ndef l(n):\n    return importlib.import_module(n)\nif __name__=='__main__':\n    l('yaml')\n",
    })
    assert only(scan(cfg, root, [vuln()], max_retries=0)).priority_tier == "NEEDS_REVIEW"


def test_transitive_cve_with_used_parent_is_never_suppressed(cfg, make_project):
    """urllib3 reached through requests: library internals are not analysed."""
    root = make_project({"app.py": """
        import requests
        def go(): return requests.get('http://a')
        if __name__ == '__main__':
            go()
        """})
    v = vuln("urllib3", ("urllib3.util.url.parse_url",), direct=False, via=["requests"], kev=False,
             cvss=7.5, epss=0.04, fixed="1.26.5", ver="1.26.4")
    f = only(scan(cfg, root, [v]))
    assert f.priority_tier == "NEEDS_REVIEW"
    assert f.agent_trace == ["ast_check", "needs_review"]          # no pointless LLM symbol hunt
    assert any("Transitive" in r for r in f.uncertainty_reasons)


def test_transitive_cve_with_unused_parent_is_suppressed(cfg, make_project):
    root = make_project({"app.py": "def a(): return 1\nif __name__=='__main__':\n    a()\n"})
    v = vuln("urllib3", ("urllib3.util.url.parse_url",), direct=False, via=["requests"], kev=False)
    assert only(scan(cfg, root, [v])).priority_tier == "SUPPRESSED_NOISE"


def test_runtime_hosted_package_is_never_suppressed_for_not_being_imported(cfg, make_project):
    root = make_project({"app.py": "def a(): return 1\nif __name__=='__main__':\n    a()\n"})
    v = vuln("gunicorn", ("gunicorn.http.parser.Parser",), ver="20.0.0", fixed="22.0.0")
    assert only(scan(cfg, root, [v])).priority_tier == "NEEDS_REVIEW"


def test_direct_package_never_imported_is_suppressed_even_without_symbols(cfg, make_project):
    root = make_project({"app.py": "def a(): return 1\nif __name__=='__main__':\n    a()\n"})
    f = only(scan(cfg, root, [vuln("requests", (), kev=False, cvss=6.1, epss=0.14)]))
    assert f.priority_tier == "SUPPRESSED_NOISE" and "never imported" in f.ai_reasoning


def test_imported_package_without_symbols_needs_review(cfg, make_project):
    f = only(scan(cfg, make_project(REACHABLE_YAML), [vuln(syms=())]))
    assert f.priority_tier == "NEEDS_REVIEW"
    assert any("No vulnerable symbols" in r for r in f.uncertainty_reasons)


def test_alias_names_resolve_for_import_detection():
    assert "yaml" in import_roots_for("PyYAML", [])
    assert "pil" in {r.lower() for r in import_roots_for("pillow", [])}
    assert "bs4" in import_roots_for("beautifulsoup4", [])


def test_investigation_cycle_finds_symbol_and_loops_back(cfg, make_project):
    class Investigator(UtilityPrioritizationAgent):
        async def resolve_ambiguous_symbols(self, vuln, existing_symbols, limitations=None):
            return existing_symbols + ["yaml.load"]

    f = only(scan(cfg, make_project(REACHABLE_YAML), [vuln(syms=())], utility=Investigator(cfg)))
    assert f.agent_trace == ["ast_check", "investigate_ambiguity", "ast_check", "deep_utility"]
    assert f.priority_tier == "CRITICAL_ACTION"


def test_one_failing_cve_does_not_kill_the_scan(cfg, make_project):
    class Flaky(UtilityPrioritizationAgent):
        async def prioritize_and_explain(self, vuln, reachability, business_criticality=1.0, repo_path=None):
            if vuln.cve_id == "CVE-BAD":
                raise RuntimeError("boom")
            return await super().prioritize_and_explain(vuln, reachability, business_criticality, repo_path)

    root = make_project(REACHABLE_YAML)
    report = scan(cfg, root, [vuln(cve="CVE-OK"), vuln(cve="CVE-BAD")], utility=Flaky(cfg))
    by_id = {f.cve_id: f for f in report.findings}
    assert by_id["CVE-OK"].priority_tier == "CRITICAL_ACTION"
    assert by_id["CVE-BAD"].priority_tier == "NEEDS_REVIEW" and "error" in by_id["CVE-BAD"].agent_trace
    assert report.total_cves_found == 2 and report.needs_review_cves == 1


def test_report_metadata_and_sorting(cfg, make_project):
    root = make_project({**REACHABLE_YAML, "requirements.txt": "pyyaml==5.3.1\n"})
    r = scan(cfg, root, [vuln(cve="A"), vuln("requests", (), cve="B", kev=False, cvss=3, epss=0.01)])
    assert [f.cve_id for f in r.findings] == ["A", "B"]
    assert r.scan_id and r.files_analyzed >= 1 and r.duration_s >= 0
    assert r.tier_counts == {"CRITICAL_ACTION": 1, "SUPPRESSED_NOISE": 1}
    assert r.noise_reduction_pct == 50.0 and r.llm_used is False


def test_empty_intel_gives_empty_report(cfg, make_project):
    r = scan(cfg, make_project(REACHABLE_YAML), [])
    assert r.total_cves_found == 0 and r.noise_reduction_pct == 0.0


def test_progress_callback_is_called_and_failures_in_it_are_ignored(cfg, make_project):
    seen = []

    def cb(stage, frac):
        seen.append(frac)
        raise RuntimeError("bad callback")
    orch = ScanOrchestrator(intel_agent=FakeIntel([vuln()]), cfg=cfg)
    asyncio.run(orch._run_pipeline(make_project(REACHABLE_YAML), "t", 1.0, on_progress=cb))
    assert seen and seen[-1] == 1.0 and seen == sorted(seen)


# ---- mock intel source ------------------------------------------------------------------
def test_mock_intel_reads_requirements(make_project):
    root = make_project({"requirements.txt": "urllib3==1.26.4\nPyYAML==5.3.1\nflask==2.0\nrequests==2.31.0\n"})
    ids = {v.cve_id for v in asyncio.run(MockThreatIntelAgent().analyze_dependencies(root))}
    assert ids == {"CVE-2020-14343", "CVE-2021-33503"}   # requests 2.31.0 is already fixed, flask has no fixture


def test_mock_intel_without_requirements_is_empty(make_project):
    assert asyncio.run(MockThreatIntelAgent().analyze_dependencies(make_project({"a.py": "x=1"}))) == []


def test_mock_intel_emits_transitive_demo(make_project):
    root = make_project({"requirements.txt": "requests==2.25.1\n"})
    vs = {v.cve_id: v for v in asyncio.run(MockThreatIntelAgent().analyze_dependencies(root))}
    assert vs["CVE-2021-33503"].is_direct_dependency is False and vs["CVE-2021-33503"].introduced_via == ["requests"]
