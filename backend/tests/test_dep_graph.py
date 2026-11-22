import asyncio

from app.core.config import Settings
from app.core.schemas import RawVulnerability
from app.services.dep_graph import (
    compute_exposure, read_all_pins, requirement_coverage_warnings,
)
from app.services.orchestrator import ScanOrchestrator


def provider_from(table):
    async def provider(name, version):
        return table.get(name)          # None => metadata unavailable
    return provider


def test_exposure_finds_direct_and_chained_parents():
    table = {"requests": ["urllib3", "idna"], "urllib3": [], "idna": [], "flask": ["werkzeug"],
             "werkzeug": ["markupsafe"], "markupsafe": [], "leftpad": []}
    pins = {n: "1.0" for n in table}
    ex = asyncio.run(compute_exposure(pins, {"requests", "flask"}, provider_from(table)))
    assert ex.complete
    assert ex.ancestors["urllib3"] == ["requests"]
    assert ex.ancestors["markupsafe"] == ["flask"]            # flask -> werkzeug -> markupsafe
    assert "leftpad" not in ex.ancestors                      # genuinely unused


def test_exposure_incomplete_when_metadata_missing():
    pins = {"requests": "1", "urllib3": "1"}
    ex = asyncio.run(compute_exposure(pins, {"requests"}, provider_from({"requests": ["urllib3"]})))
    assert ex.complete is False and ex.ancestors["urllib3"] == ["requests"]


def test_read_all_pins_covers_every_requirements_file(make_project):
    root = make_project({"requirements.txt": "Requests==2.25.1\n", "sub/requirements-dev.txt": "pytest==7.0\nflask>=2\n",
                         "venv/requirements.txt": "ignored==1\n"})
    assert read_all_pins(root) == {"requests": "2.25.1", "pytest": "7.0"}


def test_coverage_warnings_flag_unpinned_and_unsupported(make_project):
    root = make_project({"requirements.txt": "pyyaml>=5.1\nurllib3\nflask==2.0\n", "pyproject.toml": "[tool]\n"})
    w = " ".join(requirement_coverage_warnings(root))
    assert "2 requirement line(s)" in w and "pyyaml>=5.1" in w and "pyproject.toml" in w


def test_coverage_warning_when_no_requirements_at_all(make_project):
    assert any("No requirements" in w for w in requirement_coverage_warnings(make_project({"a.py": "x=1"})))


# ---------------- orchestrator-level safety (online dep graph with injected metadata) ------------
class FakeIntel:
    def __init__(self, vulns, warnings=None):
        self.vulns, self.w = vulns, warnings

    async def analyze_dependencies(self, repo_path):
        return self.vulns


class FakeIntelWithWarnings(FakeIntel):
    async def analyze_with_warnings(self, repo_path):
        return self.vulns, self.w


def v(pkg="urllib3", syms=("urllib3.util.url.parse_url",), **kw):
    base = dict(cve_id="CVE-T-1", package_name=pkg, installed_version="1.26.4", fixed_version="1.26.5",
                vulnerable_symbols=list(syms), cvss_score=7.5, epss_score=0.002)
    base.update(kw)
    return RawVulnerability(**base)


def scan(files_root, vulns, table=None, intel=None, **cfg_kw):
    cfg = Settings(_env_file=None, gemini_api_key="", dep_graph_mode="online", **cfg_kw)
    orch = ScanOrchestrator(intel_agent=intel or FakeIntel(vulns), cfg=cfg,
                            requires_provider=provider_from(table if table is not None else {}))
    return asyncio.run(orch._run_pipeline(files_root, "t", 1.0))


APP_USES_REQUESTS = {
    "requirements.txt": "requests==2.25.1\nurllib3==1.26.4\n",
    "app.py": "import requests\ndef go(): return requests.get('http://x')\nif __name__=='__main__':\n    go()\n",
}


def test_pip_freeze_transitive_dependency_is_not_suppressed(make_project):
    """Regression (found with Member 3's agent): urllib3 pinned by pip-freeze, imported by nobody,
    but required by requests which the app calls. Intel marks it 'direct'; we must still not suppress."""
    r = scan(make_project(APP_USES_REQUESTS), [v()], table={"requests": ["urllib3"], "urllib3": []})
    f = r.findings[0]
    assert f.priority_tier == "NEEDS_REVIEW"
    assert f.is_direct_dependency is False and f.introduced_via == ["requests"]
    assert any("Transitive dependency (via requests)" in x for x in f.uncertainty_reasons)


def test_unused_pinned_package_with_complete_metadata_is_still_suppressed(make_project):
    files = {"requirements.txt": "requests==2.25.1\nurllib3==1.26.4\nleftpad==1.0\n",
             "app.py": "import requests\ndef go(): return 1\nif __name__=='__main__':\n    go()\n"}
    table = {"requests": ["urllib3"], "urllib3": [], "leftpad": []}
    r = scan(make_project(files), [v("leftpad", ("leftpad.pad",), fixed_version="1.1")], table=table)
    assert r.findings[0].priority_tier == "SUPPRESSED_NOISE"


def test_metadata_outage_never_suppresses(make_project):
    files = {"requirements.txt": "leftpad==1.0\n", "app.py": "def go(): return 1\nif __name__=='__main__':\n    go()\n"}
    r = scan(make_project(files), [v("leftpad", ("leftpad.pad",))], table={})   # provider returns None
    f = r.findings[0]
    assert f.priority_tier == "NEEDS_REVIEW" and any("metadata incomplete" in x for x in f.uncertainty_reasons)
    assert any("No dependency metadata" in w for w in r.warnings)


def test_package_missing_from_pins_is_not_suppressed(make_project):
    files = {"requirements.txt": "flask==2.0\n", "app.py": "def go(): return 1\nif __name__=='__main__':\n    go()\n"}
    r = scan(make_project(files), [v("somelib", ("somelib.x",))], table={"flask": []})
    assert r.findings[0].priority_tier == "NEEDS_REVIEW"


def test_non_python_ecosystem_is_needs_review_not_suppressed(make_project):
    r = scan(make_project({"package-lock.json": "{}", "app.py": "print(1)\n"}),
             [v("lodash", ("lodash",), ecosystem="npm", fixed_version="4.17.19")])
    f = r.findings[0]
    assert f.priority_tier == "NEEDS_REVIEW" and "Unsupported ecosystem (npm)" in f.uncertainty_reasons[0]
    assert f.agent_trace == ["ast_check", "needs_review"]


REACH = {"requirements.txt": "somelib==1.0\n",
         "app.py": "import somelib\ndef go(): return somelib.helper()\nif __name__=='__main__':\n    go()\n"}


def test_package_level_symbol_gets_reduced_confidence_and_a_caveat(make_project):
    root = make_project(REACH)
    exact = scan(root, [v("somelib", ("somelib",), cvss_score=6.0, epss_score=0.3, symbol_source="structured")],
                 table={"somelib": []}).findings[0]
    fallback = scan(root, [v("somelib", ("somelib",), cvss_score=6.0, epss_score=0.3, symbol_source="fallback")],
                    table={"somelib": []}).findings[0]
    assert exact.is_reachable and fallback.is_reachable
    assert fallback.utility_score < exact.utility_score
    assert any("package is used" in x for x in fallback.uncertainty_reasons)
    assert any("package-level" in n for n in fallback.score_breakdown.notes)


def test_intel_warnings_hook_and_coverage_warnings_reach_the_report(make_project):
    root = make_project({"requirements.txt": "pyyaml>=5.1\n", "app.py": "import yaml\n"})
    intel = FakeIntelWithWarnings([], ["EPSS lookup failed: scores unavailable", "CISA KEV unavailable"])
    r = scan(root, [], intel=intel)
    assert r.total_cves_found == 0
    assert "EPSS lookup failed: scores unavailable" in r.warnings
    assert any("NOT scanned" in w for w in r.warnings)        # an empty result must not look like 'all clear'


def test_bare_advisory_symbol_does_not_match_the_projects_own_function(make_project):
    """Regression (Member 3's heuristics emit bare names like 'parse_url'; Member 2 suffix-matches them)."""
    root = make_project({"requirements.txt": "urllib3==1.26.4\n", "app.py": """
        import urllib3
        def parse_url(s): return s.strip()
        def go():
            http = urllib3.PoolManager()
            return parse_url('x')
        if __name__ == '__main__':
            go()
        """})
    r = scan(root, [v(syms=("urllib3.util.url.parse_url", "parse_url"))], table={"urllib3": []})
    assert r.findings[0].priority_tier == "SUPPRESSED_NOISE" and not r.findings[0].is_reachable


def test_bare_symbol_still_catches_a_real_reexported_call(make_project):
    """urllib3.util.parse_url is a re-export of urllib3.util.url.parse_url: the bare name must still help."""
    root = make_project({"requirements.txt": "urllib3==1.26.4\n", "app.py": """
        import urllib3
        def go(u):
            return urllib3.util.parse_url(u)
        if __name__ == '__main__':
            go('http://x')
        """})
    r = scan(root, [v(syms=("urllib3.util.url.parse_url", "parse_url"))], table={"urllib3": []})
    assert r.findings[0].is_reachable
