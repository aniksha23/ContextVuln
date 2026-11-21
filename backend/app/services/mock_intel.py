"""
Offline threat-intel source used while Member 3's live agent is not ready (INTEL_MODE=mock),
and for deterministic demos / tests.

Unlike the old hard-coded stub it READS the target repo's requirements.txt and only reports
fixtures whose package + version are really declared there.

!! The CVSS / EPSS numbers below are ILLUSTRATIVE fixture values, not live data. !!
"""
import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from packaging.version import InvalidVersion, Version

from app.core.remediation import find_requirement_file
from app.core.schemas import RawVulnerability

# package -> list of fixtures
_FIXTURES: List[dict] = [
    dict(cve_id="CVE-2020-14343", package_name="pyyaml", fixed_version="5.4", vulnerable_symbols=["yaml.load"],
         cvss_score=9.8, epss_score=0.89, is_in_kev=True, epss_percentile=0.99,
         summary="Arbitrary code execution via untrusted YAML deserialization (yaml.load / full_load)."),
    dict(cve_id="CVE-2021-33503", package_name="urllib3", fixed_version="1.26.5",
         vulnerable_symbols=["urllib3.util.url.parse_url"], cvss_score=7.5, epss_score=0.04,
         epss_percentile=0.62, summary="ReDoS in urllib3 URL authority parsing."),
    dict(cve_id="CVE-2023-32681", package_name="requests", fixed_version="2.31.0",
         vulnerable_symbols=["requests.Session.rebuild_proxies"], cvss_score=6.1, epss_score=0.14,
         epss_percentile=0.80, summary="Unintended leak of Proxy-Authorization header on redirect."),
    dict(cve_id="CVE-2022-40897", package_name="setuptools", fixed_version="65.5.1",
         vulnerable_symbols=["setuptools.package_index.PackageIndex"], cvss_score=5.9, epss_score=0.04,
         epss_percentile=0.60, summary="ReDoS in package_index HTML parsing."),
]

# Demo of a TRANSITIVE finding: urllib3 is not declared, but `requests` is.
_TRANSITIVE_DEMO = dict(parent="requests", cve_id="CVE-2021-33503", package="urllib3", installed="1.26.4")

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)")


def _norm(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def parse_pins(repo_path: str) -> Dict[str, str]:
    req = find_requirement_file(repo_path)
    pins: Dict[str, str] = {}
    if not req:
        return pins
    with open(req, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            m = _REQ_LINE.match(line)
            if m:
                pins[_norm(m.group(1))] = m.group(2)
    return pins


def _lt(a: str, b: str) -> bool:
    try:
        return Version(a) < Version(b)
    except InvalidVersion:
        return False


class MockThreatIntelAgent:
    async def analyze_dependencies(self, repo_path: str) -> List[RawVulnerability]:
        pins = parse_pins(repo_path)
        now = datetime.now(timezone.utc)
        out: List[RawVulnerability] = []

        for fx in _FIXTURES:
            installed = pins.get(_norm(fx["package_name"]))
            if installed and _lt(installed, fx["fixed_version"]):
                out.append(RawVulnerability(
                    installed_version=installed, source="mock-fixture", fetched_at=now, **fx))

        t = _TRANSITIVE_DEMO
        if _norm(t["package"]) not in pins and _norm(t["parent"]) in pins:
            fx = next(f for f in _FIXTURES if f["cve_id"] == t["cve_id"])
            out.append(RawVulnerability(
                installed_version=t["installed"], is_direct_dependency=False,
                introduced_via=[t["parent"]], source="mock-fixture", fetched_at=now, **fx))
        return out
