from typing import List
from app.core.schemas import RawVulnerability

class ThreatIntelAgent:
    """
    STUB IMPLEMENTATION (Owned by Member 3).
    Member 3 will replace this with live requirements.txt parsing + OSV.dev + FIRST EPSS APIs.
    """
    async def analyze_dependencies(self, repo_path: str) -> List[RawVulnerability]:
        return [
            RawVulnerability(
                cve_id="CVE-2020-14343",
                package_name="pyyaml",
                installed_version="5.3.1",
                fixed_version="5.4",
                vulnerable_symbols=["yaml.load"],
                cvss_score=9.8,
                epss_score=0.89,
                is_in_kev=True,
                summary="Arbitrary code execution via untrusted YAML deserialization.",
            ),
            RawVulnerability(
                cve_id="CVE-2023-32681",
                package_name="requests",
                installed_version="2.28.0",
                fixed_version="2.31.0",
                vulnerable_symbols=["requests.Session.rebuild_proxies"],
                cvss_score=6.1,
                epss_score=0.14,
                is_in_kev=False,
                summary="Unintended leak of Proxy-Authorization header.",
            ),
            RawVulnerability(
                cve_id="CVE-2022-40897",
                package_name="setuptools",
                installed_version="65.5.0",
                fixed_version="65.5.1",
                vulnerable_symbols=["setuptools.package_index.PackageIndex"],
                cvss_score=5.9,
                epss_score=0.04,
                is_in_kev=False,
                summary="ReDoS in package_index HTML parsing.",
            ),
        ]