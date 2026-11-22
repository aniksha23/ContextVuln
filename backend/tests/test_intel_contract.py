"""Contract + warning tests for the Threat Intel agent (added by Member 1). Self-contained."""
from __future__ import annotations

from pathlib import Path

import pytest
import respx

from app.agents.intel_agent import CISA_KEV_URL, EPSS_API_URL, OSV_QUERY_URL, DiskCache, ThreatIntelAgent

URLLIB3_OSV_PAGE_2 = {"vulns": [{
    "id": "GHSA-v845-jxx5-vc9f", "aliases": ["CVE-2023-43804"],
    "summary": "Cookie header retained on cross-origin redirects",
    "details": "urllib3 does not strip Cookie request headers on cross-origin redirects.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
    "affected": [{"package": {"name": "urllib3", "ecosystem": "PyPI"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.17"}]}]}],
}]}


# ===========================================================================
# 12. Integration contract fields + warnings (added by Member 1)
# ===========================================================================
@pytest.mark.asyncio
@respx.mock
async def test_contract_fields_and_feed_failure_warnings(tmp_path: Path):
    respx.post(OSV_QUERY_URL).respond(200, json=URLLIB3_OSV_PAGE_2)
    respx.get(EPSS_API_URL).respond(200, json={"data": []})
    respx.get(CISA_KEV_URL).respond(200, json={"vulnerabilities": []})
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n", encoding="utf-8")
    agent = ThreatIntelAgent()
    agent.cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    vulns, warnings = await agent.analyze_with_warnings(str(tmp_path))
    v = vulns[0]
    assert v.ecosystem == "PyPI" and v.symbol_source in {"structured", "curated", "heuristics", "fallback"}
    assert v.source == "osv.dev" and v.fetched_at is not None
    assert v.cvss_vector and v.cvss_vector.startswith("CVSS:3")
    assert warnings == []   # nothing failed


@pytest.mark.asyncio
@respx.mock
async def test_feed_outages_are_reported_not_silent(tmp_path: Path, monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr("app.agents.intel_agent.asyncio.sleep", no_sleep)
    respx.post(OSV_QUERY_URL).respond(200, json=URLLIB3_OSV_PAGE_2)
    respx.get(EPSS_API_URL).respond(500)
    respx.get(CISA_KEV_URL).respond(500)
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n", encoding="utf-8")
    agent = ThreatIntelAgent()
    agent.cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    vulns, warnings = await agent.analyze_with_warnings(str(tmp_path))
    assert len(vulns) == 1
    assert any("EPSS" in w for w in warnings) and any("KEV" in w for w in warnings)


@pytest.mark.asyncio
@respx.mock
async def test_failed_osv_lookup_is_reported_and_not_cached_as_clean(tmp_path: Path, monkeypatch):
    async def no_sleep(_):
        return None
    monkeypatch.setattr("app.agents.intel_agent.asyncio.sleep", no_sleep)
    respx.post(OSV_QUERY_URL).respond(500)
    respx.get(EPSS_API_URL).respond(200, json={"data": []})
    respx.get(CISA_KEV_URL).respond(200, json={"vulnerabilities": []})
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n", encoding="utf-8")
    cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)
    agent = ThreatIntelAgent()
    agent.cache = cache

    vulns, warnings = await agent.analyze_with_warnings(str(tmp_path))
    assert vulns == [] and any("MISSING" in w for w in warnings)
    assert cache.get("osv_PyPI_urllib3_1.26.4", 86400) is None   # an outage must not become a 24h "all clear"


@pytest.mark.asyncio
async def test_offline_mode_warns_that_fixtures_are_not_the_repo(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CONTEXTVULN_OFFLINE", "1")
    _, warnings = await ThreatIntelAgent().analyze_with_warnings(str(tmp_path))
    assert any("NOT this repository" in w for w in warnings)
