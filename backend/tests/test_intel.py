"""Unit and integration tests for Threat Intelligence Agent (Agent 2).

All HTTP requests are mocked with respx for hermetic offline testing.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import time
from typing import Any

import pytest
import respx
import httpx

from app.core.schemas import RawVulnerability
from app.agents.intel_agent import (
    ThreatIntelAgent,
    DiskCache,
    DependencyEntry,
    extract_dependencies,
    _parse_requirements_file,
    compute_cvss_score,
    extract_fixed_version,
    extract_summary,
    extract_structured_symbols,
    extract_curated_symbols,
    extract_heuristic_symbols,
    extract_fallback_symbols,
    map_vulnerable_symbols,
    fetch_epss_scores,
    fetch_cisa_kev,
    query_osv_package,
    OSV_QUERY_URL,
    EPSS_API_URL,
    CISA_KEV_URL,
)


# ---------------------------------------------------------------------------
# Test Data Fixtures
# ---------------------------------------------------------------------------
URLLIB3_OSV_PAGE_1 = {
    "vulns": [
        {
            "id": "GHSA-q2x7-8rv6-6q7h",
            "aliases": ["CVE-2021-33503"],
            "summary": "Catastrophic ReDoS in URL authority parser",
            "details": "urllib3 before 1.26.5 contains a vulnerability in urllib3.util.parse_url.",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # 7.5
                }
            ],
            "affected": [
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.26.5"}],
                        }
                    ],
                }
            ],
        },
        {
            "id": "PYSEC-2021-108",
            "aliases": ["CVE-2021-33503"],
            "summary": "",
            "details": "Catastrophic ReDoS in URL authority parser for urllib3.util.parse_url().",
            "severity": [],
            "database_specific": {"severity": "HIGH"},
            "affected": [
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.26.5"}],
                        }
                    ],
                }
            ],
        },
    ],
    "next_page_token": "page2_token",
}

URLLIB3_OSV_PAGE_2 = {
    "vulns": [
        {
            "id": "GHSA-v845-jxx5-vc9f",
            "aliases": ["CVE-2023-43804"],
            "summary": "Cookie header retained on cross-origin redirects",
            "details": "urllib3 does not strip Cookie request headers on cross-origin redirects.",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9
                }
            ],
            "affected": [
                {
                    "package": {"name": "urllib3", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.26.17"}],
                        }
                    ],
                }
            ],
        }
    ]
}

NO_CVE_OSV_PAYLOAD = {
    "vulns": [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": ["PYSEC-2099-999"],  # No CVE alias
            "summary": "Internal advisory with no CVE ID",
            "details": "A flaw exists in internal_helper().",
            "severity": [],
            "database_specific": {"severity": "MODERATE"},
            "affected": [
                {
                    "package": {"name": "custom-pkg", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        }
                    ],
                }
            ],
        }
    ]
}

SAMPLE_KEV_CATALOG = {
    "title": "CISA Known Exploited Vulnerabilities",
    "catalogVersion": "2024.01.01",
    "vulnerabilities": [
        {
            "cveID": "CVE-2020-14343",
            "vendorProject": "PyYAML",
            "product": "PyYAML",
            "vulnerabilityName": "PyYAML Arbitrary Code Execution",
        },
        {
            "cveID": "CVE-2021-33503",
            "vendorProject": "urllib3",
            "product": "urllib3",
            "vulnerabilityName": "urllib3 ReDoS",
        },
    ],
}


# ===========================================================================
# 1. Requirements Parsing Tests
# ===========================================================================
def test_parse_requirements_pins_and_syntax(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        """
        # Top-level comment
        urllib3==1.26.4
        requests[security]==2.25.1 # with extra and inline comment
        flake8===3.9.2
        black>=21.5b1 ; python_version > '3.6'
        pytest~=6.2.0
        git+https://github.com/psf/requests.git
        -e .
        scipy ; python_version >= '3.9'
        pyyaml==5.3.1; sys_platform == 'linux'
        """,
        encoding="utf-8",
    )

    deps = _parse_requirements_file(req_file)
    pkg_map = {d.normalized_name: (d.package_name, d.version) for d in deps}

    assert "urllib3" in pkg_map
    assert pkg_map["urllib3"] == ("urllib3", "1.26.4")

    assert "requests" in pkg_map
    assert pkg_map["requests"] == ("requests", "2.25.1")

    assert "flake8" in pkg_map
    assert pkg_map["flake8"] == ("flake8", "3.9.2")

    assert "pyyaml" in pkg_map
    assert pkg_map["pyyaml"] == ("pyyaml", "5.3.1")

    # Unpinned or VCS or -e lines must be skipped
    assert "black" not in pkg_map
    assert "pytest" not in pkg_map
    assert "scipy" not in pkg_map


def test_parse_requirements_includes_and_cycle_guard(tmp_path: Path):
    req_base = tmp_path / "requirements.txt"
    req_dev = tmp_path / "requirements-dev.txt"
    req_extra = tmp_path / "requirements-extra.txt"

    # base -> dev -> extra -> base (cycle)
    req_base.write_text("urllib3==1.26.4\n-r requirements-dev.txt\n", encoding="utf-8")
    req_dev.write_text("pytest==7.0.1\n-r requirements-extra.txt\n", encoding="utf-8")
    req_extra.write_text("pyyaml==5.4.1\n-r requirements.txt\n", encoding="utf-8")

    deps = extract_dependencies(str(tmp_path))
    names = {d.normalized_name for d in deps}
    assert "urllib3" in names
    assert "pytest" in names
    assert "pyyaml" in names


def test_extract_dependencies_excluded_dirs(tmp_path: Path):
    # Valid requirements.txt in root
    (tmp_path / "requirements.txt").write_text("urllib3==1.26.4\n", encoding="utf-8")

    # Excluded directories with invalid or extra requirements
    venv_dir = tmp_path / "venv"
    venv_dir.mkdir()
    (venv_dir / "requirements.txt").write_text("should-ignore==9.9.9\n", encoding="utf-8")

    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "requirements.txt").write_text("git-ignore==1.0.0\n", encoding="utf-8")

    deps = extract_dependencies(str(tmp_path))
    assert len(deps) == 1
    assert deps[0].normalized_name == "urllib3"
    assert deps[0].version == "1.26.4"


def test_extract_dependencies_empty(tmp_path: Path):
    deps = extract_dependencies(str(tmp_path))
    assert deps == []


def test_npm_package_lock_support(tmp_path: Path):
    lock_file = tmp_path / "package-lock.json"
    lock_content = {
        "name": "sample-npm-app",
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "sample-npm-app", "version": "1.0.0"},
            "node_modules/lodash": {"name": "lodash", "version": "4.17.21"},
            "node_modules/axios": {"version": "0.21.1"},
        },
    }
    lock_file.write_text(json.dumps(lock_content), encoding="utf-8")

    deps = extract_dependencies(str(tmp_path))
    npm_deps = {d.package_name: (d.version, d.ecosystem) for d in deps}
    assert "lodash" in npm_deps
    assert npm_deps["lodash"] == ("4.17.21", "npm")
    assert "axios" in npm_deps
    assert npm_deps["axios"] == ("0.21.1", "npm")


# ===========================================================================
# 2. OSV Parsing & Pagination Tests
# ===========================================================================
@pytest.mark.asyncio
@respx.mock
async def test_osv_parsing_pagination_and_deduplication(tmp_path: Path):
    def osv_side_effect(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if body.get("page_token") == "page2_token":
            return httpx.Response(200, json=URLLIB3_OSV_PAGE_2)
        return httpx.Response(200, json=URLLIB3_OSV_PAGE_1)

    respx.post(OSV_QUERY_URL).mock(side_effect=osv_side_effect)
    # Mock EPSS
    respx.get(EPSS_API_URL).respond(
        200,
        json={
            "data": [
                {"cve": "CVE-2021-33503", "epss": "0.0025"},
                {"cve": "CVE-2023-43804", "epss": "0.0012"},
            ]
        },
    )
    # Mock KEV
    respx.get(CISA_KEV_URL).respond(200, json=SAMPLE_KEV_CATALOG)

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.4\n", encoding="utf-8")

    agent = ThreatIntelAgent()
    # Force fresh cache in temp folder
    agent.cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    results = await agent.analyze_dependencies(str(tmp_path))

    # Should find 2 merged CVEs: CVE-2021-33503 and CVE-2023-43804
    cve_map = {r.cve_id: r for r in results}
    assert "CVE-2021-33503" in cve_map
    assert "CVE-2023-43804" in cve_map

    cve_1 = cve_map["CVE-2021-33503"]
    assert cve_1.package_name == "urllib3"
    assert cve_1.installed_version == "1.26.4"
    assert cve_1.fixed_version == "1.26.5"
    assert cve_1.cvss_score == 7.5
    assert cve_1.epss_score == 0.0025
    assert cve_1.is_in_kev is True
    assert "Catastrophic ReDoS" in cve_1.summary

    cve_2 = cve_map["CVE-2023-43804"]
    assert cve_2.cvss_score == 5.9
    assert cve_2.fixed_version == "1.26.17"
    assert cve_2.epss_score == 0.0012
    assert cve_2.is_in_kev is False

    # Check sorting by CVSS score descending
    assert results[0].cvss_score >= results[1].cvss_score


# ===========================================================================
# 3. Non-CVE Advisory Fallback
# ===========================================================================
@pytest.mark.asyncio
@respx.mock
async def test_advisory_without_cve_id(tmp_path: Path):
    respx.post(OSV_QUERY_URL).respond(200, json=NO_CVE_OSV_PAYLOAD)
    respx.get(CISA_KEV_URL).respond(200, json={"vulnerabilities": []})
    epss_route = respx.get(EPSS_API_URL).respond(200, json={"data": []})

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("custom-pkg==1.0.0\n", encoding="utf-8")

    agent = ThreatIntelAgent()
    agent.cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    results = await agent.analyze_dependencies(str(tmp_path))
    assert len(results) == 1
    item = results[0]
    assert item.cve_id == "GHSA-xxxx-yyyy-zzzz"
    assert item.cvss_score == 5.5  # Approximated from MODERATE
    assert item.epss_score == 0.0  # Skipped EPSS
    assert item.is_in_kev is False
    assert not epss_route.called  # Ensured EPSS was not called for non-CVE ID


# ===========================================================================
# 4. EPSS Batching, Clamping, and Failure Handling
# ===========================================================================
@pytest.mark.asyncio
@respx.mock
async def test_epss_parsing_and_clamping(tmp_path: Path):
    cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    # 1. Normal batch parsing
    respx.get(EPSS_API_URL).respond(
        200,
        json={
            "data": [
                {"cve": "CVE-2021-1111", "epss": "0.85"},
                {"cve": "CVE-2021-2222", "epss": "1.5"},  # Clamped to 1.0
                {"cve": "CVE-2021-3333", "epss": "-0.5"}, # Clamped to 0.0
            ]
        },
    )

    async with httpx.AsyncClient() as client:
        scores = await fetch_epss_scores(
            client, cache, ["CVE-2021-1111", "CVE-2021-2222", "CVE-2021-3333", "CVE-2021-4444"]
        )

    assert scores["CVE-2021-1111"] == 0.85
    assert scores["CVE-2021-2222"] == 1.0
    assert scores["CVE-2021-3333"] == 0.0
    assert scores["CVE-2021-4444"] == 0.0  # Missing CVE defaults to 0.0


@pytest.mark.asyncio
@respx.mock
async def test_epss_api_failure(tmp_path: Path):
    cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)
    respx.get(EPSS_API_URL).respond(500)

    async with httpx.AsyncClient() as client:
        scores = await fetch_epss_scores(client, cache, ["CVE-2021-1234"])

    assert scores["CVE-2021-1234"] == 0.0


# ===========================================================================
# 5. CISA KEV Match, Non-Match, and Failure
# ===========================================================================
@pytest.mark.asyncio
@respx.mock
async def test_cisa_kev_flow(tmp_path: Path):
    cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    # Success case
    respx.get(CISA_KEV_URL).respond(200, json=SAMPLE_KEV_CATALOG)
    async with httpx.AsyncClient() as client:
        kev_set = await fetch_cisa_kev(client, cache)

    assert "CVE-2020-14343" in kev_set
    assert "CVE-2021-33503" in kev_set
    assert "CVE-9999-9999" not in kev_set

    # Cached hit test
    async with httpx.AsyncClient() as client:
        cached_set = await fetch_cisa_kev(client, cache)
    assert cached_set == kev_set

    # Failure case with empty cache
    empty_cache = DiskCache(cache_dir=str(tmp_path / "empty_cache"), disabled=False)
    respx.get(CISA_KEV_URL).respond(500)
    async with httpx.AsyncClient() as client:
        failed_set = await fetch_cisa_kev(client, empty_cache)
    assert failed_set == set()


# ===========================================================================
# 6. Cache Hit, Expiry, and Bypass
# ===========================================================================
def test_disk_cache_behavior(tmp_path: Path, monkeypatch):
    cache_dir = tmp_path / "cache"
    cache = DiskCache(cache_dir=str(cache_dir), disabled=False)

    # 1. Set and get hit
    cache.set("key1", {"value": 42})
    assert cache.get("key1", ttl=60) == {"value": 42}

    # 2. TTL Expiry
    time.sleep(0.01)
    assert cache.get("key1", ttl=0.001) is None

    # 3. Bypass via CONTEXTVULN_NO_CACHE=1
    monkeypatch.setenv("CONTEXTVULN_NO_CACHE", "1")
    bypass_cache = DiskCache(cache_dir=str(cache_dir))
    bypass_cache.set("key2", {"value": 100})
    assert bypass_cache.get("key2", ttl=60) is None


# ===========================================================================
# 7. Resilience: Timeout / 500 on One Package
# ===========================================================================
@pytest.mark.asyncio
@respx.mock
async def test_resilience_partial_failure(tmp_path: Path):
    # urllib3 fails with 500
    respx.post(OSV_QUERY_URL, json__package__name="urllib3").respond(500)
    # pyyaml succeeds
    respx.post(OSV_QUERY_URL, json__package__name="pyyaml").respond(
        200,
        json={
            "vulns": [
                {
                    "id": "GHSA-8q59-q68h-6hv4",
                    "aliases": ["CVE-2020-14343"],
                    "summary": "Arbitrary code execution in PyYAML",
                    "details": "PyYAML before 5.4 lacks proper restriction on yaml.load.",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "affected": [
                        {
                            "package": {"name": "pyyaml", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "5.4"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )
    respx.get(EPSS_API_URL).respond(
        200, json={"data": [{"cve": "CVE-2020-14343", "epss": "0.89"}]}
    )
    respx.get(CISA_KEV_URL).respond(200, json=SAMPLE_KEV_CATALOG)

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.4\npyyaml==5.3.1\n", encoding="utf-8")

    agent = ThreatIntelAgent()
    agent.cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    results = await agent.analyze_dependencies(str(tmp_path))
    # urllib3 failed but pyyaml succeeded and returned results
    assert len(results) == 1
    assert results[0].package_name == "pyyaml"
    assert results[0].cve_id == "CVE-2020-14343"
    assert results[0].cvss_score == 9.8


# ===========================================================================
# 8. Symbol Mapping Tiers & Noise Filtering
# ===========================================================================
def test_symbol_mapping_tier_structured():
    vuln = {
        "affected": [
            {
                "package": {"name": "sample-pkg", "ecosystem": "PyPI"},
                "ecosystem_specific": {
                    "functions": ["sample_pkg.core.vulnerable_function", "vulnerable_function"]
                },
            }
        ]
    }
    symbols = extract_structured_symbols(vuln, "sample-pkg")
    assert symbols == ["sample_pkg.core.vulnerable_function", "vulnerable_function"]


def test_symbol_mapping_tier_curated(tmp_path: Path):
    custom_known_symbols = {
        "urllib3": {
            "CVE-2021-33503": {
                "symbols": ["urllib3.util.url.parse_url", "urllib3.util.parse_url"],
                "needs_review": False,
            }
        }
    }
    symbols = extract_curated_symbols(
        custom_known_symbols,
        normalized_pkg="urllib3",
        cve_id="CVE-2021-33503",
        aliases=[],
    )
    assert symbols == ["urllib3.util.url.parse_url", "urllib3.util.parse_url"]


def test_symbol_mapping_tier_heuristics_and_noise_filtering():
    summary = "A ReDoS vulnerability was discovered in `urllib3.util.url.parse_url`."
    details = (
        "The issue affects the `parse_url()` function in urllib3. "
        "An attacker can pass a malicious URL header to cause denial of service."
    )
    symbols = extract_heuristic_symbols(summary, details, "urllib3", "urllib3")

    # Dotted identifier should be prioritized
    assert "urllib3.util.url.parse_url" in symbols
    # Short function name emitted
    assert "parse_url" in symbols
    # Common English words/noise tokens must NOT be present
    assert "header" not in symbols
    assert "service" not in symbols
    assert "denial" not in symbols
    assert "url" not in symbols


def test_heuristic_filtering_noisy_symbols_and_parameters():
    summary = "Security update regarding urllib3"
    details = (
        "Affects `urllib3.readthedocs.io`, `urllib3.response.html`, and formats `deflate`, `zstd`, `gzip`, `html`. "
        "May trigger `FutureWarning`. Sets `Authorization` HTTP header. "
        "Contains parameters: `cert_reqs`, `verify_mode`, `ssl_context`, `proxy_ssl_context`, "
        "`proxy_assert_hostname`, `proxy_assert_fingerprint`, `retries`. "
        "Calls standard methods: `stream()`, `read()`, `request()`, `urlopen()`. "
        "Specifically affects the [read_chunked()](https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.read_chunked) "
        "method and `urllib3.util.retry.Retry`."
    )
    symbols = extract_heuristic_symbols(summary, details, "urllib3", "urllib3")

    bad_examples = [
        "urllib3.readthedocs.io",
        "urllib3.response.html",
        "deflate",
        "zstd",
        "gzip",
        "html",
        "FutureWarning",
        "Authorization",
        "cert_reqs",
        "verify_mode",
        "ssl_context",
        "proxy_ssl_context",
        "proxy_assert_hostname",
        "proxy_assert_fingerprint",
        "retries",
        "stream",
        "read",
        "request",
        "urlopen",
    ]

    for bad in bad_examples:
        assert bad not in symbols, f"Noisy symbol '{bad}' was not filtered out: {symbols}"

    # Assert good symbols are kept
    assert "urllib3.response.BaseHTTPResponse.read_chunked" in symbols
    assert "urllib3.util.retry.Retry" in symbols
    assert "read_chunked" in symbols
    assert "Retry" in symbols


def test_heuristic_empty_falls_back_to_package_tier():
    # Only noisy parameters and warnings, no callables
    vuln_noise = {
        "summary": "TLS configuration parameters",
        "details": "`proxy_ssl_context`, `proxy_assert_hostname`, `verify_mode`, and `FutureWarning` are mentioned.",
    }
    syms, tier = map_vulnerable_symbols(vuln_noise, "CVE-2026-97687", "urllib3", "urllib3", {})
    assert tier == "fallback"
    assert syms == ["urllib3"]



def test_symbol_mapping_tier_fallback():
    symbols = extract_fallback_symbols("my-custom-library", "my-custom-library")
    assert symbols == ["my_custom_library"]


def test_map_vulnerable_symbols_priority_flow():
    # 1. Structured wins when present
    vuln_structured = {
        "affected": [
            {
                "package": {"name": "testpkg", "ecosystem": "PyPI"},
                "database_specific": {"symbols": ["testpkg.vulnerable_call"]},
            }
        ],
        "summary": "Mentions other `testpkg.other_call`",
    }
    syms, tier = map_vulnerable_symbols(vuln_structured, "CVE-9999-0001", "testpkg", "testpkg", {})
    assert tier == "structured"
    assert "testpkg.vulnerable_call" in syms

    # 2. Curated wins when structured absent
    vuln_curated = {
        "summary": "Mentions `testpkg.heuristic_call`",
    }
    known = {"testpkg": {"CVE-9999-0002": {"symbols": ["testpkg.curated_call"]}}}
    syms, tier = map_vulnerable_symbols(vuln_curated, "CVE-9999-0002", "testpkg", "testpkg", known)
    assert tier == "curated"
    assert "testpkg.curated_call" in syms

    # 3. Heuristic wins when structured & curated absent
    vuln_heuristic = {
        "summary": "Found in `testpkg.heuristic_call` function",
    }
    syms, tier = map_vulnerable_symbols(vuln_heuristic, "CVE-9999-0003", "testpkg", "testpkg", {})
    assert tier == "heuristics"
    assert "testpkg.heuristic_call" in syms

    # 4. Fallback when nothing found
    vuln_empty = {"summary": "Generic bug in code without function names"}
    syms, tier = map_vulnerable_symbols(vuln_empty, "CVE-9999-0004", "testpkg", "testpkg", {})
    assert tier == "fallback"
    assert syms == ["testpkg"]


# ===========================================================================
# 9. End-to-End analyze_dependencies Test
# ===========================================================================
@pytest.mark.asyncio
@respx.mock
async def test_end_to_end_analyze_dependencies(tmp_path: Path):
    respx.post(OSV_QUERY_URL).respond(
        200,
        json={
            "vulns": [
                {
                    "id": "GHSA-q2x7-8rv6-6q7h",
                    "aliases": ["CVE-2021-33503"],
                    "summary": "Catastrophic ReDoS in URL authority parser",
                    "details": "urllib3 before 1.26.5 contains a vulnerability in urllib3.util.parse_url.",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        }
                    ],
                    "affected": [
                        {
                            "package": {"name": "urllib3", "ecosystem": "PyPI"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "1.26.5"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        },
    )
    respx.get(EPSS_API_URL).respond(
        200, json={"data": [{"cve": "CVE-2021-33503", "epss": "0.002"}]}
    )
    respx.get(CISA_KEV_URL).respond(200, json=SAMPLE_KEV_CATALOG)

    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.4\n", encoding="utf-8")

    agent = ThreatIntelAgent()
    agent.cache = DiskCache(cache_dir=str(tmp_path / "cache"), disabled=False)

    results = await agent.analyze_dependencies(str(tmp_path))

    assert len(results) == 1
    v = results[0]
    assert isinstance(v, RawVulnerability)
    assert v.cve_id == "CVE-2021-33503"
    assert v.package_name == "urllib3"
    assert v.installed_version == "1.26.4"
    assert v.fixed_version == "1.26.5"
    assert v.cvss_score == 7.5
    assert v.epss_score == 0.002
    assert v.is_in_kev is True
    assert len(v.vulnerable_symbols) > 0
    assert any("parse_url" in s for s in v.vulnerable_symbols)


# ===========================================================================
# 10. Offline Mode Test
# ===========================================================================
@pytest.mark.asyncio
async def test_offline_mode_fixture(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("CONTEXTVULN_OFFLINE", "1")
    agent = ThreatIntelAgent()

    results = await agent.analyze_dependencies(str(tmp_path))
    assert len(results) >= 4
    cve_ids = {r.cve_id for r in results}
    assert "CVE-2021-33503" in cve_ids
    assert "CVE-2023-45803" in cve_ids
    assert "CVE-2023-43804" in cve_ids
    assert "CVE-2024-37891" in cve_ids
    for r in results:
        assert isinstance(r, RawVulnerability)
        assert r.package_name == "urllib3"
        assert r.installed_version == "1.26.4"


# ===========================================================================
# 11. Live Network Test (Skipped by default)
# ===========================================================================
@pytest.mark.live
@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("RUN_LIVE_TESTS") != "1",
    reason="Live network test skipped by default. Run with RUN_LIVE_TESTS=1.",
)
async def test_live_network_api(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.4\n", encoding="utf-8")

    agent = ThreatIntelAgent()
    results = await agent.analyze_dependencies(str(tmp_path))

    assert len(results) > 0
    for r in results:
        assert isinstance(r, RawVulnerability)
        assert r.package_name == "urllib3"
        assert r.installed_version == "1.26.4"
