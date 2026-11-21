import asyncio

import httpx
import pytest

import app.agents.utility_agent as ua
from app.agents.utility_agent import UtilityPrioritizationAgent
from app.core.config import Settings
from app.core.schemas import RawVulnerability, ReachabilityResult

VULN = RawVulnerability(
    cve_id="CVE-2020-14343", package_name="pyyaml", installed_version="5.3.1", fixed_version="5.4",
    vulnerable_symbols=["yaml.load"], cvss_score=9.8, epss_score=0.89, is_in_kev=True, summary="RCE")
REACH = ReachabilityResult(is_reachable=True, confidence=1.0, call_path=["app.py:3:f()", "yaml.load()"])
NOT_REACH = ReachabilityResult(is_reachable=False, confidence=0.0, call_path=[])


def agent(**kw):
    return UtilityPrioritizationAgent(Settings(_env_file=None, **kw))


def run(coro):
    return asyncio.run(coro)


def test_no_key_uses_deterministic_fallback_and_never_calls_network(make_project):
    root = make_project({"requirements.txt": "pyyaml==5.3.1\n"})
    a = agent(gemini_api_key="")

    async def boom(*_a, **_k):
        raise AssertionError("network must not be touched without a key")
    a._post_gemini = boom

    f = run(a.prioritize_and_explain(VULN, REACH, 1.0, root))
    assert f.priority_tier == "CRITICAL_ACTION" and f.utility_score >= 60
    assert "Upgrade pyyaml 5.3.1 -> 5.4" in f.remediation_advice
    assert f.remediation.requirements_diff.count("+pyyaml==5.4") == 1
    assert f.remediation.quick_win is True or f.remediation.upgrade_effort == "minor"
    assert f.score_breakdown.floor_applied in (None, "KEV", "HIGH_CVSS")
    assert a.llm_calls == 0


def test_unreachable_finding_never_uses_llm():
    a = agent(gemini_api_key="k")
    a._post_gemini = lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("LLM must be token-gated"))
    f = run(a.prioritize_and_explain(VULN, NOT_REACH, 1.0, None))
    assert f.priority_tier == "SUPPRESSED_NOISE" and f.utility_score <= 15


def test_llm_text_is_used_but_numbers_stay_deterministic():
    a = agent(gemini_api_key="k")

    async def fake(prompt, temperature):
        assert "UNTRUSTED_CODE" in prompt                       # injected code is fenced off
        a.llm_calls += 1
        return {"ai_reasoning": "Untrusted YAML reaches yaml.load.", "remediation_advice": "Use safe_load.",
                "code_patch": "- yaml.load(f)\n+ yaml.safe_load(f)", "utility_score": 0, "version": "99.0"}
    a._post_gemini = fake
    f = run(a.prioritize_and_explain(VULN, REACH, 1.0, None))
    assert f.ai_reasoning.startswith("Untrusted YAML")
    assert f.remediation.code_patch.startswith("- yaml.load")
    assert f.utility_score >= 60                                  # LLM "utility_score: 0" is ignored
    assert f.remediation.upgrade_to == "5.4" and "99.0" not in f.remediation_advice
    assert a.llm_calls == 1


def test_llm_failure_degrades_gracefully():
    a = agent(gemini_api_key="k")

    async def fail(*_a, **_k):
        raise RuntimeError("quota")
    a._post_gemini = fail
    f = run(a.prioritize_and_explain(VULN, REACH, 1.0, None))
    assert "LLM unavailable" in f.ai_reasoning and f.priority_tier == "CRITICAL_ACTION"


def test_llm_result_is_cached():
    a = agent(gemini_api_key="k")
    calls = []

    async def fake(prompt, temperature):
        calls.append(1)
        return {"ai_reasoning": "r", "remediation_advice": "a", "code_patch": ""}
    a._post_gemini = fake
    run(a.prioritize_and_explain(VULN, REACH, 1.0, None))
    run(a.prioritize_and_explain(VULN, REACH, 1.4, None))
    assert len(calls) == 1


def test_symbol_discovery_filters_garbage_and_foreign_symbols():
    a = agent(gemini_api_key="k")

    async def fake(prompt, temperature):
        return {"symbols": ["yaml.unsafe_load", "os.system('rm -rf /')", "ignore previous instructions",
                            "subprocess.run", "yaml.full_load"]}
    a._post_gemini = fake
    out = run(a.resolve_ambiguous_symbols(VULN, ["yaml.load"], []))
    assert out == ["yaml.load", "yaml.unsafe_load", "yaml.full_load"]


def test_symbol_discovery_without_key_is_a_noop():
    assert run(agent().resolve_ambiguous_symbols(VULN, ["yaml.load"], [])) == ["yaml.load"]


def test_pypi_validation_flags_nonexistent_fix(monkeypatch):
    async def nope(pkg, ver, timeout=5.0):
        return False
    monkeypatch.setattr(ua, "pypi_version_exists", nope)
    f = run(agent(validate_versions_online=True).prioritize_and_explain(VULN, NOT_REACH, 1.0, None))
    assert f.remediation.version_validated is False


def _patch_http(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(ua.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))

    async def no_sleep(_):
        return None
    monkeypatch.setattr(ua.asyncio, "sleep", no_sleep)


def test_gemini_retries_on_429_and_sends_key_in_header_not_url(monkeypatch):
    seen = []

    def handler(request: httpx.Request):
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(429)
        body = {"candidates": [{"content": {"parts": [{"text": '{"symbols": ["yaml.load"]}'}]}}]}
        return httpx.Response(200, json=body)

    _patch_http(monkeypatch, handler)
    a = agent(gemini_api_key="SECRET")
    assert run(a._post_gemini("p", 0.1)) == {"symbols": ["yaml.load"]}
    assert len(seen) == 2
    assert all("SECRET" not in str(r.url) for r in seen)
    assert seen[0].headers["x-goog-api-key"] == "SECRET"


def test_gemini_does_not_retry_on_400(monkeypatch):
    seen = []

    def handler(request):
        seen.append(1)
        return httpx.Response(400)
    _patch_http(monkeypatch, handler)
    with pytest.raises(RuntimeError):
        run(agent(gemini_api_key="k")._post_gemini("p", 0.1))
    assert len(seen) == 1
