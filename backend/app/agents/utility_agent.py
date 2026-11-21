import json
import os
import re
from typing import List, Optional, Tuple
import httpx

from app.core.config import settings
from app.core.schemas import RawVulnerability, ReachabilityResult, VulnerabilityFinding
from app.core.scoring import compute_utility_score


class UtilityPrioritizationAgent:
    """
    Agent 3: Combines deterministic Multi-Attribute Utility Theory scoring
    with Google AI Studio (Gemini) reasoning for reachable and ambiguous CVEs.
    """

    def __init__(self):
        self.api_key = settings.gemini_api_key
        self.model = settings.gemini_model

    @property
    def endpoint(self) -> str:
        return (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )

    async def prioritize_and_explain(
        self,
        vuln: RawVulnerability,
        reachability: ReachabilityResult,
        business_criticality: float = 1.0,
        repo_path: Optional[str] = None,
    ) -> VulnerabilityFinding:
        # 1. Deterministic Utility Calculation (Never delegated to LLM)
        score, tier = compute_utility_score(
            reachability_conf=reachability.confidence,
            epss_score=vuln.epss_score,
            cvss_score=vuln.cvss_score,
            is_in_kev=vuln.is_in_kev,
            business_criticality=business_criticality,
        )

        # 2. Token-Gated AI Reasoning: invoke Gemini only on confirmed reachable paths
        if reachability.is_reachable and self.api_key:
            code_context = self._extract_callsite_snippet(repo_path, reachability.call_path)
            reasoning, advice = await self._query_gemini_analysis(
                vuln=vuln,
                reachability=reachability,
                code_context=code_context,
                utility_score=score,
            )
        else:
            reasoning, advice = self._deterministic_fallback(vuln, reachability)

        return VulnerabilityFinding(
            cve_id=vuln.cve_id,
            package_name=vuln.package_name,
            installed_version=vuln.installed_version,
            fixed_version=vuln.fixed_version,
            vulnerable_symbols=vuln.vulnerable_symbols,
            is_reachable=reachability.is_reachable,
            reachability_confidence=reachability.confidence,
            call_path=reachability.call_path,
            cvss_score=vuln.cvss_score,
            epss_score=vuln.epss_score,
            is_in_kev=vuln.is_in_kev,
            utility_score=score,
            priority_tier=tier,
            ai_reasoning=reasoning,
            remediation_advice=advice,
        )

    async def resolve_ambiguous_symbols(
        self,
        vuln: RawVulnerability,
        existing_symbols: List[str],
        limitations: Optional[List[str]] = None,
    ) -> List[str]:
        """
        Candidate discovery helper for the cyclic investigation node.
        Proposes candidate Python function/method names for Agent 1 to verify
        deterministically in the AST call graph.
        """
        if not self.api_key:
            return existing_symbols

        limitations_text = "\n".join(limitations) if limitations else "None"
        prompt = (
            "You are a Python application security researcher.\n"
            "Given a CVE summary, package name, and any dynamic AST limitations detected, "
            'return a JSON object with a single key "symbols" containing a list of 1 to 3 '
            'exact Python function or method names (e.g., ["yaml.load", "yaml.unsafe_load"]) '
            "that are affected by this vulnerability.\n\n"
            f"CVE: {vuln.cve_id}\n"
            f"Package: {vuln.package_name}=={vuln.installed_version}\n"
            f"Summary: {vuln.summary}\n"
            f"Already tried symbols: {existing_symbols}\n"
            f"Dynamic AST limitations detected:\n{limitations_text}\n"
        )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    self.endpoint,
                    params={"key": self.api_key},
                    json=payload,
                )
                resp.raise_for_status()
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text)
                inferred = parsed.get("symbols", [])
                if isinstance(inferred, list):
                    cleaned = [str(s).strip() for s in inferred if str(s).strip()]
                    return list(dict.fromkeys(existing_symbols + cleaned))
        except Exception:
            pass

        return existing_symbols

    def _extract_callsite_snippet(
        self, repo_path: Optional[str], call_path: List[str]
    ) -> str:
        """Reads source lines around the caller right before the vulnerable sink."""
        if not repo_path or not call_path:
            return "Source code snippet unavailable."

        app_nodes = [node for node in call_path if ":" in node]
        if not app_nodes:
            return "Source code snippet unavailable."

        target_node = app_nodes[-1]
        rel_file = target_node.split(":", 1)[0].strip()
        full_file_path = os.path.join(repo_path, rel_file)

        if not os.path.isfile(full_file_path):
            return f"File reference: {target_node}"

        try:
            with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            line_match = re.search(r":(\d+)", target_node)
            if line_match:
                line_num = int(line_match.group(1))
                start = max(0, line_num - 10)
                end = min(len(lines), line_num + 15)
                snippet = "".join(f"{idx + 1}: {lines[idx]}" for idx in range(start, end))
            else:
                snippet = "".join(f"{idx + 1}: {lines[idx]}" for idx in range(min(50, len(lines))))

            return f"File: {rel_file}\n{snippet}"
        except Exception:
            return f"File reference: {target_node}"

    async def _query_gemini_analysis(
        self,
        vuln: RawVulnerability,
        reachability: ReachabilityResult,
        code_context: str,
        utility_score: float,
    ) -> Tuple[str, str]:
        """Calls Gemini REST API with strict JSON output for exploit context and fix."""
        prompt = (
            "You are a senior Application Security Engineer analyzing a confirmed reachable "
            "dependency vulnerability. Be concise, technical, and actionable.\n"
            "Respond strictly as valid JSON with exactly two string keys:\n"
            '- "ai_reasoning": 2-3 sentences explaining the attack vector along the call path '
            "and whether untrusted input could reach the vulnerable sink.\n"
            '- "remediation_advice": Concrete package upgrade version plus exact code-level fix.\n\n'
            f"Vulnerability: {vuln.cve_id} in {vuln.package_name}=={vuln.installed_version} "
            f"(Fixed in: {vuln.fixed_version or 'latest'})\n"
            f"Vulnerable Symbols: {', '.join(vuln.vulnerable_symbols)}\n"
            f"Summary: {vuln.summary}\n"
            f"Metrics: Utility={utility_score}/100, CVSS={vuln.cvss_score}, "
            f"EPSS={vuln.epss_score * 100:.1f}%, CISA_KEV={vuln.is_in_kev}\n"
            f"AST Call Path: {' -> '.join(reachability.call_path)}\n\n"
            "--- APPLICATION CODE CONTEXT ---\n"
            f"{code_context}\n"
            "--- END CODE CONTEXT ---\n"
        )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    self.endpoint,
                    params={"key": self.api_key},
                    json=payload,
                )
                resp.raise_for_status()
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text)
                reasoning = str(parsed.get("ai_reasoning", "")).strip()
                advice = str(parsed.get("remediation_advice", "")).strip()
                if reasoning and advice:
                    return reasoning, advice
        except Exception as e:
            fallback_reason, fallback_advice = self._deterministic_fallback(vuln, reachability)
            return f"{fallback_reason} (Gemini fallback: {type(e).__name__})", fallback_advice

        return self._deterministic_fallback(vuln, reachability)

    def _deterministic_fallback(
        self, vuln: RawVulnerability, reachability: ReachabilityResult
    ) -> Tuple[str, str]:
        if reachability.is_reachable:
            hop_type = "Direct" if reachability.confidence >= 0.9 else "Transitive"
            reasoning = (
                f"{hop_type} execution path confirmed to vulnerable symbol(s) "
                f"{', '.join(vuln.vulnerable_symbols)}. Live EPSS exploit probability is "
                f"{vuln.epss_score * 100:.1f}%."
            )
            fix_target = vuln.fixed_version or "latest patched release"
            first_sym = vuln.vulnerable_symbols[0] if vuln.vulnerable_symbols else "the sink"
            advice = (
                f"Immediate upgrade required: bump {vuln.package_name} to {fix_target} "
                f"and sanitize inputs entering {first_sym}."
            )
            return reasoning, advice

        reasoning = (
            f"Vulnerable symbol(s) {', '.join(vuln.vulnerable_symbols)} are never "
            f"imported or invoked in the application AST call graph."
        )
        advice = "Defer patch to routine maintenance; no reachable attack surface detected."
        return reasoning, advice