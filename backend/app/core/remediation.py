"""
Deterministic remediation helpers (no LLM). The LLM never chooses a version number;
it only writes optional code-patch prose on top of what is computed here.
"""
import difflib
import logging
import os
import re
from typing import List, Optional, Tuple

import httpx
from packaging.version import InvalidVersion, Version

from app.core.schemas import RemediationPlan

logger = logging.getLogger(__name__)

_REQ_FILES = ("requirements.txt", "requirements-prod.txt", "requirements/base.txt")


def _v(s: Optional[str]) -> Optional[Version]:
    if not s:
        return None
    try:
        return Version(s.strip())
    except InvalidVersion:
        return None


def upgrade_effort(installed: str, fixed: Optional[str]) -> str:
    """patch | minor | major | unknown, based on the jump from installed to fixed."""
    a, b = _v(installed), _v(fixed)
    if a is None or b is None or b <= a:
        return "unknown"
    if b.major != a.major:
        return "major"
    if b.minor != a.minor:
        return "minor"
    return "patch"


def find_requirement_file(repo_path: str, max_depth: int = 3) -> Optional[str]:
    """Shallow search for a requirements.txt (zip uploads often have one wrapper folder)."""
    base_depth = repo_path.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(repo_path):
        if root.count(os.sep) - base_depth >= max_depth:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__"}]
        for name in sorted(files):
            if name.lower() in ("requirements.txt",):
                return os.path.join(root, name)
    return None


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def build_requirements_diff(
    repo_path: Optional[str], package: str, installed: str, fixed: Optional[str]
) -> str:
    """Unified diff that bumps `package` in requirements.txt. Empty string if not applicable."""
    if not repo_path or not fixed:
        return ""
    req = find_requirement_file(repo_path)
    if not req:
        return ""
    try:
        with open(req, "r", encoding="utf-8-sig", errors="ignore") as f:
            old_lines = f.read().splitlines(keepends=True)
    except OSError:
        return ""

    pat = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(==|>=|~=|<=|<|>|!=)\s*([^\s;#,]+)(.*)$")
    new_lines, changed = [], False
    for line in old_lines:
        m = pat.match(line)
        if m and _norm(m.group(1)) == _norm(package):
            nl = "\n" if line.endswith("\n") else ""
            new_lines.append(f"{m.group(1)}=={fixed}{m.group(4).rstrip()}{nl}")
            changed = True
        else:
            new_lines.append(line)
    if not changed:
        return ""
    rel = os.path.relpath(req, repo_path).replace("\\", "/")
    return "".join(
        difflib.unified_diff(old_lines, new_lines, fromfile=f"a/{rel}", tofile=f"b/{rel}")
    )


async def pypi_version_exists(package: str, version: str, timeout: float = 5.0) -> Optional[bool]:
    """True/False if PyPI answers, None if we could not tell (offline etc.)."""
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(f"https://pypi.org/pypi/{package}/{version}/json")
        if r.status_code == 200:
            return True
        if r.status_code == 404:
            return False
    except Exception as e:  # network down, DNS, timeout ...
        logger.info("PyPI check skipped for %s==%s (%s)", package, version, type(e).__name__)
    return None


def build_remediation_plan(
    repo_path: Optional[str],
    package: str,
    installed: str,
    fixed: Optional[str],
    cve_id: str,
    reachable: bool,
) -> RemediationPlan:
    effort = upgrade_effort(installed, fixed)
    plan = RemediationPlan(
        upgrade_to=fixed,
        upgrade_effort=effort,
        requirements_diff=build_requirements_diff(repo_path, package, installed, fixed),
        pr_title=(f"fix(deps): bump {package} {installed} -> {fixed} ({cve_id})" if fixed else ""),
        quick_win=bool(reachable and fixed and effort in ("patch", "minor")),
    )
    if not fixed:
        plan.mitigations.append(
            f"No fixed release published for {package}. Restrict untrusted input to the affected "
            f"API, or replace the dependency."
        )
    elif effort == "major":
        plan.mitigations.append(
            f"Major version jump ({installed} -> {fixed}): read the changelog and run the test suite "
            f"before merging."
        )
    return plan


def apply_version_check(plan: RemediationPlan, ok: Optional[bool]) -> RemediationPlan:
    plan.version_validated = ok
    if ok is False:
        plan.mitigations.append(
            "The suggested fixed version was not found on PyPI - verify it manually before upgrading."
        )
    return plan
