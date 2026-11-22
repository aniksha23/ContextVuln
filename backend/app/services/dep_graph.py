"""
Dependency-exposure analysis (Member 1).

Problem: a pip-freeze style requirements.txt pins EVERY package, including transitive ones
(urllib3 pulled in by requests). The app never does `import urllib3`, so "not imported" looks like
"unused" - but calls into `requests` run urllib3 internals. Suppressing that CVE would be wrong.

Solution: read each pinned package's `requires_dist` from PyPI, build the dependency edges between
pinned packages, and find which pinned packages are (transitively) required by a package the app
really imports. Anything that cannot be verified is sent to NEEDS_REVIEW instead of being suppressed.
"""
import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional, Set

import httpx
from packaging.requirements import InvalidRequirement, Requirement


logger = logging.getLogger(__name__)

RequiresProvider = Callable[[str, str], Awaitable[Optional[List[str]]]]

_REQUIRES_CACHE: Dict[tuple, List[str]] = {}
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "site-packages", ".cache"}


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


async def pypi_requires_provider(name: str, version: str) -> Optional[List[str]]:
    """Normalised names of the packages `name==version` requires (extras-only deps ignored). None = unknown."""
    key = (norm(name), version)
    if key in _REQUIRES_CACHE:
        return _REQUIRES_CACHE[key]
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(f"https://pypi.org/pypi/{name}/{version}/json")
        if resp.status_code != 200:
            return None
        names: List[str] = []
        for line in resp.json().get("info", {}).get("requires_dist") or []:
            try:
                req = Requirement(line)
            except InvalidRequirement:
                continue
            if req.marker is not None and "extra" in str(req.marker):
                continue
            names.append(norm(req.name))
        _REQUIRES_CACHE[key] = names
        return names
    except Exception as e:
        logger.info("PyPI metadata lookup failed for %s==%s (%s)", name, version, type(e).__name__)
        return None


_PIN = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[.*?\])?\s*===?\s*([^\s;#]+)")


def read_all_pins(repo_path: str) -> Dict[str, str]:
    """name -> version for every '==' pin in every requirements*.txt (same scope as the intel agent)."""
    pins: Dict[str, str] = {}
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
        for f in files:
            if f.lower().startswith("requirements") and f.lower().endswith(".txt"):
                try:
                    with open(os.path.join(root, f), encoding="utf-8-sig", errors="ignore") as fh:
                        for line in fh:
                            m = _PIN.match(line.split("#", 1)[0].split(";", 1)[0])
                            if m:
                                pins.setdefault(norm(m.group(1)), m.group(2))
                except OSError:
                    pass
    return pins


@dataclass
class Exposure:
    # pinned package -> imported pinned packages that (transitively) require it
    ancestors: Dict[str, List[str]] = field(default_factory=dict)
    complete: bool = True        # False if metadata was missing for any pinned package
    pinned: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)


async def compute_exposure(
    pins: Dict[str, str],
    imported_pins: Set[str],
    provider: RequiresProvider,
    max_lookups: int = 150,
    concurrency: int = 8,
) -> Exposure:
    pins = {norm(k): v for k, v in pins.items()}
    imported_pins = {norm(p) for p in imported_pins}
    ex = Exposure(pinned=set(pins))
    names = list(pins)[:max_lookups]
    if len(pins) > max_lookups:
        ex.complete = False
        ex.notes.append(f"Only the first {max_lookups} of {len(pins)} pinned packages were inspected.")

    sem = asyncio.Semaphore(concurrency)

    async def one(n: str):
        async with sem:
            return n, await provider(n, pins[n])

    results = await asyncio.gather(*(one(n) for n in names), return_exceptions=True)
    edges: Dict[str, List[str]] = {}
    for r in results:
        if isinstance(r, Exception):
            ex.complete = False
            continue
        n, req = r
        if req is None:
            ex.complete = False
            ex.notes.append(f"No dependency metadata for {n}=={pins[n]}.")
            continue
        edges[n] = [c for c in req if c in pins]

    # BFS from every imported package across "requires" edges
    for root in imported_pins:
        seen, stack = set(), list(edges.get(root, []))
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(edges.get(cur, []))
        for child in seen:
            if child != root:
                ex.ancestors.setdefault(child, []).append(root)
    for k in ex.ancestors:
        ex.ancestors[k] = sorted(set(ex.ancestors[k]))
    return ex


_UNPINNED = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(\[.*?\])?\s*(>=|<=|~=|!=|<|>)")


def requirement_coverage_warnings(repo_path: str) -> List[str]:
    """Tell the user what was NOT scanned (an empty result must never look like 'all clear')."""
    unpinned: List[str] = []
    found_req = False
    other_manifests: Set[str] = set()
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
        for f in files:
            fl = f.lower()
            if fl in ("pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock", "setup.py", "setup.cfg", "package.json"):
                other_manifests.add(f)
            if fl.startswith("requirements") and fl.endswith(".txt"):
                found_req = True
                try:
                    with open(os.path.join(root, f), encoding="utf-8-sig", errors="ignore") as fh:
                        for line in fh:
                            line = line.split("#", 1)[0].split(";", 1)[0].strip()
                            m = _UNPINNED.match(line)
                            if m and "==" not in line:
                                unpinned.append(line)
                            elif line and re.match(r"^[A-Za-z0-9_.\-]+(\[.*?\])?$", line):
                                unpinned.append(line)  # bare name, no version at all
                except OSError:
                    pass
    warnings: List[str] = []
    if unpinned:
        eg = ", ".join(unpinned[:3])
        warnings.append(
            f"{len(unpinned)} requirement line(s) are not pinned with '==' and were NOT scanned (e.g. {eg}). "
            f"Pin exact versions or provide a lockfile for full coverage."
        )
    if not found_req:
        warnings.append("No requirements*.txt found: no dependencies were scanned.")
    unsupported = sorted(other_manifests & {"pyproject.toml", "Pipfile", "Pipfile.lock", "poetry.lock", "package.json"})
    if unsupported:
        warnings.append(f"Found {', '.join(unsupported)} - these formats are not parsed yet; their dependencies were not scanned.")
    return warnings
