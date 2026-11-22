"""Threat Intelligence Agent (Agent 2) for ContextVuln.

Extracts dependencies, queries OSV.dev, enriches with EPSS and CISA KEV,
maps affected symbols using a 4-tier strategy, and outputs RawVulnerability models.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, List, Optional, Set, Tuple

import cvss
import httpx

from app.core.schemas import RawVulnerability

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

DEFAULT_CACHE_DIR = ".cache/intel"
OSV_CACHE_TTL = 86400    # 24 hours
EPSS_CACHE_TTL = 86400   # 24 hours
KEV_CACHE_TTL = 43200    # 12 hours

MAX_CONCURRENT_OSV_REQUESTS = 8
EPSS_BATCH_SIZE = 50
HTTP_TIMEOUT = 10.0
HTTP_MAX_RETRIES = 3

EXCLUDED_DIR_NAMES = {
    "venv", ".venv", "env", "node_modules", ".git", "__pycache__", "site-packages", ".cache"
}

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

KNOWN_SYMBOLS_PATH = Path(__file__).resolve().parent / "data" / "known_symbols.json"

# Stopwords and noise tokens for heuristic symbol extraction
HEURISTIC_STOPWORDS = {
    "the", "in", "for", "with", "and", "or", "to", "of", "a", "an", "is", "by", "from",
    "as", "on", "at", "not", "be", "it", "this", "that", "user", "data", "request",
    "requests", "response", "responses", "header", "headers", "value", "values", "url",
    "urls", "file", "files", "error", "errors", "server", "servers", "client", "clients",
    "connection", "connections", "default", "defaults", "string", "strings", "parameter",
    "parameters", "argument", "arguments", "issue", "version", "python", "package", "method",
    "function", "class", "module", "true", "false", "none", "self", "return", "exception",
    "cookie", "cookies", "redirect", "redirects", "proxy", "proxies", "body", "cve", "osv",
    "pypi", "github", "advisory", "security", "vulnerability", "vulnerabilities", "fixed",
    "introduced", "versions", "affected", "reported", "resolved", "attacker", "attackers",
    "application", "applications", "remote", "local", "code", "execution", "denial", "service"
}

GENERIC_METHOD_BLOCKLIST = {
    "read", "write", "stream", "request", "get", "post", "open", "close",
    "send", "urlopen", "run", "load", "parse", "html", "data", "text",
    "content", "headers"
}

TLD_EXTENSION_PATTERN = re.compile(
    r"\.(?:io|com|org|net|dev|html|md|txt|rst|py|json|xml|gov|edu|info)(?:$|[./])",
    re.IGNORECASE,
)

FORMAT_PROTOCOL_WORDS = {
    "gzip", "deflate", "zstd", "brotli", "html", "json", "http", "https",
    "ssl", "tls", "utf-8", "utf8", "ascii", "tar", "zip", "xml", "yaml",
    "csv", "binary", "base64", "chunked", "raw"
}

HTTP_HEADER_NAMES = {
    "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "Host",
    "User-Agent", "Accept", "Accept-Encoding", "Accept-Language", "Content-Type",
    "Content-Length", "Location", "Referer", "Origin", "Connection", "Upgrade",
    "Keep-Alive", "Transfer-Encoding", "Cache-Control", "Pragma", "Range",
    "Server", "Date", "ETag", "If-Modified-Since", "If-None-Match"
}

PACKAGE_MODULE_MAP = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "protobuf": "google.protobuf",
}

# ---------------------------------------------------------------------------
# Internal Dataclasses
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DependencyEntry:
    package_name: str
    normalized_name: str
    version: str
    source_file: str
    ecosystem: str = "PyPI"


# ---------------------------------------------------------------------------
# Cache Implementation
# ---------------------------------------------------------------------------
class DiskCache:
    """Disk-backed JSON cache with configurable TTL and bypass support."""

    def __init__(self, cache_dir: Optional[str] = None, disabled: bool = False) -> None:
        self.disabled = disabled or (os.environ.get("CONTEXTVULN_NO_CACHE") == "1")
        base_dir = cache_dir or os.environ.get("CONTEXTVULN_CACHE_DIR", DEFAULT_CACHE_DIR)
        self.cache_dir = Path(base_dir)
        if not self.disabled:
            try:
                self.cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError as err:
                logger.warning("Failed to create cache directory %s: %s; disabling cache.", self.cache_dir, err)
                self.disabled = True

    def _file_path(self, key: str) -> Path:
        hashed = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"{hashed}.json"

    def get(self, key: str, ttl: float) -> Optional[Any]:
        if self.disabled:
            return None
        target = self._file_path(key)
        if not target.is_file():
            return None
        try:
            with open(target, "r", encoding="utf-8") as f:
                payload = json.load(f)
            created_at = payload.get("created_at", 0)
            if time.time() - created_at < ttl:
                return payload.get("data")
            # Expired
            return None
        except Exception as err:
            logger.debug("Cache read error for key %s: %s", key, err)
            return None

    def set(self, key: str, data: Any) -> None:
        if self.disabled:
            return
        target = self._file_path(key)
        try:
            tmp_target = target.with_suffix(".tmp")
            payload = {"created_at": time.time(), "data": data}
            with open(tmp_target, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            tmp_target.replace(target)
        except Exception as err:
            logger.debug("Cache write error for key %s: %s", key, err)


# ---------------------------------------------------------------------------
# Helper: Package Name Normalization (PEP 503)
# ---------------------------------------------------------------------------
def normalize_package_name(name: str) -> str:
    """Normalize package name per PEP 503 (lowercase, runs of [-_.] become -)."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# Helper: Curated Symbol Map Loader
# ---------------------------------------------------------------------------
def load_known_symbols(path: Optional[Path] = None) -> dict[str, Any]:
    """Load curated known_symbols.json file."""
    file_path = path or KNOWN_SYMBOLS_PATH
    if not file_path.is_file():
        logger.debug("Curated symbols file %s not found.", file_path)
        return {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Normalize package keys
        normalized: dict[str, Any] = {}
        for pkg, cve_map in data.items():
            norm_pkg = normalize_package_name(pkg)
            normalized[norm_pkg] = cve_map
        return normalized
    except Exception as err:
        logger.warning("Failed to load known symbols from %s: %s", file_path, err)
        return {}


# ---------------------------------------------------------------------------
# Subsystem 1: Dependency Extraction
# ---------------------------------------------------------------------------
def _find_requirement_files(target_dir: str) -> list[Path]:
    """Find all requirements*.txt and package-lock.json files, ignoring excluded directories."""
    matched_files: list[Path] = []
    root_path = Path(target_dir).resolve()
    if not root_path.exists():
        logger.warning("Target directory %s does not exist.", target_dir)
        return []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Exclude specified directories in-place
        dirnames[:] = [d for d in dirnames if d.lower() not in EXCLUDED_DIR_NAMES]
        for fname in filenames:
            flock = fname.lower()
            if flock.startswith("requirements") and flock.endswith(".txt"):
                matched_files.append(Path(dirpath) / fname)
            elif flock == "package-lock.json":
                matched_files.append(Path(dirpath) / fname)

    return matched_files


def _parse_requirements_file(
    file_path: Path,
    visited: Optional[Set[Path]] = None,
) -> list[DependencyEntry]:
    """Parse a single requirements.txt file with support for comments, extras, markers, and includes."""
    if visited is None:
        visited = set()

    resolved_path = file_path.resolve()
    if resolved_path in visited:
        logger.warning("Cycle or duplicate detected for requirement file %s; skipping.", resolved_path)
        return []
    visited.add(resolved_path)

    if not resolved_path.is_file():
        logger.warning("Requirement file %s not found.", resolved_path)
        return []

    entries: list[DependencyEntry] = []
    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as err:
        logger.warning("Failed to read requirements file %s: %s", resolved_path, err)
        return []

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Strip inline comment
        if " #" in line:
            line = line.split(" #", 1)[0].strip()

        # Handle -r / --requirement includes
        if line.startswith(("-r ", "--requirement ")):
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                inc_path = (resolved_path.parent / parts[1].strip()).resolve()
                entries.extend(_parse_requirements_file(inc_path, visited))
            continue

        # Skip -e / --editable
        if line.startswith(("-e ", "--editable ")):
            logger.warning(
                "Skipping editable requirement in %s line %d: %s",
                resolved_path.name, line_num, line
            )
            continue

        # Skip URLs and VCS specs
        if any(vcs in line for vcs in ("git+", "svn+", "hg+", "bzr+", "http://", "https://")):
            logger.warning(
                "Skipping URL/VCS requirement in %s line %d: %s",
                resolved_path.name, line_num, line
            )
            continue

        # Strip environment markers (; python_version < "3.8")
        if ";" in line:
            line = line.split(";", 1)[0].strip()

        # Look for exact pins (== or ===)
        # Handle extras like requests[security]==2.25.1
        pin_match = re.match(
            r"^([a-zA-Z0-9_\-\.]+)(?:\[.*?\])?\s*(===|==)\s*([a-zA-Z0-9_\-\.\+]+)$",
            line,
        )
        if pin_match:
            pkg_name = pin_match.group(1).strip()
            version = pin_match.group(3).strip()
            norm_name = normalize_package_name(pkg_name)
            entries.append(
                DependencyEntry(
                    package_name=pkg_name,
                    normalized_name=norm_name,
                    version=version,
                    source_file=str(resolved_path),
                    ecosystem="PyPI",
                )
            )
            continue

        # Detect range / unpinned specifiers (>=, <=, ~=, !=, <, >)
        if any(op in line for op in (">=", "<=", "~=", "!=", "<", ">")):
            logger.warning(
                "Skipping range/unpinned specifier in %s line %d: %s",
                resolved_path.name, line_num, line
            )
            continue

        # Unrecognized format
        logger.warning(
            "Skipping unrecognized line in %s line %d: %s",
            resolved_path.name, line_num, line
        )

    return entries


def _parse_package_lock_json(file_path: Path) -> list[DependencyEntry]:
    """Extract npm dependencies from package-lock.json (lockfile v1, v2, v3)."""
    resolved_path = file_path.resolve()
    if not resolved_path.is_file():
        return []

    entries: list[DependencyEntry] = []
    try:
        with open(resolved_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as err:
        logger.warning("Failed to parse package-lock.json at %s: %s", resolved_path, err)
        return []

    # v2/v3 lockfile has 'packages' dict
    packages = data.get("packages")
    if isinstance(packages, dict):
        for pkg_key, pkg_info in packages.items():
            if not pkg_key or not isinstance(pkg_info, dict):
                continue
            # Usually node_modules/package-name
            version = pkg_info.get("version")
            if not version:
                continue
            pkg_name = pkg_info.get("name")
            if not pkg_name:
                parts = pkg_key.split("node_modules/")
                pkg_name = parts[-1] if len(parts) > 1 else pkg_key
            if pkg_name:
                entries.append(
                    DependencyEntry(
                        package_name=pkg_name,
                        normalized_name=pkg_name.lower(),
                        version=str(version),
                        source_file=str(resolved_path),
                        ecosystem="npm",
                    )
                )

    # v1 lockfile or fallback 'dependencies' dict
    if not entries and isinstance(data.get("dependencies"), dict):
        for pkg_name, pkg_info in data["dependencies"].items():
            if isinstance(pkg_info, dict) and "version" in pkg_info:
                entries.append(
                    DependencyEntry(
                        package_name=pkg_name,
                        normalized_name=pkg_name.lower(),
                        version=str(pkg_info["version"]),
                        source_file=str(resolved_path),
                        ecosystem="npm",
                    )
                )

    return entries


def extract_dependencies(target_dir: str) -> list[DependencyEntry]:
    """Walk target directory, parse dependency files, and return deduplicated entries."""
    matched_files = _find_requirement_files(target_dir)
    if not matched_files:
        logger.info("No dependency files found in target directory: %s", target_dir)
        return []

    raw_entries: list[DependencyEntry] = []
    visited_reqs: Set[Path] = set()

    for path in matched_files:
        if path.name.lower() == "package-lock.json":
            raw_entries.extend(_parse_package_lock_json(path))
        else:
            raw_entries.extend(_parse_requirements_file(path, visited_reqs))

    # Deduplicate by (normalized_name, version, ecosystem)
    seen: set[tuple[str, str, str]] = set()
    deduped: list[DependencyEntry] = []
    for entry in raw_entries:
        key = (entry.normalized_name, entry.version, entry.ecosystem)
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    logger.info("Extracted %d unique dependencies from %s", len(deduped), target_dir)
    return deduped


# ---------------------------------------------------------------------------
# Subsystem 2: Resilient HTTP Client Helper
# ---------------------------------------------------------------------------
async def fetch_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    retries: int = HTTP_MAX_RETRIES,
    **kwargs: Any,
) -> Optional[httpx.Response]:
    """Perform HTTP request with exponential backoff on 429, 5xx, or network errors."""
    for attempt in range(retries):
        try:
            resp = await client.request(method, url, timeout=HTTP_TIMEOUT, **kwargs)
            if resp.status_code == 429 or resp.status_code >= 500:
                delay = 0.5 * (2 ** attempt)
                logger.warning(
                    "HTTP %d for %s (attempt %d/%d). Backing off for %.2fs.",
                    resp.status_code, url, attempt + 1, retries, delay
                )
                await asyncio.sleep(delay)
                continue
            return resp
        except (httpx.RequestError, httpx.TimeoutException) as exc:
            delay = 0.5 * (2 ** attempt)
            logger.warning(
                "Request error for %s (%s) (attempt %d/%d). Backing off for %.2fs.",
                url, exc, attempt + 1, retries, delay
            )
            await asyncio.sleep(delay)

    logger.error("All %d retries failed for %s", retries, url)
    return None


# ---------------------------------------------------------------------------
# Subsystem 3 & 4: OSV.dev Lookup and Vulnerability Parsing
# ---------------------------------------------------------------------------
def compute_cvss_score(
    severity_list: list[dict[str, Any]],
    database_specific: dict[str, Any],
    cve_id: str,
) -> float:
    """Compute base score from CVSS vectors or approximate from qualitative severity."""
    # 1. Vector computation via cvss library
    for entry in severity_list:
        score_str = entry.get("score")
        s_type = entry.get("type", "")
        if not score_str or not isinstance(score_str, str):
            continue
        try:
            if "CVSS:3" in score_str or s_type == "CVSS_V3":
                c3 = cvss.CVSS3(score_str)
                return max(0.0, min(10.0, float(c3.base_score)))
            elif "CVSS:4" in score_str or s_type == "CVSS_V4":
                c4 = cvss.CVSS4(score_str)
                return max(0.0, min(10.0, float(c4.base_score)))
            elif "CVSS:2" in score_str or s_type == "CVSS_V2" or "AV:" in score_str:
                c2 = cvss.CVSS2(score_str)
                return max(0.0, min(10.0, float(c2.base_score)))
        except Exception as exc:
            logger.debug("Failed parsing CVSS vector '%s' for %s: %s", score_str, cve_id, exc)

    # 2. Qualitative database_specific approximation
    qual = database_specific.get("severity")
    if qual and isinstance(qual, str):
        mapping = {
            "LOW": 3.0,
            "MODERATE": 5.5,
            "MEDIUM": 5.5,
            "HIGH": 7.5,
            "CRITICAL": 9.5,
        }
        val = mapping.get(qual.strip().upper())
        if val is not None:
            logger.info("CVSS score approximated from qualitative severity '%s' for %s: %.1f", qual, cve_id, val)
            return val

    return 0.0


def extract_fixed_version(affected_list: list[dict[str, Any]], normalized_pkg: str) -> Optional[str]:
    """Find the first fixed version from affected ranges for the given package."""
    for record in affected_list:
        pkg = record.get("package", {})
        pkg_name = pkg.get("name", "")
        if normalize_package_name(pkg_name) != normalized_pkg:
            continue
        for rng in record.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return str(ev["fixed"])

    # Fallback: check any record in affected_list with a fixed event
    for record in affected_list:
        for rng in record.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    return str(ev["fixed"])
    return None


def extract_summary(vuln: dict[str, Any]) -> str:
    """Extract OSV summary, or first sentence of details if summary is empty, trimmed to ~300 chars."""
    summary = (vuln.get("summary") or "").strip()
    if not summary:
        details = (vuln.get("details") or "").strip()
        if details:
            m = re.match(r"^(.+?)(?:\.\s|\.\n|\n|$)", details, re.DOTALL)
            summary = m.group(1).strip() if m else details

    if len(summary) > 300:
        summary = summary[:297].rstrip() + "..."
    return summary


# ---------------------------------------------------------------------------
# Subsystem 6: CVE-to-Symbol Mapping Tiers
# ---------------------------------------------------------------------------
def order_symbols(symbols: list[str]) -> list[str]:
    """Deduplicate symbols preserving fully-qualified order (more dots first)."""
    seen: set[str] = set()
    deduped: list[str] = []
    for s in symbols:
        cleaned = s.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)
    # Sort with more dots (fully qualified) first, stable for equal dots
    deduped.sort(key=lambda item: item.count("."), reverse=True)
    return deduped


def extract_structured_symbols(vuln: dict[str, Any], normalized_pkg: str) -> list[str]:
    """Tier a: Extract symbols from OSV affected[].ecosystem_specific or database_specific."""
    candidates: list[str] = []
    for record in vuln.get("affected", []):
        pkg = record.get("package", {})
        if normalize_package_name(pkg.get("name", "")) != normalized_pkg:
            continue

        for container in (record.get("ecosystem_specific"), record.get("database_specific")):
            if not isinstance(container, dict):
                continue
            for key in ("symbols", "functions", "affected_functions", "imports"):
                val = container.get(key)
                if isinstance(val, list):
                    for item in val:
                        if isinstance(item, str) and item.strip():
                            candidates.append(item.strip())
                elif isinstance(val, str) and val.strip():
                    candidates.append(val.strip())

    return order_symbols(candidates)


def extract_curated_symbols(
    known_symbols_data: dict[str, Any],
    normalized_pkg: str,
    cve_id: str,
    aliases: list[str],
) -> list[str]:
    """Tier b: Extract symbols from curated known_symbols.json."""
    pkg_entry = known_symbols_data.get(normalized_pkg)
    if not isinstance(pkg_entry, dict):
        return []

    # Check direct cve_id and all aliases
    keys_to_check = [cve_id] + [a for a in aliases if a]
    for key in keys_to_check:
        if key in pkg_entry:
            val = pkg_entry[key]
            if isinstance(val, dict):
                symbols = val.get("symbols", [])
                if isinstance(symbols, list):
                    return order_symbols(symbols)
            elif isinstance(val, list):
                return order_symbols(val)
    return []


def extract_heuristic_symbols(
    summary: str,
    details: str,
    package_name: str,
    normalized_pkg: str,
) -> list[str]:
    """Tier c: Heuristic extraction from summary and details with strict filtering.

    Filters out domain names, URLs, compression formats, exception classes,
    HTTP headers, parameter names, and generic method names.
    """
    raw_text = f"{summary}\n{details}"
    pkg_mod = PACKAGE_MODULE_MAP.get(normalized_pkg, normalized_pkg.replace("-", "_"))

    raw_candidates: set[str] = set()

    # 1. Documentation anchors pointing to package symbols:
    # e.g., https://.../reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.read_chunked
    anchor_pattern = re.compile(
        rf"#(?:{re.escape(pkg_mod)}|{re.escape(normalized_pkg)})(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+"
    )
    for m in anchor_pattern.finditer(raw_text):
        raw_candidates.add(m.group(0).lstrip("#"))

    # 2. Strip URLs, markdown link targets, and HTML tags from text
    clean_text = re.sub(r"https?://\S+", " ", raw_text)
    clean_text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", clean_text)
    clean_text = re.sub(r"<[^>]+>", " ", clean_text)

    # 3. Backticked tokens: `urllib3.util.parse_url` or `read_chunked`
    for m in re.finditer(r"`([a-zA-Z_][a-zA-Z0-9_\.]+)`", clean_text):
        raw_candidates.add(m.group(1))

    # 4. Function call patterns: `urllib3.response.BaseHTTPResponse.read_chunked()` or `func()`
    for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+)\(\)", clean_text):
        raw_candidates.add(m.group(1))
    for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\(\)", clean_text):
        raw_candidates.add(m.group(1))

    # 5. Descriptive phrases: "the X function/method/class"
    phrase_pattern = re.compile(
        r"\b(?:the|in|into|using)\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s+(?:function|method|class|callable)\b",
        re.IGNORECASE,
    )
    for m in phrase_pattern.finditer(clean_text):
        raw_candidates.add(m.group(1))

    # 6. Explicit dotted paths starting with the package's module
    dotted_pattern = re.compile(
        rf"\b({re.escape(pkg_mod)}(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+)\b"
    )
    for m in dotted_pattern.finditer(clean_text):
        raw_candidates.add(m.group(1))

    accepted_fq_symbols: list[str] = []
    accepted_bare_symbols: list[str] = []

    # First pass: evaluate dotted candidates (fully-qualified symbols)
    for token in raw_candidates:
        cand = token.strip(" .")
        if not cand or "." not in cand:
            continue

        # Reject if contains TLD or domain/file extension pattern (.io, .html, .md, etc.)
        if TLD_EXTENSION_PATTERN.search(cand):
            continue

        # Reject if ends in Warning/Error/Exception
        if re.search(r"(?:Warning|Error|Exception)$", cand):
            continue

        # Reject if in HTTP header names
        if cand in HTTP_HEADER_NAMES:
            continue

        # Reject all uppercase constants (e.g. DEFAULT_REMOVE_HEADERS_ON_REDIRECT)
        leaf = cand.split(".")[-1]
        if re.match(r"^[A-Z0-9_]+$", leaf):
            continue

        # Must start with the package's own module name (e.g. urllib3.*)
        if not (cand.startswith(f"{pkg_mod}.") or cand.startswith(f"{normalized_pkg}.")):
            continue

        # All parts must be valid Python identifiers
        parts = cand.split(".")
        if not all(re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", p) for p in parts):
            continue

        # Discard if leaf is in format/protocol words
        if leaf.lower() in FORMAT_PROTOCOL_WORDS:
            continue

        # Discard if all parts are stopwords
        if all(p.lower() in HEURISTIC_STOPWORDS for p in parts):
            continue

        accepted_fq_symbols.append(cand)

        # Emit leaf as short name if valid
        if (
            leaf.lower() not in GENERIC_METHOD_BLOCKLIST
            and leaf.lower() not in FORMAT_PROTOCOL_WORDS
            and leaf.lower() not in HEURISTIC_STOPWORDS
            and not re.search(r"(?:Warning|Error|Exception)$", leaf)
            and leaf not in HTTP_HEADER_NAMES
            and not re.match(r"^[A-Z0-9_]+$", leaf)
            and len(leaf) >= 3
            and re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", leaf)
        ):
            accepted_bare_symbols.append(leaf)

    # Second pass: evaluate bare candidates (no dots)
    for token in raw_candidates:
        cand = token.strip(" .")
        if not cand or "." in cand:
            continue

        cand_lower = cand.lower()

        # Reject if in generic method blocklist
        if cand_lower in GENERIC_METHOD_BLOCKLIST:
            continue

        # Reject if in format/protocol words (gzip, deflate, zstd, html, etc.)
        if cand_lower in FORMAT_PROTOCOL_WORDS:
            continue

        # Reject if in stopwords
        if cand_lower in HEURISTIC_STOPWORDS:
            continue

        # Reject if ends in Warning/Error/Exception
        if re.search(r"(?:Warning|Error|Exception)$", cand):
            continue

        # Reject if Capitalized HTTP header name
        if cand in HTTP_HEADER_NAMES or re.match(r"^[A-Z][a-zA-Z0-9]*(-[A-Z][a-zA-Z0-9]*)+$", cand):
            continue

        # Reject all uppercase tokens (HTTP, POST, GET, etc.)
        if re.match(r"^[A-Z0-9_]+$", cand):
            continue

        # Must be valid identifier of length >= 3
        if len(cand) < 3 or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", cand):
            continue

        # Must be explicitly called as "cand()" in the advisory text
        if not re.search(rf"\b{re.escape(cand)}\s*\(", raw_text):
            continue

        accepted_bare_symbols.append(cand)

    combined = accepted_fq_symbols + accepted_bare_symbols
    return order_symbols(combined)


def extract_fallback_symbols(package_name: str, normalized_pkg: str) -> list[str]:
    """Tier d: Top-level module name fallback."""
    pkg_mod = PACKAGE_MODULE_MAP.get(normalized_pkg, normalized_pkg.replace("-", "_"))
    return [pkg_mod]


def map_vulnerable_symbols(
    vuln: dict[str, Any],
    cve_id: str,
    package_name: str,
    normalized_pkg: str,
    known_symbols_data: dict[str, Any],
) -> tuple[list[str], str]:
    """Run symbol mapping tiers a -> b -> c -> d and return ordered symbols and tier name."""
    # Tier a: Structured
    symbols = extract_structured_symbols(vuln, normalized_pkg)
    if symbols:
        logger.info("Symbol mapping tier Structured used for %s (%s): %s", cve_id, package_name, symbols)
        return symbols, "structured"

    # Tier b: Curated Map
    aliases = vuln.get("aliases", [])
    symbols = extract_curated_symbols(known_symbols_data, normalized_pkg, cve_id, aliases)
    if symbols:
        logger.info("Symbol mapping tier Curated Map used for %s (%s): %s", cve_id, package_name, symbols)
        return symbols, "curated"

    # Tier c: Heuristics
    summary = vuln.get("summary", "")
    details = vuln.get("details", "")
    symbols = extract_heuristic_symbols(summary, details, package_name, normalized_pkg)
    if symbols:
        logger.info("Symbol mapping tier Heuristics used for %s (%s): %s", cve_id, package_name, symbols)
        return symbols, "heuristics"

    # Tier d: Fallback
    symbols = extract_fallback_symbols(package_name, normalized_pkg)
    logger.info("Symbol mapping tier Fallback (package-level) used for %s (%s): %s", cve_id, package_name, symbols)
    return symbols, "fallback"


# ---------------------------------------------------------------------------
# Subsystem 3: Query OSV for a single package
# ---------------------------------------------------------------------------
async def query_osv_package(
    client: httpx.AsyncClient,
    cache: DiskCache,
    dep: DependencyEntry,
    sem: asyncio.Semaphore,
    warnings: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """Query OSV.dev for a single dependency with pagination and semaphore limit."""
    cache_key = f"osv_{dep.ecosystem}_{dep.normalized_name}_{dep.version}"
    cached_vulns = cache.get(cache_key, OSV_CACHE_TTL)
    if cached_vulns is not None:
        logger.debug("Cache hit for OSV query: %s", cache_key)
        return cached_vulns

    vulns: list[dict[str, Any]] = []
    page_token: Optional[str] = None

    async with sem:
        while True:
            payload: dict[str, Any] = {
                "package": {
                    "name": dep.package_name,
                    "ecosystem": dep.ecosystem,
                },
                "version": dep.version,
            }
            if page_token:
                payload["page_token"] = page_token

            resp = await fetch_with_retry(client, "POST", OSV_QUERY_URL, json=payload)
            if not resp or resp.status_code != 200:
                logger.warning(
                    "OSV query failed for %s==%s (status %s)",
                    dep.package_name, dep.version, resp.status_code if resp else "error"
                )
                if warnings is not None:
                    warnings.append(
                        f"OSV lookup failed for {dep.package_name}=={dep.version}: "
                        f"its vulnerabilities are MISSING from this report."
                    )
                return vulns if vulns else []   # do not cache a failed lookup as 'no vulnerabilities'

            try:
                data = resp.json()
            except Exception as err:
                logger.warning("Failed to decode OSV JSON response for %s==%s: %s", dep.package_name, dep.version, err)
                break

            batch = data.get("vulns", [])
            if isinstance(batch, list):
                vulns.extend(batch)

            page_token = data.get("next_page_token")
            if not page_token:
                break

    cache.set(cache_key, vulns)
    return vulns


# ---------------------------------------------------------------------------
# Subsystem 5: EPSS and KEV Lookups
# ---------------------------------------------------------------------------
async def fetch_epss_scores(
    client: httpx.AsyncClient,
    cache: DiskCache,
    cve_ids: list[str],
    warnings: Optional[list[str]] = None,
) -> dict[str, float]:
    """Fetch EPSS scores from api.first.org in batches of 50, with caching."""
    scores: dict[str, float] = {}
    valid_cves = [cve for cve in cve_ids if CVE_REGEX.match(cve)]
    if not valid_cves:
        return scores

    cves_to_fetch: list[str] = []
    for cve in valid_cves:
        cached_score = cache.get(f"epss_{cve}", EPSS_CACHE_TTL)
        if cached_score is not None:
            scores[cve] = float(cached_score)
        else:
            cves_to_fetch.append(cve)

    # Chunk into batches of up to EPSS_BATCH_SIZE
    for i in range(0, len(cves_to_fetch), EPSS_BATCH_SIZE):
        batch = cves_to_fetch[i : i + EPSS_BATCH_SIZE]
        params = {"cve": ",".join(batch)}
        resp = await fetch_with_retry(client, "GET", EPSS_API_URL, params=params)
        if not resp or resp.status_code != 200:
            logger.warning("EPSS lookup failed for batch: %s", batch)
            if warnings is not None:
                warnings.append(
                    "EPSS data unavailable for some CVEs: exploit likelihood is treated as 0.0, "
                    "so their priority may be UNDERSTATED."
                )
            for cve in batch:
                scores[cve] = 0.0
            continue

        try:
            res_data = resp.json().get("data", [])
            found_cves: set[str] = set()
            for item in res_data:
                cve_key = item.get("cve")
                epss_raw = item.get("epss")
                if cve_key and epss_raw is not None:
                    try:
                        score_val = max(0.0, min(1.0, float(epss_raw)))
                    except (ValueError, TypeError):
                        score_val = 0.0
                    scores[cve_key] = score_val
                    cache.set(f"epss_{cve_key}", score_val)
                    found_cves.add(cve_key)

            for cve in batch:
                if cve not in found_cves:
                    logger.warning("No EPSS score found for %s; setting 0.0", cve)
                    scores[cve] = 0.0
                    cache.set(f"epss_{cve}", 0.0)
        except Exception as err:
            logger.warning("Failed to parse EPSS response: %s", err)
            for cve in batch:
                scores[cve] = 0.0

    return scores


async def fetch_cisa_kev(
    client: httpx.AsyncClient, cache: DiskCache, warnings: Optional[list[str]] = None
) -> set[str]:
    """Download CISA KEV catalog once per run, returning set of known exploited CVE IDs."""
    cached_kev = cache.get("cisa_kev_catalog", KEV_CACHE_TTL)
    if cached_kev is not None and isinstance(cached_kev, list):
        return set(cached_kev)

    resp = await fetch_with_retry(client, "GET", CISA_KEV_URL)
    if not resp or resp.status_code != 200:
        logger.warning("Failed to download CISA KEV catalog (status: %s)", resp.status_code if resp else "none")
        if warnings is not None:
            warnings.append("CISA KEV catalog unavailable: known-exploited status could not be checked.")
        return set()

    try:
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        kev_set = {
            item["cveID"] for item in vulns
            if isinstance(item, dict) and "cveID" in item and item["cveID"]
        }
        cache.set("cisa_kev_catalog", list(kev_set))
        logger.info("Loaded %d CVEs from CISA KEV catalog", len(kev_set))
        return kev_set
    except Exception as err:
        logger.warning("Failed to parse CISA KEV catalog JSON: %s", err)
        return set()


# ---------------------------------------------------------------------------
# Offline Fixture Generator
# ---------------------------------------------------------------------------
def get_offline_fixtures() -> list[RawVulnerability]:
    """Return deterministic fixture data for urllib3==1.26.4 when CONTEXTVULN_OFFLINE=1."""
    return [
        RawVulnerability(
            cve_id="CVE-2021-33503",
            package_name="urllib3",
            installed_version="1.26.4",
            fixed_version="1.26.5",
            vulnerable_symbols=[
                "urllib3.util.url.parse_url",
                "urllib3.util.parse_url",
                "parse_url",
            ],
            cvss_score=7.5,
            epss_score=0.002,
            is_in_kev=False,
            summary="Catastrophic ReDoS in URL authority parser",
        ),
        RawVulnerability(
            cve_id="CVE-2023-45803",
            package_name="urllib3",
            installed_version="1.26.4",
            fixed_version="1.26.18",
            vulnerable_symbols=[
                "urllib3.poolmanager.PoolManager.urlopen",
                "urllib3.connectionpool.HTTPConnectionPool.urlopen",
            ],
            cvss_score=7.5,
            epss_score=0.001,
            is_in_kev=False,
            summary="Request body not cleared on 303 redirect",
        ),
        RawVulnerability(
            cve_id="CVE-2023-43804",
            package_name="urllib3",
            installed_version="1.26.4",
            fixed_version="1.26.17",
            vulnerable_symbols=[
                "urllib3.poolmanager.PoolManager.urlopen",
                "urllib3.connectionpool.HTTPConnectionPool.urlopen",
                "urllib3.util.retry.Retry",
            ],
            cvss_score=5.9,
            epss_score=0.001,
            is_in_kev=False,
            summary="Cookie header not stripped on cross-origin redirects",
        ),
        RawVulnerability(
            cve_id="CVE-2024-37891",
            package_name="urllib3",
            installed_version="1.26.4",
            fixed_version="1.26.19",
            vulnerable_symbols=[
                "urllib3.poolmanager.ProxyManager",
                "urllib3.connectionpool.HTTPConnectionPool.urlopen",
                "urllib3.util.retry.Retry",
            ],
            cvss_score=5.9,
            epss_score=0.001,
            is_in_kev=False,
            summary="Proxy-Authorization header retained across redirects",
        ),
    ]


# ---------------------------------------------------------------------------
# Threat Intelligence Agent Main Class
# ---------------------------------------------------------------------------
class ThreatIntelAgent:
    """Threat Intelligence Agent (Agent 2) for ContextVuln.

    Extracts dependencies from repository requirements files, queries OSV.dev for
    vulnerabilities, enriches with EPSS and CISA KEV data, maps affected symbols
    across 4 tiers, and outputs sorted RawVulnerability records.
    """

    def __init__(self) -> None:
        self.cache = DiskCache()
        self.known_symbols = load_known_symbols()

    async def analyze_dependencies(self, target_dir: str) -> list[RawVulnerability]:
        """Backward-compatible entry point (warnings are discarded)."""
        vulns, _ = await self.analyze_with_warnings(target_dir)
        return vulns

    async def analyze_with_warnings(self, target_dir: str) -> tuple[list[RawVulnerability], list[str]]:
        """Same as analyze_dependencies, plus human-readable warnings the report should show
        (failed feeds, skipped lookups). The orchestrator uses this when it exists."""
        warnings: list[str] = []
        vulns = await self._analyze(target_dir, warnings)
        return vulns, warnings

    async def _analyze(self, target_dir: str, warnings: list[str]) -> list[RawVulnerability]:
        """Analyze repository dependencies, fetch CVE intelligence, and return RawVulnerabilities."""
        fetched_at = datetime.now(timezone.utc)
        # 1. Check Offline Mode
        if os.environ.get("CONTEXTVULN_OFFLINE") == "1":
            logger.info("CONTEXTVULN_OFFLINE=1 detected. Returning deterministic offline fixture.")
            warnings.append(
                "CONTEXTVULN_OFFLINE=1: built-in urllib3 fixtures are shown, NOT this repository's dependencies."
            )
            return get_offline_fixtures()

        # 2. Extract dependencies from target_dir
        deps = extract_dependencies(target_dir)
        if not deps:
            logger.info("No dependencies extracted from %s; returning empty vulnerability list.", target_dir)
            return []

        # 3. Query OSV.dev concurrently with max 8 parallel requests
        sem = asyncio.Semaphore(MAX_CONCURRENT_OSV_REQUESTS)
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            # Query OSV for all dependencies concurrently
            osv_tasks = [query_osv_package(client, self.cache, dep, sem, warnings) for dep in deps]
            osv_results = await asyncio.gather(*osv_tasks, return_exceptions=True)

            # Pre-parse vulnerabilities per package
            raw_vulns_per_pkg: list[tuple[DependencyEntry, list[RawVulnerability]]] = []
            all_cve_ids: set[str] = set()

            for dep, result in zip(deps, osv_results):
                if isinstance(result, Exception):
                    logger.error("OSV lookup task raised an exception for %s: %s", dep.package_name, result)
                    warnings.append(f"OSV lookup crashed for {dep.package_name}=={dep.version}; results missing.")
                    continue
                if not isinstance(result, list):
                    continue

                pkg_raw_vulns: list[RawVulnerability] = []
                for vuln in result:
                    # Determine cve_id: first alias matching CVE regex, else OSV id
                    aliases = vuln.get("aliases", [])
                    cve_id = vuln.get("id", "UNKNOWN")
                    for alias in aliases:
                        if CVE_REGEX.match(alias):
                            cve_id = alias
                            break

                    if CVE_REGEX.match(cve_id):
                        all_cve_ids.add(cve_id)

                    # Extract CVSS
                    severity_list = vuln.get("severity", [])
                    db_specific = vuln.get("database_specific", {})
                    cvss_val = compute_cvss_score(severity_list, db_specific, cve_id)

                    # Extract fixed version
                    affected_list = vuln.get("affected", [])
                    fixed_ver = extract_fixed_version(affected_list, dep.normalized_name)

                    # Extract summary
                    summary_text = extract_summary(vuln)

                    # Symbol mapping
                    symbols, tier_used = map_vulnerable_symbols(
                        vuln=vuln,
                        cve_id=cve_id,
                        package_name=dep.package_name,
                        normalized_pkg=dep.normalized_name,
                        known_symbols_data=self.known_symbols,
                    )

                    pkg_raw_vulns.append(
                        RawVulnerability(
                            cve_id=cve_id,
                            package_name=dep.package_name,
                            installed_version=dep.version,
                            fixed_version=fixed_ver,
                            vulnerable_symbols=symbols,
                            cvss_score=cvss_val,
                            epss_score=0.0,
                            is_in_kev=False,
                            summary=summary_text,
                            # --- v2 contract fields used by the orchestrator's safety rules ---
                            ecosystem=dep.ecosystem,
                            symbol_source=tier_used,
                            source="osv.dev",
                            fetched_at=fetched_at,
                            aliases=[a for a in aliases if a != cve_id],
                            cvss_vector=next(
                                (e["score"] for e in severity_list
                                 if isinstance(e.get("score"), str) and e["score"].startswith("CVSS:")),
                                None,
                            ),
                        )
                    )

                raw_vulns_per_pkg.append((dep, pkg_raw_vulns))

            # 4. Enrich with EPSS and CISA KEV
            kev_task = fetch_cisa_kev(client, self.cache, warnings)
            epss_task = fetch_epss_scores(client, self.cache, list(all_cve_ids), warnings)
            kev_set, epss_map = await asyncio.gather(kev_task, epss_task)

            # 5. Merge duplicates and apply EPSS + KEV
            final_vulns: list[RawVulnerability] = []

            for dep, vuln_list in raw_vulns_per_pkg:
                # Deduplicate multiple advisories for same package + CVE
                merged: dict[str, RawVulnerability] = {}
                for v in vuln_list:
                    # Enrich with EPSS and KEV
                    if CVE_REGEX.match(v.cve_id):
                        v.epss_score = epss_map.get(v.cve_id, 0.0)
                        v.is_in_kev = v.cve_id in kev_set
                    else:
                        v.epss_score = 0.0
                        v.is_in_kev = False

                    if v.cve_id not in merged:
                        merged[v.cve_id] = v
                    else:
                        existing = merged[v.cve_id]
                        # Keep maximum CVSS and EPSS
                        existing.cvss_score = max(existing.cvss_score, v.cvss_score)
                        existing.epss_score = max(existing.epss_score, v.epss_score)
                        existing.is_in_kev = existing.is_in_kev or v.is_in_kev
                        if not existing.fixed_version and v.fixed_version:
                            existing.fixed_version = v.fixed_version
                        # Union symbols
                        existing.vulnerable_symbols = order_symbols(
                            existing.vulnerable_symbols + v.vulnerable_symbols
                        )
                        # Prefer longer or non-empty summary
                        if len(v.summary) > len(existing.summary):
                            existing.summary = v.summary

                final_vulns.extend(merged.values())

        # 6. Sort results by cvss_score descending
        final_vulns.sort(key=lambda item: item.cvss_score, reverse=True)
        warnings[:] = list(dict.fromkeys(warnings))   # de-duplicate, keep order
        return final_vulns
