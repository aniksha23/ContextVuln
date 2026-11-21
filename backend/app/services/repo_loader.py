import io
import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from typing import BinaryIO, Generator

from fastapi import UploadFile

from app.core.config import settings

GITHUB_URL_PATTERN = re.compile(r"^https?://(www\.)?github\.com/[\w.-]+/[\w.-]+(\.git)?/?$")
_MB = 1024 * 1024


def _remove_readonly(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def _rmtree(path: str) -> None:
    # `onexc` replaced the deprecated `onerror` in Python 3.12
    try:
        shutil.rmtree(path, onexc=_remove_readonly)
    except TypeError:
        shutil.rmtree(path, onerror=_remove_readonly)


@contextmanager
def load_github_repo(repo_url: str) -> Generator[str, None, None]:
    """Clones a public GitHub URL into a temp folder and deletes it after scanning."""
    cleaned = repo_url.strip()
    if not GITHUB_URL_PATTERN.match(cleaned):
        raise ValueError(f"Invalid GitHub repository URL: {cleaned}")

    temp_dir = tempfile.mkdtemp(prefix="contextvuln_git_")
    try:
        # GIT_TERMINAL_PROMPT=0: a private repo fails fast instead of hanging on a password prompt
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch", "--", cleaned, temp_dir],
                capture_output=True,
                text=True,
                timeout=settings.git_clone_timeout_s,
                env=env,
            )
        except subprocess.TimeoutExpired:
            raise ValueError(
                f"Git clone timed out after {settings.git_clone_timeout_s}s (repository too large?)."
            )
        except FileNotFoundError:
            raise RuntimeError("git is not installed on the server.")
        if result.returncode != 0:
            raise ValueError(f"Git clone failed: {result.stderr.strip()[:300]}")
        yield temp_dir
    finally:
        _rmtree(temp_dir)


def read_upload_limited(upload_file: UploadFile) -> bytes:
    """Reads an upload into memory but refuses anything over max_upload_mb."""
    limit = settings.max_upload_mb * _MB
    data = upload_file.file.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"Archive too large (limit {settings.max_upload_mb} MB).")
    return data


def _safe_extract(zf: zipfile.ZipFile, extract_dir: str) -> None:
    """Validates then extracts. Rejects zip-slip, symlinks, zip bombs and huge archives."""
    infos = zf.infolist()
    if len(infos) > settings.max_zip_files:
        raise ValueError(f"Archive has too many files (limit {settings.max_zip_files}).")

    root = os.path.realpath(extract_dir)
    total = 0
    for info in infos:
        # 1) path traversal  (commonpath, not startswith: "/x/extracted_evil" must NOT pass for "/x/extracted")
        target = os.path.realpath(os.path.join(root, info.filename))
        if os.path.commonpath([root, target]) != root:
            raise ValueError("Unsafe zip archive detected (path traversal).")
        # 2) symlinks inside the archive
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            raise ValueError("Unsafe zip archive detected (symbolic link).")
        # 3) zip bomb: total size and per-file compression ratio
        total += info.file_size
        if total > settings.max_uncompressed_mb * _MB:
            raise ValueError(
                f"Archive expands beyond {settings.max_uncompressed_mb} MB (possible zip bomb)."
            )
        if info.compress_size > 0 and info.file_size / info.compress_size > settings.max_compression_ratio \
                and info.file_size > 5 * _MB:
            raise ValueError("Suspicious compression ratio (possible zip bomb).")
    zf.extractall(root)


@contextmanager
def load_zip_stream(fileobj: BinaryIO, filename: str) -> Generator[str, None, None]:
    """Extracts a zip given as a binary stream into a temp dir; cleans up afterwards."""
    if not filename or not filename.lower().endswith(".zip"):
        raise ValueError("Please upload a .zip archive of your project folder.")

    temp_dir = tempfile.mkdtemp(prefix="contextvuln_zip_")
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    try:
        try:
            with zipfile.ZipFile(fileobj, "r") as zf:
                _safe_extract(zf, extract_dir)
        except zipfile.BadZipFile:
            raise ValueError("The uploaded file is not a valid .zip archive.")
        yield extract_dir
    finally:
        _rmtree(temp_dir)


@contextmanager
def load_uploaded_zip(upload_file: UploadFile) -> Generator[str, None, None]:
    """Saves an uploaded .zip project archive, extracts it to a temp dir, and cleans up."""
    if not upload_file.filename or not upload_file.filename.lower().endswith(".zip"):
        raise ValueError("Please upload a .zip archive of your project folder.")
    data = read_upload_limited(upload_file)
    with load_zip_stream(io.BytesIO(data), upload_file.filename) as extract_dir:
        yield extract_dir


def find_project_root(path: str) -> str:
    """
    Zipping a folder adds a wrapper directory (my_project/app/...). Import statements inside the
    code ('from app.x import y') are relative to the project root, so the AST agent must be pointed
    at that root, not at the wrapper. Descends through single-directory wrappers, but never into a
    Python package itself (a folder that has __init__.py).
    """
    current = path
    for _ in range(3):
        try:
            entries = [e for e in os.listdir(current) if not e.startswith(".") and e != "__MACOSX"]
        except OSError:
            break
        if len(entries) != 1:
            break
        child = os.path.join(current, entries[0])
        if not os.path.isdir(child) or os.path.exists(os.path.join(child, "__init__.py")):
            break
        current = child
    return current
