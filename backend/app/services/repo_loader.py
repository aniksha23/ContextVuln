import os
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile
from contextlib import contextmanager
from typing import Generator
from fastapi import UploadFile

GITHUB_URL_PATTERN = re.compile(r"^https?://(www\.)?github\.com/[\w.-]+/[\w.-]+(\.git)?/?$")


def _remove_readonly(func, path, _):
    os.chmod(path, stat.S_IWRITE)
    func(path)


@contextmanager
def load_github_repo(repo_url: str) -> Generator[str, None, None]:
    """Clones a public GitHub URL into a temp folder and deletes it after scanning."""
    cleaned = repo_url.strip()
    if not GITHUB_URL_PATTERN.match(cleaned):
        raise ValueError(f"Invalid GitHub repository URL: {cleaned}")

    temp_dir = tempfile.mkdtemp(prefix="contextvuln_git_")
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", cleaned, temp_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise ValueError(f"Git clone failed: {result.stderr.strip()}")
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, onerror=_remove_readonly)


@contextmanager
def load_uploaded_zip(upload_file: UploadFile) -> Generator[str, None, None]:
    """Saves an uploaded .zip project archive, extracts it to a temp dir, and cleans up."""
    if not upload_file.filename or not upload_file.filename.endswith(".zip"):
        raise ValueError("Please upload a .zip archive of your project folder.")

    temp_dir = tempfile.mkdtemp(prefix="contextvuln_zip_")
    zip_path = os.path.join(temp_dir, "archive.zip")
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)

    try:
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Prevent Zip Slip path traversal attacks
            for member in zf.namelist():
                member_path = os.path.abspath(os.path.join(extract_dir, member))
                if not member_path.startswith(os.path.abspath(extract_dir)):
                    raise ValueError("Unsafe zip archive detected (path traversal).")
            zf.extractall(extract_dir)

        yield extract_dir
    finally:
        shutil.rmtree(temp_dir, onerror=_remove_readonly)