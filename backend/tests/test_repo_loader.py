import io
import os
import stat
import zipfile
from unittest.mock import MagicMock, patch

import pytest
from fastapi import UploadFile

from app.core.config import settings
from app.services.repo_loader import find_project_root, load_github_repo, load_uploaded_zip, load_zip_stream


def _zip(entries: dict, symlink: str | None = None) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    buf.seek(0)
    return buf


def test_invalid_github_url_raises_value_error():
    for bad in ("https://evil.example.com/org/repo", "not-even-a-url", "https://github.com/a/b; rm -rf /"):
        with pytest.raises(ValueError, match="Invalid GitHub repository URL"):
            with load_github_repo(bad):
                pass


def test_valid_github_url_clones_and_cleans_up():
    captured = {}

    def fake_git_clone(cmd, **kwargs):
        target_dir = cmd[-1]
        with open(os.path.join(target_dir, "requirements.txt"), "w") as f:
            f.write("flask==2.0.1\n")
        captured["env"] = kwargs.get("env", {})
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=fake_git_clone) as mock_run:
        with load_github_repo("https://github.com/pallets/flask") as repo_dir:
            captured["dir"] = repo_dir
            assert os.path.isfile(os.path.join(repo_dir, "requirements.txt"))

    mock_run.assert_called_once()
    assert captured["env"].get("GIT_TERMINAL_PROMPT") == "0"   # never hang on a credentials prompt
    assert "--" in mock_run.call_args[0][0]                     # URL can never be parsed as an option
    assert not os.path.exists(captured["dir"])


def test_git_timeout_becomes_value_error():
    import subprocess
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 1)):
        with pytest.raises(ValueError, match="timed out"):
            with load_github_repo("https://github.com/a/b"):
                pass


def test_zip_upload_extracts_and_cleans_up():
    upload = UploadFile(filename="my_project.zip",
                        file=_zip({"my_project/app.py": "print(1)\n", "my_project/requirements.txt": "x==1\n"}))
    with load_uploaded_zip(upload) as d:
        captured = d
        assert os.path.isfile(os.path.join(d, "my_project", "app.py"))
    assert not os.path.exists(captured)


def test_zip_upload_rejects_non_zip_extension():
    with pytest.raises(ValueError, match="Please upload a .zip archive"):
        with load_uploaded_zip(UploadFile(filename="malware.tar.gz", file=io.BytesIO(b"x"))):
            pass


def test_corrupt_zip_is_a_value_error_not_a_crash():
    with pytest.raises(ValueError, match="not a valid .zip"):
        with load_zip_stream(io.BytesIO(b"definitely not a zip"), "x.zip"):
            pass


@pytest.mark.parametrize("evil", ["../../outside.py", "/etc/evil.py", "../extracted_evil/x.py"])
def test_zip_slip_variants_blocked(evil):
    """The last variant defeats a plain startswith() check - commonpath() must catch it."""
    with pytest.raises(ValueError, match="Unsafe zip archive"):
        with load_zip_stream(_zip({evil: "x"}), "m.zip"):
            pass


def test_symlink_entries_blocked():
    with pytest.raises(ValueError, match="symbolic link"):
        with load_zip_stream(_zip({"a.py": "x"}, symlink="link"), "m.zip"):
            pass


def test_zip_bomb_blocked_by_total_size(monkeypatch):
    monkeypatch.setattr(settings, "max_uncompressed_mb", 1)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.py", "#" * (3 * 1024 * 1024))
    buf.seek(0)
    assert len(buf.getvalue()) < 50_000  # tiny on the wire, huge on disk
    with pytest.raises(ValueError, match="zip bomb"):
        with load_zip_stream(buf, "bomb.zip"):
            pass


def test_too_many_files_blocked(monkeypatch):
    monkeypatch.setattr(settings, "max_zip_files", 3)
    with pytest.raises(ValueError, match="too many files"):
        with load_zip_stream(_zip({f"f{i}.py": "x" for i in range(5)}), "m.zip"):
            pass


def test_oversized_upload_rejected(monkeypatch):
    monkeypatch.setattr(settings, "max_upload_mb", 0)
    with pytest.raises(ValueError, match="too large"):
        with load_uploaded_zip(UploadFile(filename="a.zip", file=_zip({"a.py": "x"}))):
            pass


def test_find_project_root_skips_wrapper_but_not_packages(tmp_path):
    (tmp_path / "wrapper" / "app").mkdir(parents=True)
    (tmp_path / "wrapper" / "app" / "m.py").write_text("x=1")
    (tmp_path / "wrapper" / "requirements.txt").write_text("x==1")
    assert find_project_root(str(tmp_path)) == str(tmp_path / "wrapper")      # single wrapper dir -> descend

    pkg = tmp_path / "pkgzip"
    (pkg / "mypkg").mkdir(parents=True)
    (pkg / "mypkg" / "__init__.py").write_text("")
    assert find_project_root(str(pkg)) == str(pkg)                            # a package is not a wrapper

    multi = tmp_path / "multi"
    (multi / "a").mkdir(parents=True)
    (multi / "b").mkdir()
    assert find_project_root(str(multi)) == str(multi)
