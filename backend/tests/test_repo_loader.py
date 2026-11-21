import io
import os
import zipfile
import pytest
from unittest.mock import MagicMock, patch
from fastapi import UploadFile
from app.services.repo_loader import load_github_repo, load_uploaded_zip


def test_invalid_github_url_raises_value_error():
    with pytest.raises(ValueError, match="Invalid GitHub repository URL"):
        with load_github_repo("https://evil.example.com/org/repo"):
            pass

    with pytest.raises(ValueError, match="Invalid GitHub repository URL"):
        with load_github_repo("not-even-a-url"):
            pass


def test_valid_github_url_clones_and_cleans_up():
    captured_temp_dir = None

    def fake_git_clone(cmd, capture_output, text, timeout):
        # Simulate git clone creating a file inside target temp dir
        target_dir = cmd[-1]
        with open(os.path.join(target_dir, "requirements.txt"), "w") as f:
            f.write("flask==2.0.1\n")
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        return mock_proc

    with patch("subprocess.run", side_effect=fake_git_clone) as mock_run:
        with load_github_repo("https://github.com/pallets/flask") as repo_dir:
            captured_temp_dir = repo_dir
            assert os.path.isdir(repo_dir)
            assert os.path.isfile(os.path.join(repo_dir, "requirements.txt"))

    mock_run.assert_called_once()
    # Verify cleanup deleted the temporary directory after exiting context manager
    assert captured_temp_dir is not None
    assert not os.path.exists(captured_temp_dir)


def test_zip_upload_extracts_and_cleans_up():
    # Build an in-memory .zip archive
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("my_project/app.py", "print('hello contextvuln')\n")
        zf.writestr("my_project/requirements.txt", "pyyaml==5.3.1\n")
    buf.seek(0)

    upload = UploadFile(filename="my_project.zip", file=buf)
    captured_dir = None

    with load_uploaded_zip(upload) as extracted_dir:
        captured_dir = extracted_dir
        assert os.path.isdir(extracted_dir)
        assert os.path.isfile(os.path.join(extracted_dir, "my_project", "app.py"))

    assert captured_dir is not None
    assert not os.path.exists(captured_dir)


def test_zip_upload_rejects_non_zip_extension():
    upload = UploadFile(filename="malware.tar.gz", file=io.BytesIO(b"fake data"))
    with pytest.raises(ValueError, match="Please upload a .zip archive"):
        with load_uploaded_zip(upload):
            pass


def test_zip_upload_blocks_path_traversal():
    """Security check: ensures Zip Slip ('../../evil.py') archives are rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../outside_target.py", "import os; os.system('id')")
    buf.seek(0)

    upload = UploadFile(filename="malicious.zip", file=buf)
    with pytest.raises(ValueError, match="Unsafe zip archive detected"):
        with load_uploaded_zip(upload):
            pass