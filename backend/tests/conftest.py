import os
import sys
import textwrap

import pytest

# Make `import app...` work no matter where pytest is launched from
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import Settings  # noqa: E402


@pytest.fixture
def cfg() -> Settings:
    """Settings with no LLM key and mock intel, independent of any local .env file."""
    return Settings(_env_file=None, gemini_api_key="", intel_mode="mock", api_key="")


@pytest.fixture
def make_project(tmp_path):
    """make_project({'app.py': 'code', 'requirements.txt': '...'}) -> str path"""
    def _make(files: dict) -> str:
        for rel, src in files.items():
            fp = tmp_path / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(textwrap.dedent(src))
        return str(tmp_path)
    return _make
