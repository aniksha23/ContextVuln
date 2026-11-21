import os
import sys
import tempfile
import pytest

from app.core.schemas import ReachabilityResult, VulnerabilityFinding
from app.agents.ast_agent import (
    ASTReachabilityAgent,
    ExtendedReachabilityResult,
    build_call_graph,
    check_reachability,
    analyze_reachability,
)

# Base paths
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLES_DIR = os.path.join(ROOT_DIR, "benchmark", "samples")


def test_direct_vuln_reachability():
    """
    Scenario 1: Entry point directly calls yaml.load in sample_direct_vuln.py.
    Expected: is_reachable = True, confidence = 1.0, depth = 1.
    """
    sample_file = os.path.join(SAMPLES_DIR, "sample_direct_vuln.py")
    assert os.path.exists(sample_file), f"Sample file not found: {sample_file}"

    agent = ASTReachabilityAgent(sample_file)
    agent.build_graph()

    result = agent.check_reachability(["yaml.load"])

    assert result.is_reachable is True
    assert result.confidence == 1.0
    assert result.depth == 1
    assert len(result.call_path) >= 2
    assert "yaml.load()" in result.call_path[-1]
    assert any("sample_direct_vuln.py" in step for step in result.call_path)


def test_transitive_vuln_reachability():
    """
    Scenario 2: Multi-file project (main.py -> service.py -> yaml.load).
    Expected: is_reachable = True, confidence = 0.7, depth >= 2.
    """
    sample_dir = os.path.join(SAMPLES_DIR, "sample_transitive_vuln")
    assert os.path.isdir(sample_dir), f"Sample dir not found: {sample_dir}"

    agent = ASTReachabilityAgent(sample_dir)
    agent.build_graph()

    result = agent.check_reachability(["yaml.load"])

    assert result.is_reachable is True
    assert result.confidence == 0.7
    assert result.depth >= 2
    assert len(result.call_path) >= 3
    assert "yaml.load()" in result.call_path[-1]

    # Verify cross-file trace
    path_str = " -> ".join(result.call_path)
    assert "main.py" in path_str
    assert "service.py" in path_str
    assert len(result.call_trace) >= 2


def test_aliased_vuln_reachability():
    """
    Scenario 3: Vulnerable function imported as alias (from yaml import load as unsafe_loader).
    Expected: is_reachable = True, confidence = 1.0.
    """
    sample_file = os.path.join(SAMPLES_DIR, "sample_aliased_vuln.py")
    assert os.path.exists(sample_file), f"Sample file not found: {sample_file}"

    agent = ASTReachabilityAgent(sample_file)
    agent.build_graph()

    result = agent.check_reachability(["yaml.load"])

    assert result.is_reachable is True
    assert result.confidence == 1.0
    assert len(result.call_path) >= 2
    assert "yaml.load()" in result.call_path[-1]


def test_unreachable_imported_reachability():
    """
    Scenario 4: urllib3 is imported and used safely (PoolManager, request),
    never invoking vulnerable symbol (urllib3.util.retry.Retry).
    Expected: is_reachable = False, confidence = 0.0, call_path = [].
    """
    sample_file = os.path.join(SAMPLES_DIR, "sample_unreachable_imported.py")
    assert os.path.exists(sample_file), f"Sample file not found: {sample_file}"

    agent = ASTReachabilityAgent(sample_file)
    agent.build_graph()

    result = agent.check_reachability(["urllib3.util.retry.Retry"])

    assert result.is_reachable is False
    assert result.confidence == 0.0
    assert result.call_path == []
    assert result.depth == 0


def test_dead_code_vuln_unreachable():
    """
    Scenario 5: yaml.load exists in dead_utility_func, uncalled by any entry point.
    Expected: is_reachable = False, confidence = 0.0, call_path = [].
    """
    sample_file = os.path.join(SAMPLES_DIR, "sample_dead_code_vuln.py")
    assert os.path.exists(sample_file), f"Sample file not found: {sample_file}"

    agent = ASTReachabilityAgent(sample_file)
    agent.build_graph()

    result = agent.check_reachability(["yaml.load"])

    assert result.is_reachable is False
    assert result.confidence == 0.0
    assert result.call_path == []
    assert result.depth == 0


def test_dynamic_constructs_limitation_flagging():
    """
    Scenario 6: Inspect AST for dynamic constructs (getattr, eval, importlib.import_module).
    Expected: limitations/uncertainty list populated with detected constructs.
    """
    sample_file = os.path.join(SAMPLES_DIR, "sample_dynamic_dispatch.py")
    assert os.path.exists(sample_file), f"Sample file not found: {sample_file}"

    agent = ASTReachabilityAgent(sample_file)
    agent.build_graph()

    assert len(agent.limitations) >= 3
    assert any("getattr" in lim for lim in agent.limitations)
    assert any("eval" in lim for lim in agent.limitations)
    assert any("importlib" in lim for lim in agent.limitations)

    # Result also propagates limitations
    res = agent.check_reachability(["yaml.load"])
    assert len(res.limitations) >= 3


def test_chained_attribute_calls():
    """
    Tests chained call resolution: urllib3.PoolManager().request(...)
    Verifies that both PoolManager and PoolManager.request match correctly.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = os.path.join(tmp_dir, "chained_test.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("""
import urllib3

def trigger():
    client = urllib3.PoolManager()
    return client.request("GET", "https://api.example.com")

if __name__ == "__main__":
    trigger()
""")

        agent = ASTReachabilityAgent(tmp_dir)
        agent.build_graph()

        res_method = agent.check_reachability(["urllib3.PoolManager.request"])
        assert res_method.is_reachable is True

        res_pkg = agent.check_reachability(["urllib3.PoolManager"])
        assert res_pkg.is_reachable is True


def test_fastapi_route_decorator_entrypoints():
    """
    Tests web framework route handlers (@app.get) detected as entry points.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = os.path.join(tmp_dir, "api.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("""
from fastapi import FastAPI
import yaml

app = FastAPI()

@app.get("/upload")
def upload_handler(data: str):
    return yaml.load(data, Loader=yaml.Loader)
""")

        agent = ASTReachabilityAgent(tmp_dir)
        agent.build_graph()

        res = agent.check_reachability(["yaml.load"])
        assert res.is_reachable is True
        assert res.confidence == 1.0  # Direct call from route handler
        assert res.depth == 1
        assert any("upload_handler" in step for step in res.call_path)


def test_syntax_error_graceful_handling():
    """
    Tests graceful degradation when encountering files with syntax errors.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        bad_file = os.path.join(tmp_dir, "bad_syntax.py")
        with open(bad_file, "w", encoding="utf-8") as f:
            f.write("def broken(x\n  return 1")

        good_file = os.path.join(tmp_dir, "good.py")
        with open(good_file, "w", encoding="utf-8") as f:
            f.write("""
import yaml
if __name__ == "__main__":
    yaml.load("test", Loader=yaml.Loader)
""")

        agent = ASTReachabilityAgent(tmp_dir)
        # Should not throw SyntaxError
        agent.build_graph()

        assert len(agent.warnings) >= 1
        assert any("bad_syntax.py" in w for w in agent.warnings)

        res = agent.check_reachability(["yaml.load"])
        assert res.is_reachable is True


def test_reachability_result_schema_compatibility():
    """
    Tests that ExtendedReachabilityResult is fully compatible with ReachabilityResult
    and VulnerabilityFinding schemas.
    """
    result = ExtendedReachabilityResult(
        is_reachable=True,
        confidence=1.0,
        call_path=["main.py:10:run()", "yaml.load()"],
        limitations=["Dynamic eval detected"],
        call_trace=[{"file_path": "main.py", "line_number": 10, "caller": "run", "callee": "yaml.load"}],
        depth=1,
    )

    # Must be valid ReachabilityResult instance
    assert isinstance(result, ReachabilityResult)
    assert result.is_reachable is True
    assert result.confidence == 1.0

    # Must integrate with VulnerabilityFinding without error
    finding = VulnerabilityFinding(
        cve_id="CVE-2020-1747",
        package_name="pyyaml",
        installed_version="5.1",
        fixed_version="5.3.1",
        vulnerable_symbols=["yaml.load"],
        is_reachable=result.is_reachable,
        reachability_confidence=result.confidence,
        call_path=result.call_path,
        cvss_score=9.8,
        epss_score=0.45,
        is_in_kev=True,
        utility_score=92.5,
        priority_tier="CRITICAL_ACTION",
        ai_reasoning="Reachable yaml.load call site.",
        remediation_advice="Upgrade pyyaml to 5.3.1",
    )
    assert finding.cve_id == "CVE-2020-1747"
    assert finding.is_reachable is True


def test_parent_call_does_not_falsely_match_submethod():
    """
    Verifies that invoking a parent object (urllib3.PoolManager()) does NOT falsely match
    a specific vulnerable sub-method (urllib3.PoolManager.request_encode_body).
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = os.path.join(tmp_dir, "parent_test.py")
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("""
import urllib3

if __name__ == "__main__":
    pm = urllib3.PoolManager()
""")

        agent = ASTReachabilityAgent(tmp_dir)
        agent.build_graph()

        # Specifically targeting a sub-method that was never called
        res = agent.check_reachability(["urllib3.PoolManager.request_encode_body"])
        assert res.is_reachable is False
        assert res.confidence == 0.0


def test_no_duplicate_limitations_in_assignments():
    """
    Verifies that variable assignment statements (e.g. func = getattr(...))
    do not produce duplicate entries in limitations.
    """
    sample_file = os.path.join(SAMPLES_DIR, "sample_dynamic_dispatch.py")
    agent = ASTReachabilityAgent(sample_file)
    agent.build_graph()

    # Exact count: 1 getattr, 1 eval, 1 importlib = 3
    assert len(agent.limitations) == 3
    assert len(agent.limitations) == len(set(agent.limitations)), "Duplicate limitations detected!"


def test_top_level_helper_functions():
    """
    Verifies top-level helper functions: build_call_graph, check_reachability, analyze_reachability.
    """
    sample_file = os.path.join(SAMPLES_DIR, "sample_direct_vuln.py")

    # 1. build_call_graph
    agent = build_call_graph(sample_file)
    assert isinstance(agent, ASTReachabilityAgent)
    assert agent.graph.number_of_nodes() > 0

    # 2. check_reachability
    res1 = check_reachability(sample_file, ["yaml.load"])
    assert res1.is_reachable is True
    assert res1.confidence == 1.0

    # 3. analyze_reachability
    res2 = analyze_reachability(sample_file, ["yaml.load"])
    assert res2.is_reachable is True
    assert res2.confidence == 1.0

