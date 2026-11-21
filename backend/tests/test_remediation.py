import os

from app.core.remediation import (
    apply_version_check, build_remediation_plan, build_requirements_diff, upgrade_effort,
)


def test_upgrade_effort_levels():
    assert upgrade_effort("1.26.4", "1.26.5") == "patch"
    assert upgrade_effort("1.26.4", "1.27.0") == "minor"
    assert upgrade_effort("1.26.4", "2.0.0") == "major"
    assert upgrade_effort("1.26.4", None) == "unknown"
    assert upgrade_effort("garbage", "1.0") == "unknown"
    assert upgrade_effort("2.0", "1.0") == "unknown"   # fixed older than installed makes no sense


def test_requirements_diff_bumps_only_the_target(make_project):
    root = make_project({"requirements.txt": "urllib3==1.26.4\nPyYAML==5.3.1  # cfg\nflask>=2.0\n"})
    diff = build_requirements_diff(root, "pyyaml", "5.3.1", "5.4")
    assert "-PyYAML==5.3.1" in diff and "+PyYAML==5.4  # cfg" in diff
    assert "urllib3" not in diff.replace("urllib3==1.26.4", "")  # untouched lines not in +/- hunks
    assert "+urllib3" not in diff and "-urllib3" not in diff


def test_requirements_diff_empty_when_package_absent_or_no_fix(make_project):
    root = make_project({"requirements.txt": "flask==2.0.1\n"})
    assert build_requirements_diff(root, "urllib3", "1.0", "1.1") == ""
    assert build_requirements_diff(root, "flask", "2.0.1", None) == ""
    assert build_requirements_diff("/nonexistent", "flask", "2.0.1", "2.1") == ""


def test_requirements_found_one_folder_deep(make_project):
    root = make_project({"my_project/requirements.txt": "urllib3==1.26.4\n"})
    assert "+urllib3==1.26.5" in build_requirements_diff(root, "urllib3", "1.26.4", "1.26.5")


def test_plan_quick_win_and_major_warning(make_project):
    root = make_project({"requirements.txt": "urllib3==1.26.4\n"})
    p = build_remediation_plan(root, "urllib3", "1.26.4", "1.26.5", "CVE-1", reachable=True)
    assert p.quick_win and p.pr_title.startswith("fix(deps)")
    p2 = build_remediation_plan(root, "urllib3", "1.26.4", "2.0.0", "CVE-1", reachable=True)
    assert not p2.quick_win and any("Major" in m for m in p2.mitigations)
    p3 = build_remediation_plan(root, "urllib3", "1.26.4", None, "CVE-1", reachable=True)
    assert p3.mitigations and not p3.quick_win


def test_version_check_false_adds_warning():
    p = build_remediation_plan(None, "x", "1.0", "1.1", "CVE-1", False)
    assert apply_version_check(p, False).version_validated is False
    assert any("PyPI" in m for m in p.mitigations)
