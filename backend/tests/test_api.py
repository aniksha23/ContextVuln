import io
import os
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.api import routes
from app.main import app
from app.services.mock_intel import MockThreatIntelAgent

DEMO = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo_project")


def demo_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for root, _, files in os.walk(DEMO):
            for name in files:
                full = os.path.join(root, name)
                zf.write(full, os.path.join("demo_project", os.path.relpath(full, DEMO)))
    return buf.getvalue()


@pytest.fixture(autouse=True)
def mock_mode(monkeypatch):
    routes.orchestrator.intel_agent = MockThreatIntelAgent()
    monkeypatch.setattr(routes.settings, "api_key", "")
    monkeypatch.setattr(routes.settings, "gemini_api_key", "")
    routes.orchestrator.utility_agent.api_key = ""


@pytest.fixture
def client():
    with TestClient(app) as c:      # keeps the event loop alive so background jobs can finish
        yield c


def upload(client, data=None, name="p.zip", **form):
    return client.post("/api/scan/upload", files={"file": (name, data or demo_zip(), "application/zip")}, data=form)


def test_health_is_open(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_demo_project_end_to_end(client):
    r = upload(client)
    assert r.status_code == 200, r.text
    j = r.json()
    tiers = {f["cve_id"]: f["priority_tier"] for f in j["findings"]}
    assert tiers["CVE-2020-14343"] == "CRITICAL_ACTION"          # yaml.load really called
    assert tiers["CVE-2021-33503"] == "SUPPRESSED_NOISE"         # urllib3 used, parse_url never called
    assert tiers["CVE-2023-32681"] == "SUPPRESSED_NOISE"         # requests never imported
    assert j["noise_reduction_pct"] == 75.0 and j["scan_id"] and j["files_analyzed"] == 4
    top = j["findings"][0]
    assert top["call_trace"] and top["remediation"]["requirements_diff"].count("+pyyaml==5.4") == 1


def test_validation_errors_are_clean(client):
    assert upload(client, criticality="x").status_code in (200, 422)
    assert upload(client, business_criticality="99").status_code == 422
    assert upload(client, name="p.txt").status_code == 400
    r = upload(client, data=b"notazip")
    assert r.status_code == 400 and "not a valid" in r.json()["detail"]


def test_internal_errors_do_not_leak_details(client, monkeypatch):
    async def boom(*a, **k):
        raise RuntimeError("secret /srv/path/leak")
    monkeypatch.setattr(routes.orchestrator, "scan_zip_upload", boom)
    r = upload(client)
    assert r.status_code == 500 and "secret" not in r.text and "ref" in r.json()["detail"]


def test_scan_request_accepts_old_and_new_field_names():
    from app.core.schemas import ScanRequest
    assert ScanRequest(repo_path="https://github.com/a/b").repo_url.endswith("a/b")
    assert ScanRequest(repo_url="https://github.com/a/b").repo_url.endswith("a/b")


def test_github_route_rejects_non_github_urls(client):
    r = client.post("/api/scan/github", json={"repo_url": "/etc"})
    assert r.status_code == 400 and "Invalid GitHub" in r.json()["detail"]


def test_job_flow_start_poll_finish(client):
    r = client.post("/api/jobs/upload", files={"file": ("p.zip", demo_zip(), "application/zip")})
    assert r.status_code == 202
    sid = r.json()["scan_id"]
    for _ in range(100):
        job = client.get(f"/api/jobs/{sid}").json()
        if job["status"] in ("done", "failed"):
            break
        time.sleep(0.05)
    assert job["status"] == "done" and job["progress"] == 1.0
    assert job["report"]["total_cves_found"] == 4 and job["report"]["scan_id"] == sid


def test_failed_job_reports_safe_error(client):
    r = client.post("/api/jobs/upload", files={"file": ("p.zip", b"notazip", "application/zip")})
    sid = r.json()["scan_id"]
    for _ in range(100):
        job = client.get(f"/api/jobs/{sid}").json()
        if job["status"] != "queued" and job["status"] != "running":
            break
        time.sleep(0.05)
    assert job["status"] == "failed" and "not a valid" in job["error"]


def test_unknown_job_is_404(client):
    assert client.get("/api/jobs/nope").status_code == 404


def test_api_key_protects_scan_endpoints_but_not_health(client, monkeypatch):
    monkeypatch.setattr(routes.settings, "api_key", "s3cret")
    assert client.get("/api/health").status_code == 200
    assert upload(client).status_code == 401
    ok = client.post("/api/scan/upload", files={"file": ("p.zip", demo_zip(), "application/zip")},
                     headers={"X-API-Key": "s3cret"})
    assert ok.status_code == 200


def test_config_endpoint_exposes_scoring_model(client):
    j = client.get("/api/config").json()
    assert abs(sum(j["weights"].values()) - 1.0) < 1e-9
