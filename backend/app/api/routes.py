import asyncio
import hmac
import logging
import uuid

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, UploadFile

from app.core.config import settings
from app.core.schemas import ScanJob, ScanReport, ScanRequest
from app.services.jobs import JobManager
from app.services.orchestrator import ScanOrchestrator
from app.services.repo_loader import read_upload_limited

logger = logging.getLogger(__name__)

orchestrator = ScanOrchestrator()
jobs = JobManager()


def require_api_key(x_api_key: str = Header(default="")) -> None:
    """If API_KEY is configured, every scan endpoint requires header  X-API-Key."""
    if settings.api_key and not hmac.compare_digest(x_api_key, settings.api_key):
        raise HTTPException(status_code=401, detail="Missing or invalid API key.")


# Public (no key): health only
public = APIRouter(prefix="/api", tags=["Health"])
# Protected
router = APIRouter(prefix="/api", tags=["Scanning"], dependencies=[Depends(require_api_key)])


def _fail(exc: Exception, what: str) -> HTTPException:
    """ValueError = our own validation message (safe to show). Anything else is logged, not leaked."""
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    ref = uuid.uuid4().hex[:8]
    logger.exception("%s failed (ref %s)", what, ref)
    return HTTPException(status_code=500, detail=f"{what} failed due to an internal error (ref {ref}).")


@public.get("/health")
async def health_check():
    return {"status": "ok", "service": "contextvuln-backend", "intel_mode": settings.intel_mode,
            "llm_configured": bool(settings.llm_enabled and settings.gemini_api_key)}


@router.get("/config")
async def scoring_config():
    """Exposes the active scoring model so the UI can show / explain it."""
    return {
        "weights": {"epss": settings.w_epss, "cvss": settings.w_cvss, "kev": settings.w_kev},
        "epss_exponent": settings.epss_exponent,
        "reachability_confidence": {"direct": settings.conf_direct, "transitive": settings.conf_transitive,
                                    "needs_review_prior": settings.conf_needs_review},
        "criticality_band": [settings.criticality_min, settings.criticality_max],
        "tiers": {"critical": settings.tier_critical, "monitor": settings.tier_monitor},
        "floors": {"kev": settings.kev_floor_score, "cvss>=": settings.high_cvss_threshold,
                   "high_cvss": settings.high_cvss_floor_score},
    }


# ----------------------------------------------------------------------------
# Synchronous endpoints (simple; fine for small repos / tests)
# ----------------------------------------------------------------------------
@router.post("/scan/github", response_model=ScanReport)
async def scan_github_repository(request: ScanRequest):
    """Scans a public GitHub repository URL and returns the finished report."""
    try:
        return await orchestrator.scan_github(request)
    except Exception as e:
        raise _fail(e, "GitHub scan")


@router.post("/scan/upload", response_model=ScanReport)
async def scan_uploaded_archive(
    file: UploadFile = File(...),
    business_criticality: float = Form(1.0, ge=0.1, le=2.0),
):
    """Scans an uploaded .zip archive of a project folder."""
    try:
        return await orchestrator.scan_zip_upload(file, business_criticality)
    except Exception as e:
        raise _fail(e, "Archive scan")


# ----------------------------------------------------------------------------
# Job endpoints (recommended for the UI: start, then poll)
# ----------------------------------------------------------------------------
@router.post("/jobs/github", response_model=ScanJob, status_code=202)
async def start_github_job(request: ScanRequest):
    return jobs.submit(lambda sid, cb: orchestrator.scan_github(request, sid, cb))


@router.post("/jobs/upload", response_model=ScanJob, status_code=202)
async def start_upload_job(
    file: UploadFile = File(...),
    business_criticality: float = Form(1.0, ge=0.1, le=2.0),
):
    if not file.filename or not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Please upload a .zip archive of your project folder.")
    try:
        data = await asyncio.to_thread(read_upload_limited, file)  # the upload is closed after the response
    except Exception as e:
        raise _fail(e, "Upload")
    name = file.filename
    return jobs.submit(lambda sid, cb: orchestrator.scan_zip_bytes(data, name, business_criticality, sid, cb))


@router.get("/jobs/{scan_id}", response_model=ScanJob)
async def get_job(scan_id: str):
    job = jobs.get(scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown scan_id (jobs are kept in memory only).")
    return job
