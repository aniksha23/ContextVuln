from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from app.core.schemas import ScanRequest, ScanReport
from app.services.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/api", tags=["Scanning"])
orchestrator = ScanOrchestrator()


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "contextvuln-backend"}


@router.post("/scan/github", response_model=ScanReport)
async def scan_github_repository(request: ScanRequest):
    """Scans a public GitHub repository URL."""
    try:
        return await orchestrator.scan_github(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GitHub scan failed: {str(e)}")


@router.post("/scan/upload", response_model=ScanReport)
async def scan_uploaded_archive(
    file: UploadFile = File(...),
    business_criticality: float = Form(1.0),
):
    """Scans an uploaded .zip archive of a project folder."""
    try:
        return await orchestrator.scan_zip_upload(file, business_criticality)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Archive scan failed: {str(e)}")