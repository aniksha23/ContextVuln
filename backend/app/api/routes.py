from fastapi import APIRouter, HTTPException
from app.core.schemas import ScanRequest, ScanReport
from app.services.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/api", tags=["Scanning"])
orchestrator = ScanOrchestrator()

@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "contextvuln-backend"}

@router.post("/scan", response_model=ScanReport)
async def scan_repository(request: ScanRequest):
    try:
        return await orchestrator.execute_scan(request)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan pipeline failed: {str(e)}")