"""HTTP routes for ShieldLabs."""

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.models import repository, schemas
from app.models.database import get_db
from app.models.entities import ScanStatus
from app.scan_engine import scan_github_repo, scan_local_file, scan_web_domain
from app.utils.llm import analyze_code_security, ask_llm

logger = logging.getLogger("shieldlabs.api")
router = APIRouter()
legacy_scans_router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])
scan_router = APIRouter(prefix="/api", tags=["Scanning"])


@legacy_scans_router.get("/health", response_model=schemas.MessageResponse)
def health_check():
    return schemas.MessageResponse(message="ShieldLabs API is running")


@legacy_scans_router.post("/", response_model=schemas.ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(request: schemas.CreateScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan = repository.create_scan(db, target=request.target, scan_type=request.scan_type.value, status="pending")
    
    # Run the scan in the background
    if request.scan_type.value == "code":
        if "github.com" in request.target or request.target.startswith("http"):
            background_tasks.add_task(scan_github_repo, request.target, scan.scan_id)
        else:
            background_tasks.add_task(scan_local_file, request.target, scan.scan_id)
    elif request.scan_type.value == "web":
        background_tasks.add_task(scan_web_domain, request.target, scan.scan_id)
        
    return scan



@legacy_scans_router.get("/", response_model=list[schemas.ScanResponse])
def get_all_scans(limit: int = 50, db: Session = Depends(get_db)):
    return repository.get_all_scans(db, limit=limit)


@legacy_scans_router.get("/{scan_id}", response_model=schemas.ScanDetailResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = repository.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return scan


@legacy_scans_router.delete("/{scan_id}", response_model=schemas.MessageResponse)
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    if not repository.delete_scan(db, scan_id):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return schemas.MessageResponse(message=f"Scan {scan_id} deleted successfully")


@legacy_scans_router.post("/{scan_id}/findings", response_model=schemas.FindingResponse, status_code=status.HTTP_201_CREATED)
def add_finding(scan_id: str, request: schemas.AddFindingRequest, db: Session = Depends(get_db)):
    finding = repository.add_finding(
        db=db,
        scan_id=scan_id,
        vuln_type=request.vuln_type,
        severity=request.severity.value,
        description=request.description,
        file_path=request.file_path,
        line_number=request.line_number,
        vulnerable_code=request.vulnerable_code,
        ai_explanation=request.ai_explanation,
        ai_fix=request.ai_fix,
        confidence=request.confidence,
    )
    if not finding:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return finding


@legacy_scans_router.get("/{scan_id}/findings", response_model=list[schemas.FindingResponse])
def get_findings(scan_id: str, severity: str | None = None, db: Session = Depends(get_db)):
    if not repository.get_scan(db, scan_id):
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return repository.get_findings_by_scan(db, scan_id, severity_filter=severity)


@legacy_scans_router.post("/ai/ask", response_model=schemas.LLMResponse, tags=["AI"])
def ask_ai(request: schemas.AskLLMRequest):
    return schemas.LLMResponse(**ask_llm(prompt=request.prompt, prefer_local=request.prefer_local))


@legacy_scans_router.post("/ai/analyze-code", response_model=schemas.LLMResponse, tags=["AI"])
def analyze_code(code: str, language: str = "python"):
    return schemas.LLMResponse(**analyze_code_security(code, language))


@scan_router.post("/scan/code", response_model=schemas.ScanQueuedResponse, status_code=status.HTTP_201_CREATED)
def queue_code_scan(request: schemas.CodeScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    target = str(request.repo_url) if request.repo_url else request.zip_path
    if not target:
        raise HTTPException(status_code=422, detail="repo_url or zip_path is required")
    scan = repository.create_scan(db, target=target, scan_type="code", repo_url=str(request.repo_url) if request.repo_url else None, zip_path=request.zip_path, status=ScanStatus.QUEUED.value)
    
    if request.repo_url:
        background_tasks.add_task(scan_github_repo, str(request.repo_url), scan.scan_id)
    else:
        background_tasks.add_task(scan_local_file, request.zip_path, scan.scan_id)
        
    return schemas.ScanQueuedResponse(scan_id=scan.scan_id, status=scan.status, message="Code scan queued successfully")


@scan_router.post("/scan/web", response_model=schemas.ScanQueuedResponse, status_code=status.HTTP_201_CREATED)
def queue_web_scan(request: schemas.WebScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan = repository.create_scan(db, target=request.domain, scan_type="web", domain=request.domain, status=ScanStatus.QUEUED.value)
    background_tasks.add_task(scan_web_domain, request.domain, scan.scan_id)
    return schemas.ScanQueuedResponse(scan_id=scan.scan_id, status=scan.status, message="Web scan queued successfully")


@scan_router.post("/analyze", response_model=schemas.ScanQueuedResponse)
def analyze_scan(request: schemas.AnalyzeRequest, db: Session = Depends(get_db)):
    scan = repository.update_scan_status(db, request.scan_id, ScanStatus.SCANNING.value, progress=10, stage="Running multi-agent analysis")
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return schemas.ScanQueuedResponse(scan_id=scan.scan_id, status=scan.status, message="Analysis started")


@scan_router.get("/results/{scan_id}", response_model=schemas.ResultsResponse)
def get_results(scan_id: str, db: Session = Depends(get_db)):
    scan = repository.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return schemas.ResultsResponse(
        scan_id=scan.scan_id,
        status=scan.status,
        scan_type=scan.scan_type,
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        findings=repository.get_findings_by_scan(db, scan.scan_id),
        report_path=scan.report_path,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
    )


@scan_router.get("/status/{scan_id}")
def get_scan_status(scan_id: str, db: Session = Depends(get_db)):
    scan = repository.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan_id": scan.scan_id, "status": scan.status, "progress": scan.progress, "current_stage": scan.current_stage, "total_findings": scan.total_findings}


router.include_router(legacy_scans_router)
router.include_router(scan_router)
