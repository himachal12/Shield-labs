"""
API routes for ShieldLabs
Main endpoints for scanning, analysis, results
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List
import uuid
import os
from datetime import datetime

from app.database import get_db, Scan, Finding
from app import schemas

# Create router
router = APIRouter(
    prefix="/api",
    tags=["api"]
)

# ==================
# CODE SCANNING
# ==================

@router.post("/scan/code", response_model=schemas.ScanResponse)
async def scan_code(
    request: schemas.CodeScanRequest,
    db: Session = Depends(get_db)
):
    """
    Initiate a code repository scan
    Accepts GitHub URL or ZIP upload
    """
    try:
        # Generate unique scan ID
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        
        # Create scan record in database
        scan = Scan(
            scan_id=scan_id,
            scan_type="code",
            status="queued",
            repo_url=str(request.repo_url) if request.repo_url else None,
            progress=0,
            current_stage="Initializing...",
            created_at=datetime.utcnow()
        )
        
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return schemas.ScanResponse(
            scan_id=scan_id,
            status="queued",
            message="Code scan queued successfully"
        )
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan/web", response_model=schemas.ScanResponse)
async def scan_web(
    request: schemas.WebScanRequest,
    db: Session = Depends(get_db)
):
    """
    Initiate a web application scan
    Scans open ports, services, misconfigurations
    """
    try:
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        
        scan = Scan(
            scan_id=scan_id,
            scan_type="web",
            status="queued",
            domain=request.domain,
            progress=0,
            current_stage="Initializing...",
            created_at=datetime.utcnow()
        )
        
        db.add(scan)
        db.commit()
        db.refresh(scan)
        
        return schemas.ScanResponse(
            scan_id=scan_id,
            status="queued",
            message="Web scan queued successfully"
        )
    
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ==================
# ANALYSIS & RESULTS
# ==================

@router.post("/analyze", response_model=schemas.ScanResponse)
async def analyze_scan(
    request: schemas.AnalyzeRequest,
    db: Session = Depends(get_db)
):
    """
    Start multi-agent analysis on completed scan
    This is where CrewAI agents will run
    """
    # Check if scan exists
    scan = db.query(Scan).filter(Scan.scan_id == request.scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Update status to analyzing
    scan.status = "scanning"
    scan.current_stage = "Running multi-agent analysis..."
    db.commit()
    
    return schemas.ScanResponse(
        scan_id=request.scan_id,
        status="scanning",
        message="Analysis started"
    )


@router.get("/results/{scan_id}", response_model=schemas.ResultsResponse)
async def get_results(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Get scan results (findings, report)
    """
    # Get scan
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get findings for this scan
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    findings_response = [
        schemas.FindingSchema.from_orm(f) for f in findings
    ]
    
    return schemas.ResultsResponse(
        scan_id=scan_id,
        status=scan.status,
        scan_type=scan.scan_type,
        total_findings=scan.total_findings,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        findings=findings_response,
        report_path=scan.report_path,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )


# ==================
# HEALTH & STATUS
# ==================

@router.get("/status/{scan_id}")
async def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db)
):
    """
    Get current scan status (for real-time updates)
    """
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "current_stage": scan.current_stage,
        "total_findings": scan.total_findings
    }