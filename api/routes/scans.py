"""
api/routes/scans.py

FastAPI route handlers for all scan-related endpoints.

Each function here is one API endpoint.
FastAPI automatically:
- Parses the incoming JSON using our Pydantic schemas
- Validates the data (returns 422 if invalid)
- Calls our function
- Serializes the response back to JSON
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import ScanStatus
from db import queries
from schemas.scan import (
    CreateScanRequest,
    AddFindingRequest,
    AskLLMRequest,
    ScanResponse,
    ScanDetailResponse,
    FindingResponse,
    LLMResponse,
    MessageResponse,
)
from utils.llm import ask_llm, analyze_code_security

logger = logging.getLogger("shieldlabs.api")

# APIRouter is like a mini FastAPI app for a specific section.
# prefix="/scans" means all routes here start with /scans
# tags=["Scans"] groups them in the Swagger docs
router = APIRouter(prefix="/scans", tags=["Scans"])


# ─────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────

@router.get("/health", response_model=MessageResponse)
def health_check():
    """
    Simple endpoint to verify the API is running.
    Always returns 200 OK if the server is up.
    """
    return MessageResponse(message="ShieldLabs API is running!", success=True)


# ─────────────────────────────────────────────
# SCAN ENDPOINTS
# ─────────────────────────────────────────────

@router.post(
    "/",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED  # 201 = Created (more accurate than 200)
)
def create_scan(
    request: CreateScanRequest,   # Pydantic auto-validates the request body
    db: Session = Depends(get_db) # FastAPI auto-provides the DB session
):
    """
    Create a new scan.

    The scanner will update this scan's status as it runs.
    Start with POST /scans, get back a scan ID, then use that ID everywhere.
    """
    logger.info(f"New scan request: {request.target} ({request.scan_type})")

    scan = queries.create_scan(
        db=db,
        target=request.target,
        scan_type=request.scan_type.value  # .value converts enum to string
    )

    return scan  # Pydantic automatically converts Scan → ScanResponse


@router.get("/", response_model=list[ScanResponse])
def get_all_scans(
    limit: int = 50,              # Query parameter: /scans?limit=10
    db: Session = Depends(get_db)
):
    """
    Get all scans, newest first.

    Query params:
        limit: How many to return (default 50)
    """
    scans = queries.get_all_scans(db, limit=limit)
    return scans


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def get_scan(
    scan_id: int,                 # Path parameter from the URL
    db: Session = Depends(get_db)
):
    """
    Get a single scan with all its findings.

    Path params:
        scan_id: The ID of the scan (from the URL)
    """
    scan = queries.get_scan(db, scan_id)

    # If not found, raise HTTP 404
    # HTTPException automatically returns the right error response
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )

    return scan


@router.delete("/{scan_id}", response_model=MessageResponse)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """
    Delete a scan and all its findings.
    """
    deleted = queries.delete_scan(db, scan_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )

    return MessageResponse(message=f"Scan {scan_id} deleted successfully")


# ─────────────────────────────────────────────
# FINDINGS ENDPOINTS
# ─────────────────────────────────────────────

@router.post(
    "/{scan_id}/findings",
    response_model=FindingResponse,
    status_code=status.HTTP_201_CREATED
)
def add_finding(
    scan_id: int,
    request: AddFindingRequest,
    db: Session = Depends(get_db)
):
    """
    Add a vulnerability finding to a scan.

    Called by the scanner every time it detects a vulnerability.
    """
    # First verify the scan exists
    scan = queries.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )

    finding = queries.add_finding(
        db=db,
        scan_id=scan_id,
        vuln_type=request.vuln_type,
        severity=request.severity.value,
        description=request.description,
        file_path=request.file_path,
        line_number=request.line_number,
        vulnerable_code=request.vulnerable_code,
        ai_explanation=request.ai_explanation,
        ai_fix=request.ai_fix
    )

    # Update the scan's total_findings count
    queries.update_scan_findings_count(db, scan_id)

    return finding


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
def get_findings(
    scan_id: int,
    severity: str = None,         # Optional filter: /scans/1/findings?severity=critical
    db: Session = Depends(get_db)
):
    """
    Get all findings for a scan.

    Query params:
        severity: Filter by severity (critical/high/medium/low/info)
    """
    scan = queries.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )

    findings = queries.get_findings_by_scan(db, scan_id, severity_filter=severity)
    return findings


# ─────────────────────────────────────────────
# AI ENDPOINTS
# ─────────────────────────────────────────────

@router.post("/ai/ask", response_model=LLMResponse, tags=["AI"])
def ask_ai(request: AskLLMRequest):
    """
    Ask the AI a security question directly.

    Useful for testing the LLM integration and
    for the frontend to show AI explanations.
    """
    result = ask_llm(
        prompt=request.prompt,
        prefer_local=request.prefer_local
    )
    return LLMResponse(**result)


@router.post("/ai/analyze-code", response_model=LLMResponse, tags=["AI"])
def analyze_code(
    code: str,
    language: str = "python"
):
    """
    Analyze a code snippet for security vulnerabilities using AI.

    Query params:
        code: The source code to analyze
        language: Programming language (default: python)
    """
    result = analyze_code_security(code, language)
    return LLMResponse(**result)