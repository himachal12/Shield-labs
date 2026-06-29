"""
schemas/scan.py

Pydantic schemas for request validation and response formatting.

WHY SEPARATE FROM DB MODELS?
- db/models.py = how data is stored (SQLAlchemy)
- schemas/scan.py = how data moves in/out of the API (Pydantic)

They look similar but serve different purposes.
Keeping them separate lets you change one without breaking the other.
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from db.models import ScanStatus, ScanType, Severity


# ─────────────────────────────────────────────
# REQUEST SCHEMAS (What the client sends TO us)
# ─────────────────────────────────────────────

class CreateScanRequest(BaseModel):
    """
    Shape of the JSON body when creating a new scan.

    Example request body:
    {
        "target": "github.com/user/repo",
        "scan_type": "code"
    }
    """

    # Field() lets us add validation rules and documentation
    target: str = Field(
        ...,                              # ... means required (no default)
        min_length=3,                     # Must be at least 3 characters
        max_length=500,                   # No more than 500 characters
        description="GitHub URL or domain to scan",
        examples=["github.com/user/repo"]
    )

    scan_type: ScanType = Field(
        ...,
        description="Type of scan: 'code' or 'web'"
    )


class AddFindingRequest(BaseModel):
    """
    Shape of the JSON body when adding a finding manually.

    Example:
    {
        "vuln_type": "SQL Injection",
        "severity": "critical",
        "description": "User input directly used in SQL query",
        "file_path": "app/db.py",
        "line_number": 42
    }
    """
    vuln_type: str = Field(
        ...,
        min_length=2,
        max_length=200,
        description="Type of vulnerability found"
    )

    severity: Severity = Field(
        ...,
        description="Severity level: critical/high/medium/low/info"
    )

    description: str = Field(
        ...,
        min_length=5,
        description="Description of the vulnerability"
    )

    file_path: Optional[str] = Field(
        None,
        description="File where vulnerability was found"
    )

    line_number: Optional[int] = Field(
        None,
        ge=1,                # ge = greater than or equal to 1
        description="Line number of the vulnerability"
    )

    vulnerable_code: Optional[str] = Field(
        None,
        description="The vulnerable code snippet"
    )

    ai_explanation: Optional[str] = Field(
        None,
        description="AI explanation of the vulnerability"
    )

    ai_fix: Optional[str] = Field(
        None,
        description="AI suggested fix"
    )


class AskLLMRequest(BaseModel):
    """
    Shape for directly asking the LLM a security question.
    """
    prompt: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description="The security question to ask the AI"
    )

    prefer_local: bool = Field(
        False,
        description="If true, use local Ollama instead of Groq"
    )


# ─────────────────────────────────────────────
# RESPONSE SCHEMAS (What we send BACK to client)
# ─────────────────────────────────────────────

class FindingResponse(BaseModel):
    """
    Shape of a finding in API responses.
    """
    id: int
    scan_id: int
    vuln_type: str
    severity: str
    description: str
    file_path: Optional[str]
    line_number: Optional[int]
    vulnerable_code: Optional[str]
    ai_explanation: Optional[str]
    ai_fix: Optional[str]
    created_at: datetime

    class Config:
        # This tells Pydantic to read data from SQLAlchemy
        # model attributes, not just plain dicts
        from_attributes = True


class ScanResponse(BaseModel):
    """
    Shape of a scan in API responses.
    """
    id: int
    target: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime]
    error_message: Optional[str]
    total_findings: int

    class Config:
        from_attributes = True


class ScanDetailResponse(ScanResponse):
    """
    Extended scan response that includes findings.
    Inherits everything from ScanResponse and adds findings list.
    """
    findings: list[FindingResponse] = []

    class Config:
        from_attributes = True


class LLMResponse(BaseModel):
    """Response from LLM endpoints."""
    success: bool
    response: Optional[str]
    model_used: Optional[str]
    error: Optional[str]


class MessageResponse(BaseModel):
    """Simple message response for confirmations."""
    message: str
    success: bool = True