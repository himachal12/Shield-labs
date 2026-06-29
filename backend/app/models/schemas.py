"""Pydantic request and response schemas."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanTypeEnum(str, Enum):
    CODE = "code"
    WEB = "web"
    COMBINED = "combined"


class StatusEnum(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CreateScanRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=500)
    scan_type: ScanTypeEnum = ScanTypeEnum.CODE


class CodeScanRequest(BaseModel):
    repo_url: Optional[HttpUrl] = None
    zip_path: Optional[str] = None


class WebScanRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)


class AnalyzeRequest(BaseModel):
    scan_id: str


class AddFindingRequest(BaseModel):
    vuln_type: str = Field(..., min_length=2, max_length=200)
    severity: SeverityEnum
    description: str = Field(..., min_length=5)
    file_path: Optional[str] = None
    line_number: Optional[int] = Field(None, ge=1)
    vulnerable_code: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_fix: Optional[str] = None
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class AskLLMRequest(BaseModel):
    prompt: str = Field(..., min_length=10, max_length=5000)
    prefer_local: bool = False


class FindingResponse(BaseModel):
    id: int
    finding_id: str
    scan_id: str
    vuln_type: str
    severity: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None
    port: Optional[int] = None
    vulnerable_code: Optional[str] = None
    fixed_code: Optional[str] = None
    fix_explanation: Optional[str] = None
    remediation_time: Optional[str] = None
    confidence: float
    is_false_positive: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: int
    scan_id: str
    target: str
    scan_type: str
    status: str
    progress: int
    current_stage: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    total_files: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    model_config = {"from_attributes": True}


class ScanQueuedResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanDetailResponse(ScanResponse):
    findings: list[FindingResponse] = []

    model_config = {"from_attributes": True}


class ResultsResponse(BaseModel):
    scan_id: str
    status: str
    scan_type: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list[FindingResponse]
    report_path: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class LLMResponse(BaseModel):
    success: bool
    response: Optional[str] = None
    model_used: Optional[str] = None
    error: Optional[str] = None


class MessageResponse(BaseModel):
    message: str
    success: bool = True


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    debug: bool
    services: dict
