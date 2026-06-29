"""
Pydantic schemas for request/response validation
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List
from datetime import datetime
from enum import Enum

# ==================
# ENUMS
# ==================

class ScanTypeEnum(str, Enum):
    """Types of scans"""
    CODE = "code"
    WEB = "web"
    COMBINED = "combined"


class StatusEnum(str, Enum):
    """Scan status"""
    QUEUED = "queued"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityEnum(str, Enum):
    """Vulnerability severity"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ==================
# REQUEST SCHEMAS
# ==================

class CodeScanRequest(BaseModel):
    """Request to scan code repository"""
    repo_url: Optional[HttpUrl] = Field(None, description="GitHub repository URL")
    scan_type: ScanTypeEnum = Field(ScanTypeEnum.CODE, description="Type of scan")
    
    class Config:
        json_schema_extra = {
            "example": {
                "repo_url": "https://github.com/example/vulnerable-app",
                "scan_type": "code"
            }
        }


class WebScanRequest(BaseModel):
    """Request to scan web application"""
    domain: str = Field(..., description="Domain or IP to scan (e.g., example.com or 192.168.1.1)")
    
    class Config:
        json_schema_extra = {
            "example": {
                "domain": "example.com"
            }
        }


class AnalyzeRequest(BaseModel):
    """Request to analyze scan results"""
    scan_id: str = Field(..., description="ID of the scan to analyze")
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "scan_abc123"
            }
        }


# ==================
# RESPONSE SCHEMAS
# ==================

class ScanResponse(BaseModel):
    """Response when scan is initiated"""
    scan_id: str
    status: StatusEnum
    message: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "scan_abc123",
                "status": "queued",
                "message": "Scan queued successfully"
            }
        }


class FindingSchema(BaseModel):
    """Individual vulnerability finding"""
    finding_id: str
    vuln_type: str
    severity: SeverityEnum
    cvss_score: Optional[float] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    url: Optional[str] = None
    port: Optional[int] = None
    description: str
    vulnerable_code: Optional[str] = None
    fixed_code: Optional[str] = None
    fix_explanation: Optional[str] = None
    remediation_time: Optional[str] = None
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    is_false_positive: bool = False
    
    class Config:
        from_attributes = True


class ResultsResponse(BaseModel):
    """Complete scan results"""
    scan_id: str
    status: StatusEnum
    scan_type: ScanTypeEnum
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[FindingSchema]
    report_path: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    app: str
    version: str
    debug: bool
    services: dict


class ErrorResponse(BaseModel):
    """Error response"""
    error: str
    detail: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "error": "Invalid scan ID",
                "detail": "Scan with ID 'xyz' not found"
            }
        }