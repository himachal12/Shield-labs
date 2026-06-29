"""SQLAlchemy models for ShieldLabs scans and findings."""

from datetime import datetime
import enum

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.models.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanType(str, enum.Enum):
    CODE = "code"
    WEB = "web"
    COMBINED = "combined"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    scan_id = Column(String(64), unique=True, index=True, nullable=False)
    target = Column(String(500), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False, default=ScanType.CODE.value)
    status = Column(String(50), nullable=False, default=ScanStatus.QUEUED.value)
    repo_url = Column(String(500), nullable=True)
    zip_path = Column(String(500), nullable=True)
    domain = Column(String(255), nullable=True)
    progress = Column(Integer, default=0)
    current_stage = Column(String(255), default="Queued")
    total_files = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    report_path = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    attack_chains = relationship("AttackChain", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    finding_id = Column(String(80), unique=True, index=True, nullable=False)
    scan_id = Column(String(64), ForeignKey("scans.scan_id"), nullable=False, index=True)
    vuln_type = Column(String(200), nullable=False, index=True)
    severity = Column(String(50), nullable=False, default=Severity.MEDIUM.value, index=True)
    cvss_score = Column(Float, nullable=True)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)
    url = Column(String(500), nullable=True)
    port = Column(Integer, nullable=True)
    description = Column(Text, nullable=False)
    vulnerable_code = Column(Text, nullable=True)
    fixed_code = Column(Text, nullable=True)
    fix_explanation = Column(Text, nullable=True)
    remediation_time = Column(String(100), nullable=True)
    confidence = Column(Float, default=1.0)
    is_false_positive = Column(Boolean, default=False)
    is_cross_domain = Column(Boolean, default=False)
    attack_chain_id = Column(String(80), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    scan_id = Column(String(64), ForeignKey("scans.scan_id"), nullable=False, index=True)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=True)
    executive_summary = Column(Text, nullable=True)
    risk_level = Column(String(50), nullable=False, default=Severity.INFO.value)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="reports")


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    scan_id = Column(String(64), ForeignKey("scans.scan_id"), nullable=False, index=True)
    chain_id = Column(String(80), unique=True, index=True, nullable=False)
    finding_ids = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    time_to_exploit = Column(String(100), nullable=True)
    impact = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    scan = relationship("Scan", back_populates="attack_chains")
