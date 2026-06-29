"""
db/models.py

SQLAlchemy database models for ShieldLabs.

Each class = one database table.
Each class attribute = one column in that table.
"""

from datetime import datetime
from sqlalchemy import (
    Column,         # Defines a column
    Integer,        # Integer data type
    String,         # String/text data type
    Text,           # Long text data type
    DateTime,       # Date and time data type
    ForeignKey,     # Links two tables together
    Enum            # Restricts values to a specific set
)
from sqlalchemy.orm import relationship  # Defines relationships between tables
import enum                              # Python's built-in enum module

from db.database import Base            # Our Base class from database.py


# ─────────────────────────────────────────────
# ENUMS — Allowed values for certain columns
# ─────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    """
    Possible states a scan can be in.
    Using an Enum prevents typos — you can't accidentally
    set status to "runing" instead of "running".
    """
    PENDING   = "pending"    # Scan created but not started
    RUNNING   = "running"    # Scan in progress
    COMPLETED = "completed"  # Scan finished successfully
    FAILED    = "failed"     # Scan encountered an error


class ScanType(str, enum.Enum):
    """Type of scan being performed."""
    CODE = "code"   # Scanning source code (GitHub/ZIP)
    WEB  = "web"    # Scanning a website/domain


class Severity(str, enum.Enum):
    """
    Vulnerability severity levels.
    Based on industry standard CVSS scoring.
    """
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"       # Informational, not a real vulnerability


# ─────────────────────────────────────────────
# SCAN MODEL
# ─────────────────────────────────────────────

class Scan(Base):
    """
    Represents a single security scan.

    One scan can have many findings.
    Think of it as the "job" — findings are the results.
    """

    # __tablename__ tells SQLAlchemy what to name the table in the database
    __tablename__ = "scans"

    # PRIMARY KEY — unique identifier for each row
    # autoincrement=True means SQLite assigns 1, 2, 3... automatically
    id = Column(Integer, primary_key=True, autoincrement=True)

    # What are we scanning? GitHub URL or domain name
    # index=True makes searching by target faster (adds a DB index)
    target = Column(String(500), nullable=False, index=True)

    # What type of scan: "code" or "web"
    scan_type = Column(String(50), nullable=False)

    # Current state of the scan
    # default=ScanStatus.PENDING means new scans start as "pending"
    status = Column(
        String(50),
        nullable=False,
        default=ScanStatus.PENDING
    )

    # When was the scan created? Defaults to right now.
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # When did the scan finish? Null until completed.
    completed_at = Column(DateTime, nullable=True)

    # Optional: store error message if scan failed
    error_message = Column(Text, nullable=True)

    # How many vulnerabilities were found (filled in when scan completes)
    total_findings = Column(Integer, default=0)

    # ── RELATIONSHIP ──
    # This tells SQLAlchemy: "A Scan has many Finding objects"
    # back_populates="scan" links to the Finding.scan relationship below
    # cascade="all, delete-orphan" means: if a Scan is deleted,
    # automatically delete all its findings too
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        """String representation for debugging."""
        return f"<Scan id={self.id} target={self.target} status={self.status}>"


# ─────────────────────────────────────────────
# FINDING MODEL
# ─────────────────────────────────────────────

class Finding(Base):
    """
    Represents a single vulnerability found during a scan.

    Each finding belongs to one scan (via scan_id foreign key).
    """

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # FOREIGN KEY — links this finding to a specific scan
    # "scans.id" means: reference the id column of the scans table
    # nullable=False means every finding MUST belong to a scan
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)

    # What type of vulnerability is this?
    # e.g., "SQL Injection", "Hardcoded Secret", "XSS"
    vuln_type = Column(String(200), nullable=False)

    # How serious is it?
    severity = Column(String(50), nullable=False, default=Severity.MEDIUM)

    # Human-readable description of what was found
    description = Column(Text, nullable=False)

    # Where in the code was it found? (for code scans)
    file_path = Column(String(500), nullable=True)
    line_number = Column(Integer, nullable=True)

    # The actual vulnerable code snippet
    vulnerable_code = Column(Text, nullable=True)

    # AI-generated explanation (from utils/llm.py)
    ai_explanation = Column(Text, nullable=True)

    # AI-generated fix suggestion
    ai_fix = Column(Text, nullable=True)

    # When was this finding recorded?
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # ── RELATIONSHIP ──
    # This is the other side of the Scan.findings relationship
    # "scan" gives us access to the parent Scan object
    scan = relationship("Finding.scan" and "Scan", back_populates="findings")

    def __repr__(self):
        return f"<Finding id={self.id} type={self.vuln_type} severity={self.severity}>"