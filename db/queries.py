"""
db/queries.py

All database operations for ShieldLabs.
These functions are the ONLY way the rest of the app
should interact with the database.

Pattern used: Repository Pattern
- Each function does exactly one thing
- Takes a db session as first argument
- Returns model objects or None
"""

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session   # Type hint for the DB session
from sqlalchemy import desc          # For ordering results (descending)

from db.models import Scan, Finding, ScanStatus, Severity

logger = logging.getLogger("shieldlabs.db")


# ─────────────────────────────────────────────
# SCAN OPERATIONS
# ─────────────────────────────────────────────

def create_scan(
    db: Session,
    target: str,
    scan_type: str,
) -> Scan:
    """
    Create a new scan record in the database.

    Args:
        db: The database session (provided by FastAPI's Depends)
        target: What we're scanning (GitHub URL or domain)
        scan_type: "code" or "web"

    Returns:
        The newly created Scan object with its assigned ID

    Example:
        scan = create_scan(db, "github.com/user/repo", "code")
        print(scan.id)  # → 1
    """
    logger.info(f"Creating scan for target: {target}")

    # Step 1: Create a Scan object in memory
    # At this point, it's just a Python object — not in DB yet
    scan = Scan(
        target=target,
        scan_type=scan_type,
        status=ScanStatus.PENDING,  # Always starts as pending
        created_at=datetime.utcnow()
    )

    # Step 2: Add to the session (like adding to a shopping cart)
    db.add(scan)

    # Step 3: Commit — actually writes to the database file
    db.commit()

    # Step 4: Refresh — reloads the object from DB so we get
    # the auto-generated ID and any default values
    db.refresh(scan)

    logger.info(f"Scan created with ID: {scan.id}")
    return scan


def get_scan(db: Session, scan_id: int) -> Optional[Scan]:
    """
    Fetch a single scan by its ID.

    Args:
        db: Database session
        scan_id: The ID of the scan to fetch

    Returns:
        Scan object if found, None if not found

    Example:
        scan = get_scan(db, 1)
        if scan:
            print(scan.status)
        else:
            print("Scan not found")
    """
    # .query(Scan) → SELECT * FROM scans
    # .filter(Scan.id == scan_id) → WHERE id = scan_id
    # .first() → LIMIT 1, returns None if nothing found
    return db.query(Scan).filter(Scan.id == scan_id).first()


def get_all_scans(db: Session, limit: int = 50) -> list[Scan]:
    """
    Fetch all scans, newest first.

    Args:
        db: Database session
        limit: Maximum number of scans to return (default 50)

    Returns:
        List of Scan objects
    """
    return (
        db.query(Scan)
        .order_by(desc(Scan.created_at))  # Newest first
        .limit(limit)
        .all()                            # Returns a list
    )


def update_scan_status(
    db: Session,
    scan_id: int,
    status: ScanStatus,
    error_message: Optional[str] = None
) -> Optional[Scan]:
    """
    Update the status of an existing scan.

    Called when:
    - Scan starts running → status = RUNNING
    - Scan finishes → status = COMPLETED
    - Scan fails → status = FAILED + error_message

    Args:
        db: Database session
        scan_id: Which scan to update
        status: New status value
        error_message: Optional error details if scan failed

    Returns:
        Updated Scan object, or None if scan not found
    """
    # First fetch the scan
    scan = get_scan(db, scan_id)

    if not scan:
        logger.warning(f"Tried to update non-existent scan ID: {scan_id}")
        return None

    # Update the fields
    scan.status = status

    if status == ScanStatus.COMPLETED or status == ScanStatus.FAILED:
        # Record when it finished
        scan.completed_at = datetime.utcnow()

    if error_message:
        scan.error_message = error_message

    # Commit the changes
    db.commit()
    db.refresh(scan)

    logger.info(f"Scan {scan_id} status updated to: {status}")
    return scan


def update_scan_findings_count(db: Session, scan_id: int) -> Optional[Scan]:
    """
    Count all findings for a scan and update total_findings.

    Called after all findings are added to keep the count accurate.

    Args:
        db: Database session
        scan_id: Which scan to update

    Returns:
        Updated Scan object
    """
    scan = get_scan(db, scan_id)
    if not scan:
        return None

    # Count how many findings exist for this scan
    count = db.query(Finding).filter(Finding.scan_id == scan_id).count()
    scan.total_findings = count

    db.commit()
    db.refresh(scan)
    return scan


# ─────────────────────────────────────────────
# FINDING OPERATIONS
# ─────────────────────────────────────────────

def add_finding(
    db: Session,
    scan_id: int,
    vuln_type: str,
    severity: str,
    description: str,
    file_path: Optional[str] = None,
    line_number: Optional[int] = None,
    vulnerable_code: Optional[str] = None,
    ai_explanation: Optional[str] = None,
    ai_fix: Optional[str] = None,
) -> Optional[Finding]:
    """
    Add a vulnerability finding to a scan.

    This is called by the scanner every time it finds a vulnerability.

    Args:
        db: Database session
        scan_id: Which scan this finding belongs to
        vuln_type: Type of vulnerability (e.g., "SQL Injection")
        severity: How serious ("critical", "high", "medium", "low", "info")
        description: What was found
        file_path: Which file had the issue (for code scans)
        line_number: Which line (for code scans)
        vulnerable_code: The actual vulnerable code snippet
        ai_explanation: AI's explanation of the vulnerability
        ai_fix: AI's suggested fix

    Returns:
        The created Finding object, or None if scan doesn't exist
    """
    # Make sure the scan exists before adding a finding to it
    scan = get_scan(db, scan_id)
    if not scan:
        logger.error(f"Cannot add finding — scan {scan_id} does not exist")
        return None

    finding = Finding(
        scan_id=scan_id,
        vuln_type=vuln_type,
        severity=severity.lower(),  # Normalize to lowercase
        description=description,
        file_path=file_path,
        line_number=line_number,
        vulnerable_code=vulnerable_code,
        ai_explanation=ai_explanation,
        ai_fix=ai_fix,
        created_at=datetime.utcnow()
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    logger.info(f"Finding added to scan {scan_id}: {vuln_type} ({severity})")
    return finding


def get_findings_by_scan(
    db: Session,
    scan_id: int,
    severity_filter: Optional[str] = None
) -> list[Finding]:
    """
    Get all findings for a specific scan.

    Args:
        db: Database session
        scan_id: Which scan's findings to fetch
        severity_filter: Optional — only return this severity level
                         e.g., "critical" returns only critical findings

    Returns:
        List of Finding objects
    """
    # Start building the query
    query = db.query(Finding).filter(Finding.scan_id == scan_id)

    # Optionally filter by severity
    if severity_filter:
        query = query.filter(Finding.severity == severity_filter.lower())

    # Order by severity (critical first)
    # We use a CASE-like approach with a list
    severity_order = ["critical", "high", "medium", "low", "info"]

    results = query.all()

    # Sort in Python by our severity order
    results.sort(
        key=lambda f: severity_order.index(f.severity)
        if f.severity in severity_order else 99
    )

    return results


def get_finding(db: Session, finding_id: int) -> Optional[Finding]:
    """
    Fetch a single finding by its ID.

    Args:
        db: Database session
        finding_id: The ID of the finding

    Returns:
        Finding object or None
    """
    return db.query(Finding).filter(Finding.id == finding_id).first()


def delete_scan(db: Session, scan_id: int) -> bool:
    """
    Delete a scan and all its findings.

    The cascade="all, delete-orphan" in our model means
    findings are automatically deleted when the scan is deleted.

    Args:
        db: Database session
        scan_id: Which scan to delete

    Returns:
        True if deleted, False if scan not found
    """
    scan = get_scan(db, scan_id)
    if not scan:
        return False

    db.delete(scan)
    db.commit()
    logger.info(f"Scan {scan_id} and all its findings deleted.")
    return True