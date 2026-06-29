"""Repository functions for database access."""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import desc
from sqlalchemy.orm import Session, selectinload

from app.models.entities import Finding, Scan, ScanStatus

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def make_scan_id() -> str:
    return f"scan_{uuid.uuid4().hex[:8]}"


def make_finding_id(vuln_type: str) -> str:
    prefix = "".join(ch for ch in vuln_type.lower() if ch.isalnum())[:12] or "finding"
    return f"find_{prefix}_{uuid.uuid4().hex[:8]}"


def create_scan(db: Session, target: str, scan_type: str, **extra) -> Scan:
    scan = Scan(
        scan_id=extra.pop("scan_id", make_scan_id()),
        target=target,
        scan_type=scan_type,
        status=extra.pop("status", ScanStatus.PENDING.value),
        repo_url=extra.pop("repo_url", None),
        zip_path=extra.pop("zip_path", None),
        domain=extra.pop("domain", None),
        current_stage=extra.pop("current_stage", "Queued"),
        progress=extra.pop("progress", 0),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: int | str) -> Optional[Scan]:
    query = db.query(Scan).options(selectinload(Scan.findings))
    if isinstance(scan_id, int) or str(scan_id).isdigit():
        scan = query.filter(Scan.id == int(scan_id)).first()
        if scan:
            return scan
    return query.filter(Scan.scan_id == str(scan_id)).first()


def get_all_scans(db: Session, limit: int = 50) -> list[Scan]:
    return db.query(Scan).order_by(desc(Scan.created_at)).limit(limit).all()


def update_scan_status(db: Session, scan_id: int | str, status: str | ScanStatus, error_message: Optional[str] = None, progress: Optional[int] = None, stage: Optional[str] = None) -> Optional[Scan]:
    scan = get_scan(db, scan_id)
    if not scan:
        return None
    status_value = status.value if hasattr(status, "value") else str(status)
    scan.status = status_value
    if status_value in {ScanStatus.RUNNING.value, ScanStatus.SCANNING.value} and not scan.started_at:
        scan.started_at = datetime.utcnow()
    if status_value in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value}:
        scan.completed_at = datetime.utcnow()
    if error_message:
        scan.error_message = error_message
    if progress is not None:
        scan.progress = progress
    if stage is not None:
        scan.current_stage = stage
    db.commit()
    db.refresh(scan)
    return scan


def add_finding(db: Session, scan_id: int | str, vuln_type: str, severity: str, description: str, file_path: Optional[str] = None, line_number: Optional[int] = None, vulnerable_code: Optional[str] = None, ai_explanation: Optional[str] = None, ai_fix: Optional[str] = None, confidence: float = 1.0, **extra) -> Optional[Finding]:
    scan = get_scan(db, scan_id)
    if not scan:
        return None
    finding = Finding(
        finding_id=extra.pop("finding_id", make_finding_id(vuln_type)),
        scan_id=scan.scan_id,
        vuln_type=vuln_type,
        severity=severity.lower(),
        description=description,
        file_path=file_path,
        line_number=line_number,
        url=extra.pop("url", None),
        port=extra.pop("port", None),
        vulnerable_code=vulnerable_code,
        fixed_code=ai_fix or extra.pop("fixed_code", None),
        fix_explanation=ai_explanation or extra.pop("fix_explanation", None),
        remediation_time=extra.pop("remediation_time", None),
        confidence=confidence,
        cvss_score=extra.pop("cvss_score", None),
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    update_scan_findings_count(db, scan.scan_id)
    return finding


def update_finding(db: Session, finding_id: str, **updates) -> Optional[Finding]:
    finding = db.query(Finding).filter(Finding.finding_id == finding_id).first()
    if not finding:
        return None
    for key, value in updates.items():
        if hasattr(finding, key):
            setattr(finding, key, value)
    db.commit()
    db.refresh(finding)
    update_scan_findings_count(db, finding.scan_id)
    return finding


def get_findings_by_scan(db: Session, scan_id: int | str, severity_filter: Optional[str] = None) -> list[Finding]:
    scan = get_scan(db, scan_id)
    if not scan:
        return []
    query = db.query(Finding).filter(Finding.scan_id == scan.scan_id)
    if severity_filter:
        query = query.filter(Finding.severity == severity_filter.lower())
    findings = query.all()
    findings.sort(key=lambda item: SEVERITY_ORDER.index(item.severity) if item.severity in SEVERITY_ORDER else 99)
    return findings


def update_scan_findings_count(db: Session, scan_id: int | str) -> Optional[Scan]:
    scan = get_scan(db, scan_id)
    if not scan:
        return None
    findings = db.query(Finding).filter(Finding.scan_id == scan.scan_id).all()
    scan.total_findings = len(findings)
    scan.critical_count = sum(1 for f in findings if f.severity == "critical")
    scan.high_count = sum(1 for f in findings if f.severity == "high")
    scan.medium_count = sum(1 for f in findings if f.severity == "medium")
    scan.low_count = sum(1 for f in findings if f.severity == "low")
    scan.info_count = sum(1 for f in findings if f.severity == "info")
    db.commit()
    db.refresh(scan)
    return scan


def delete_scan(db: Session, scan_id: int | str) -> bool:
    scan = get_scan(db, scan_id)
    if not scan:
        return False
    db.delete(scan)
    db.commit()
    return True
