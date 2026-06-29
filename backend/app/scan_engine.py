"""End-to-end scanning pipelines."""

import logging

from app.models import repository
from app.models.database import SessionLocal, init_db
from app.models.entities import ScanStatus
from app.scanners.fix_generator import generate_fixes_for_all
from app.scanners.pattern_detector import scan_file_for_patterns
from app.scanners.semantic_analyzer import filter_findings_with_llm
from app.utils.repo_handler import cleanup_temp_repo, download_github_repo, get_all_code_files

logger = logging.getLogger("shieldlabs.engine")


def _confidence_to_severity(confidence: float) -> str:
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def _get_or_create_scan(db, scan_id: str | None, target: str, scan_type: str, **extra):
    if scan_id:
        scan = repository.get_scan(db, scan_id)
        if scan:
            return scan
    return repository.create_scan(db, target=target, scan_type=scan_type, **extra)


def _save_pipeline_findings(db, scan, findings: list[dict]) -> None:
    for item in findings:
        repository.add_finding(
            db=db,
            scan_id=scan.scan_id,
            vuln_type=item.get("vuln_type", "Unknown"),
            severity=_confidence_to_severity(item.get("confidence", 0.5)),
            description=item.get("reason", "Security finding"),
            file_path=item.get("file"),
            line_number=item.get("line"),
            vulnerable_code=item.get("code_snippet"),
            ai_explanation=item.get("fix_explanation") or item.get("llm_explanation"),
            ai_fix=item.get("fix_code"),
            confidence=item.get("confidence", 1.0),
        )


def scan_local_file(file_path: str, scan_id: str | None = None) -> dict:
    init_db()
    db = SessionLocal()
    scan = None
    try:
        scan = _get_or_create_scan(db, scan_id, file_path, "code")
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=10, stage="Scanning local file")
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()
        findings = scan_file_for_patterns(file_path, source)
        reviewed = filter_findings_with_llm(findings)
        fixed = generate_fixes_for_all(reviewed)
        _save_pipeline_findings(db, scan, fixed)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.COMPLETED.value, progress=100, stage="Completed")
        return format_scan_result(db, scan.scan_id)
    except Exception as exc:
        logger.exception("Local file scan failed")
        if scan:
            repository.update_scan_status(db, scan.scan_id, ScanStatus.FAILED.value, str(exc), progress=100, stage="Failed")
        raise
    finally:
        db.close()


def scan_github_repo(url: str, scan_id: str | None = None) -> dict:
    init_db()
    db = SessionLocal()
    repo_path = None
    scan = None
    try:
        scan = _get_or_create_scan(db, scan_id, url, "code", repo_url=url)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=5, stage="Cloning repository")
        repo_path = download_github_repo(url)
        files = get_all_code_files(repo_path)
        scan.total_files = len(files)
        db.commit()
        all_findings = []
        for file_path in files:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                all_findings.extend(scan_file_for_patterns(file_path, handle.read()))
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=55, stage="Reviewing findings")
        reviewed = filter_findings_with_llm(all_findings)
        fixed = generate_fixes_for_all(reviewed)
        _save_pipeline_findings(db, scan, fixed)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.COMPLETED.value, progress=100, stage="Completed")
        return format_scan_result(db, scan.scan_id)
    except Exception as exc:
        logger.exception("GitHub scan failed")
        if scan:
            repository.update_scan_status(db, scan.scan_id, ScanStatus.FAILED.value, str(exc), progress=100, stage="Failed")
        raise
    finally:
        if repo_path:
            cleanup_temp_repo(repo_path)
        db.close()


def scan_web_domain(domain: str, scan_id: str | None = None) -> dict:
    init_db()
    db = SessionLocal()
    try:
        scan = _get_or_create_scan(db, scan_id, domain, "web", domain=domain)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=25, stage="Preparing web scan")
        repository.update_scan_status(db, scan.scan_id, ScanStatus.COMPLETED.value, progress=100, stage="Completed")
        return format_scan_result(db, scan.scan_id)
    finally:
        db.close()


def format_scan_result(db, scan_id: str) -> dict:
    scan = repository.get_scan(db, scan_id)
    findings = repository.get_findings_by_scan(db, scan_id)
    return {
        "scan": {"id": scan.id, "scan_id": scan.scan_id, "target": scan.target, "status": scan.status, "total_findings": scan.total_findings},
        "findings": [
            {"finding_id": finding.finding_id, "vuln_type": finding.vuln_type, "severity": finding.severity, "file": finding.file_path, "line": finding.line_number, "code": finding.vulnerable_code, "fix": finding.fixed_code}
            for finding in findings
        ],
    }
