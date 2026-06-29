"""
scan_engine.py

Main pipeline — wired to use the existing SQLAlchemy
models and queries your friend built on Day 1-2.
"""

import logging
from db.database import SessionLocal, engine, Base
from db.models import ScanStatus
from db import queries
from scanners.pattern_detector import scan_file_for_patterns
from scanners.semantic_analyzer import filter_findings_with_llm
from scanners.fix_generator import generate_fixes_for_all
from utils.repo_handler import (
    download_github_repo, get_all_code_files,
    cleanup_temp_repo
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shieldlabs.engine")


def _init_db():
    """Creates tables if they don't exist yet."""
    Base.metadata.create_all(bind=engine)


def _confidence_to_severity(confidence: float) -> str:
    """Maps our 0.0-1.0 confidence score to severity levels."""
    if confidence >= 0.9:
        return "critical"
    elif confidence >= 0.75:
        return "high"
    elif confidence >= 0.5:
        return "medium"
    else:
        return "low"


def scan_local_file(file_path: str) -> dict:
    """Scan a single local file end-to-end."""
    _init_db()
    db = SessionLocal()

    try:
        # Create scan record
        scan = queries.create_scan(db, target=file_path, scan_type="code")
        queries.update_scan_status(db, scan.id, ScanStatus.RUNNING)

        # Read file
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        # Run pipeline
        findings = scan_file_for_patterns(file_path, source)
        reviewed = filter_findings_with_llm(findings)
        fixed = generate_fixes_for_all(reviewed)

        # Save each finding
        for f in fixed:
            queries.add_finding(
                db,
                scan_id=scan.id,
                vuln_type=f.get("vuln_type", "Unknown"),
                severity=_confidence_to_severity(f.get("confidence", 0.5)),
                description=f.get("reason", ""),
                file_path=f.get("file"),
                line_number=f.get("line"),
                vulnerable_code=f.get("code_snippet"),
                ai_explanation=f.get("llm_explanation"),
                ai_fix=f.get("fix_code"),
            )

        # Mark complete
        queries.update_scan_findings_count(db, scan.id)
        queries.update_scan_status(db, scan.id, ScanStatus.COMPLETED)

        # Return result
        scan = queries.get_scan(db, scan.id)
        findings_out = queries.get_findings_by_scan(db, scan.id)

        return {
            "scan": {
                "id": scan.id,
                "target": scan.target,
                "status": scan.status,
                "total_findings": scan.total_findings,
                "created_at": str(scan.created_at),
            },
            "findings": [
                {
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "file": f.file_path,
                    "line": f.line_number,
                    "code": f.vulnerable_code,
                    "explanation": f.ai_explanation,
                    "fix": f.ai_fix,
                }
                for f in findings_out
            ]
        }

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        queries.update_scan_status(db, scan.id, ScanStatus.FAILED, str(e))
        raise

    finally:
        db.close()


def scan_github_repo(url: str) -> dict:
    """Clone a GitHub repo and scan all code files."""
    _init_db()
    db = SessionLocal()
    repo_path = None

    try:
        scan = queries.create_scan(db, target=url, scan_type="code")
        queries.update_scan_status(db, scan.id, ScanStatus.RUNNING)

        repo_path = download_github_repo(url)
        files = get_all_code_files(repo_path)

        all_findings = []
        for file_path in files:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            findings = scan_file_for_patterns(file_path, source)
            all_findings.extend(findings)

        reviewed = filter_findings_with_llm(all_findings)
        fixed = generate_fixes_for_all(reviewed)

        for f in fixed:
            queries.add_finding(
                db,
                scan_id=scan.id,
                vuln_type=f.get("vuln_type", "Unknown"),
                severity=_confidence_to_severity(f.get("confidence", 0.5)),
                description=f.get("reason", ""),
                file_path=f.get("file"),
                line_number=f.get("line"),
                vulnerable_code=f.get("code_snippet"),
                ai_explanation=f.get("llm_explanation"),
                ai_fix=f.get("fix_code"),
            )

        queries.update_scan_findings_count(db, scan.id)
        queries.update_scan_status(db, scan.id, ScanStatus.COMPLETED)

        scan = queries.get_scan(db, scan.id)
        findings_out = queries.get_findings_by_scan(db, scan.id)

        return {
            "scan": {
                "id": scan.id,
                "target": scan.target,
                "status": scan.status,
                "total_findings": scan.total_findings,
            },
            "findings": [
                {
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "file": f.file_path,
                    "line": f.line_number,
                    "fix": f.ai_fix,
                }
                for f in findings_out
            ]
        }

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        queries.update_scan_status(db, scan.id, ScanStatus.FAILED, str(e))
        raise

    finally:
        if repo_path:
            cleanup_temp_repo(repo_path)
        db.close()