"""End-to-end scanning pipelines."""

import logging

from app.agents.code_parser import CodeParserAgent
from app.agents.fix_generation import FixGenerationAgent
from app.models import repository
from app.models.database import SessionLocal, init_db
from app.models.entities import ScanStatus
from app.scanners.web_scanner import run_web_recon
from app.scanners.fix_generator import generate_fixes_for_all
from app.scanners.pattern_detector import scan_file_for_patterns
from app.scanners.semantic_analyzer import filter_findings_with_llm
from app.utils.repo_handler import cleanup_temp_repo, download_github_repo, get_all_code_files

# Instantiated once at module load — CrewAI Agent construction has
# overhead, no need to rebuild per scan.
_code_parser_agent = CodeParserAgent()
_fix_review_agent = FixGenerationAgent()

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


def _save_pipeline_findings(db, scan, findings: list[dict]) -> list:
    saved = []
    for item in findings:
        record = repository.add_finding(
            db=db,
            scan_id=scan.scan_id,
            vuln_type=item.get("vuln_type", "Unknown"),
            severity=item.get("severity_hint") or _confidence_to_severity(item.get("confidence", 0.5)),
            description=item.get("reason", "Security finding"),
            file_path=item.get("file"),
            line_number=item.get("line"),
            vulnerable_code=item.get("code_snippet"),
            ai_explanation=item.get("fix_explanation") or item.get("llm_explanation"),
            ai_fix=item.get("fixed_code"),
            confidence=item.get("confidence", 1.0),
            unified_diff=item.get("unified_diff"),
            breaking_change_risk=item.get("breaking_change_risk"),
        )
        if record:
            saved.append(record)
    return saved


def _review_fixes_with_agent(db, saved_findings: list, source_findings: list[dict]) -> None:
    """
    Runs FixGenerationAgent.review_fix() as a real CrewAI task for
    each finding that has a fix, and attaches the verdict to the
    already-saved Finding record. Non-blocking: a failure here logs
    and moves on rather than failing the whole scan.
    """
    for record, item in zip(saved_findings, source_findings):
        if not item.get("fixed_code"):
            continue
        try:
            verdict = _fix_review_agent.review_fix(item)
            repository.update_finding(db, record.finding_id, agent_review_notes=verdict)
        except Exception:
            logger.exception("Fix Generation Agent review failed for %s; skipping.", record.finding_id)

def scan_local_file(file_path: str, scan_id: str | None = None) -> dict:
    init_db()
    db = SessionLocal()
    scan = None
    try:
        scan = _get_or_create_scan(db, scan_id, file_path, "code")
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=10, stage="Scanning local file")

        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            source = handle.read()

        # CrewAI structural pass — informational, non-blocking. If the
        # agent/LLM has issues, we log and continue with detection
        # rather than failing the whole scan over a context step.
        try:
            structural_summary = _code_parser_agent.analyze(file_path, source)
            logger.info("Code Parser Agent summary for %s:\n%s", file_path, structural_summary)
        except Exception:
            logger.exception("Code Parser Agent failed for %s; continuing without it.", file_path)

        findings = scan_file_for_patterns(file_path, source)
        reviewed = filter_findings_with_llm(findings)
        fixed = generate_fixes_for_all(reviewed)
        saved = _save_pipeline_findings(db, scan, fixed)

        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=90, stage="Reviewing fixes")
        _review_fixes_with_agent(db, saved, fixed)

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
    scan = None
    try:
        scan = _get_or_create_scan(db, scan_id, domain, "web", domain=domain)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=25, stage="Running web reconnaissance")
        findings = run_web_recon(domain)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=70, stage="Generating fixes")
        fixed = generate_fixes_for_all(findings)
        _save_pipeline_findings(db, scan, fixed)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.COMPLETED.value, progress=100, stage="Completed")
        return format_scan_result(db, scan.scan_id)
    except Exception as exc:
        logger.exception("Web domain scan failed")
        if scan:
            repository.update_scan_status(db, scan.scan_id, ScanStatus.FAILED.value, str(exc), progress=100, stage="Failed")
        raise
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