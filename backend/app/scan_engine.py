"""End-to-end scanning pipelines."""
import os
import json
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
from app.agents.severity_reasoning import SeverityReasoningAgent
from app.agents.cross_domain_analyzer import CrossDomainAnalysisAgent
from app.utils.pdf_generator_html import generate_pdf_report_html
from app.scanners.nuclei_scanner import run_nuclei_scan

# Instantiated once at module load — CrewAI Agent construction has
# overhead, no need to rebuild per scan.
_code_parser_agent = CodeParserAgent()
_fix_review_agent = FixGenerationAgent()
_cross_domain_agent = CrossDomainAnalysisAgent()
_severity_agent = SeverityReasoningAgent()

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

def _assess_severity_with_agent(db, saved_findings: list, source_findings: list[dict]) -> None:
    """
    Runs SeverityReasoningAgent.assess() for each saved finding and
    attaches CVSS + exploitability data. Non-blocking: a failure here
    logs and moves on rather than failing the whole scan.
    """
    for record, item in zip(saved_findings, source_findings):
        try:
            assessment = _severity_agent.assess(item)
            repository.update_finding(
                db,
                record.finding_id,
                cvss_score=assessment.get("cvss_score"),
                cvss_vector=assessment.get("cvss_vector"),
                exploitability=assessment.get("exploitability"),
                time_to_exploit=assessment.get("time_to_exploit"),
                business_impact=assessment.get("business_impact"),
            )
        except Exception:
            logger.exception("Severity Reasoning Agent failed for %s; skipping.", record.finding_id)


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
        _assess_severity_with_agent(db, saved, fixed)

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

        # Cap agent-based structural analysis to avoid excessive LLM
        # calls on large repos — every file still gets pattern-detected,
        # only the CrewAI narrative summary is capped.
        MAX_STRUCTURAL_ANALYSIS_FILES = 10

        all_findings = []
        for index, file_path in enumerate(files):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                source = handle.read()

            if index < MAX_STRUCTURAL_ANALYSIS_FILES:
                try:
                    summary = _code_parser_agent.analyze(file_path, source)
                    logger.info("Code Parser Agent summary for %s:\n%s", file_path, summary)
                except Exception:
                    logger.exception("Code Parser Agent failed for %s; continuing without it.", file_path)

            all_findings.extend(scan_file_for_patterns(file_path, source))

        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=55, stage="Reviewing findings")
        reviewed = filter_findings_with_llm(all_findings)
        fixed = generate_fixes_for_all(reviewed)
        saved = _save_pipeline_findings(db, scan, fixed)

        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=90, stage="Reviewing fixes")
        _review_fixes_with_agent(db, saved, fixed)
        _assess_severity_with_agent(db, saved, fixed)

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


def scan_web_domain(domain: str, scan_id: str | None = None, deep_scan: bool = False) -> dict:
    """
    Runs web reconnaissance (headers, ports, SSL) against a domain.

    If deep_scan=True, also runs a Nuclei scan for misconfigurations,
    exposures, and known-weakness checks (SSH ciphers, missing
    headers, etc.). Nuclei adds several minutes to the scan — kept
    opt-in so a default web scan stays fast, matching prior behavior.
    """
    init_db()
    db = SessionLocal()
    scan = None
    try:
        scan = _get_or_create_scan(db, scan_id, domain, "web", domain=domain)
        repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=25, stage="Running web reconnaissance")
        findings = run_web_recon(domain)

        if deep_scan:
            repository.update_scan_status(db, scan.scan_id, ScanStatus.RUNNING.value, progress=45, stage="Running Nuclei deep scan")
            target_url = domain if domain.startswith(("http://", "https://")) else "http://" + domain
            try:
                nuclei_findings = run_nuclei_scan(target_url)
                findings.extend(nuclei_findings)
            except Exception:
                logger.exception("Nuclei deep scan failed for %s; continuing with existing findings.", domain)

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
        
def analyze_cross_domain(code_scan_id: str, web_scan_id: str) -> dict:
    """
    Pulls findings from an existing code scan and an existing web scan
    (both already completed) and runs the Cross-Domain Analysis Agent
    to identify compounded-risk attack chains between them.

    Saves any chains found under the code scan's record (see the
    design note in repository.add_attack_chain — chains are stored
    against a single scan_id even though they span two scans), and
    marks the underlying findings as is_cross_domain=True.

    Returns:
        dict with the two source scan_ids and the list of chains found.
    """
    init_db()
    db = SessionLocal()
    try:
        code_findings_orm = repository.get_findings_by_scan(db, code_scan_id)
        web_findings_orm = repository.get_findings_by_scan(db, web_scan_id)

        code_findings = [
            {"finding_id": f.finding_id, "vuln_type": f.vuln_type, "description": f.description}
            for f in code_findings_orm
        ]
        web_findings = [
            {"finding_id": f.finding_id, "vuln_type": f.vuln_type, "description": f.description}
            for f in web_findings_orm
        ]

        chains = _cross_domain_agent.identify_chains(code_findings, web_findings)

        saved_chains = []
        for chain in chains:
            record = repository.add_attack_chain(
                db=db,
                scan_id=code_scan_id,
                finding_ids=chain.get("finding_ids", []),
                severity=chain.get("severity", "medium"),
                description=chain.get("description", ""),
                time_to_exploit=chain.get("time_to_exploit"),
                impact=chain.get("impact"),
            )
            if record:
                saved_chains.append(record)
                for finding_id in chain.get("finding_ids", []):
                    repository.update_finding(db, finding_id, is_cross_domain=True, attack_chain_id=record.chain_id)

        logger.info("Cross-domain analysis (%s + %s): %d chain(s) found.", code_scan_id, web_scan_id, len(saved_chains))

        return {
            "code_scan_id": code_scan_id,
            "web_scan_id": web_scan_id,
            "chains_found": len(saved_chains),
            "chains": [
                {
                    "chain_id": c.chain_id,
                    "finding_ids": json.loads(c.finding_ids),
                    "severity": c.severity,
                    "description": c.description,
                    "time_to_exploit": c.time_to_exploit,
                    "impact": c.impact,
                }
                for c in saved_chains
            ],
        }
    finally:
        db.close()
        

def generate_report(scan_id: str, force: bool = False) -> str:
    """
    Generates (or returns the existing) PDF report for a completed scan.

    Pulls the scan's findings and any attack chains, builds the PDF via
    the HTML/Jinja2 generator, and saves the resulting path onto the
    Scan record so repeat requests don't regenerate unnecessarily.

    Args:
        scan_id: the scan to report on
        force: if True, regenerates even if a report_path already exists
               and the file is still present on disk

    Returns:
        Absolute file path of the PDF.
    """
    init_db()
    db = SessionLocal()
    try:
        scan_orm = repository.get_scan(db, scan_id)
        if not scan_orm:
            raise ValueError("Scan not found: " + str(scan_id))

        if not force and scan_orm.report_path and os.path.exists(scan_orm.report_path):
            logger.info("Reusing existing report for %s: %s", scan_id, scan_orm.report_path)
            return scan_orm.report_path

        findings_orm = repository.get_findings_by_scan(db, scan_id)
        findings = [
            {
                "finding_id": f.finding_id,
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "file": f.file_path,
                "line": f.line_number,
                "url": f.url,
                "code": f.vulnerable_code,
                "fix": f.fixed_code,
                "cvss_score": f.cvss_score,
                "cvss_vector": f.cvss_vector,
                "agent_review_notes": f.agent_review_notes,
                "business_impact": f.business_impact,
            }
            for f in findings_orm
        ]

        chains_orm = repository.get_attack_chains_by_scan(db, scan_id)
        chains = [
            {
                "severity": c.severity,
                "time_to_exploit": c.time_to_exploit,
                "description": c.description,
                "impact": c.impact,
            }
            for c in chains_orm
        ]

        scan_dict = {
            "scan_id": scan_orm.scan_id,
            "target": scan_orm.target,
            "scan_type": scan_orm.scan_type,
        }

        report_path = generate_pdf_report_html(scan_dict, findings, chains)
        repository.update_scan_report_path(db, scan_id, report_path)

        logger.info("Generated report for scan %s: %s", scan_id, report_path)
        return report_path
    finally:
        db.close()


def format_scan_result(db, scan_id: str) -> dict:
    scan = repository.get_scan(db, scan_id)
    findings = repository.get_findings_by_scan(db, scan_id)
    return {
        "scan": {"id": scan.id, "scan_id": scan.scan_id, "target": scan.target, "status": scan.status, "total_findings": scan.total_findings},
        "findings": [
            {
                "finding_id": finding.finding_id,
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "file": finding.file_path,
                "line": finding.line_number,
                "code": finding.vulnerable_code,
                "fix": finding.fixed_code,
                "unified_diff": finding.unified_diff,
                "breaking_change_risk": finding.breaking_change_risk,
                "agent_review_notes": finding.agent_review_notes,
                "cvss_score": finding.cvss_score,
                "cvss_vector": finding.cvss_vector,
                "exploitability": finding.exploitability,
                "time_to_exploit": finding.time_to_exploit,
                "business_impact": finding.business_impact,
            }
            for finding in findings
        ],
    }
