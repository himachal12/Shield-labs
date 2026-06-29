"""
scan_engine.py

The main pipeline. Takes a file path or GitHub URL,
runs the full scan, saves to SQLite, returns results.
"""

import logging
from db.database import init_db, create_scan, save_findings, finish_scan, get_scan_with_findings
from scanners.ast_parser import parse_file
from scanners.pattern_detector import scan_file_for_patterns
from scanners.semantic_analyzer import filter_findings_with_llm
from scanners.fix_generator import generate_fixes_for_all
from utils.repo_handler import (
    download_github_repo, extract_zip,
    get_all_code_files, cleanup_temp_repo,
    validate_github_url
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shieldlabs.engine")


def scan_local_file(file_path: str) -> dict:
    """Scan a single local file end-to-end."""
    init_db()
    scan_id = create_scan(file_path, "local_file")

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        findings = scan_file_for_patterns(file_path, source)
        reviewed = filter_findings_with_llm(findings)
        fixed = generate_fixes_for_all(reviewed)

        save_findings(scan_id, fixed)
        finish_scan(scan_id, total_files=1, total_findings=len(fixed))

        return get_scan_with_findings(scan_id)

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        finish_scan(scan_id, 0, 0)
        raise


def scan_github_repo(url: str) -> dict:
    """Clone a GitHub repo and scan all code files."""
    init_db()
    scan_id = create_scan(url, "github")
    repo_path = None

    try:
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

        save_findings(scan_id, fixed)
        finish_scan(scan_id, total_files=len(files), total_findings=len(fixed))

        return get_scan_with_findings(scan_id)

    finally:
        if repo_path:
            cleanup_temp_repo(repo_path)