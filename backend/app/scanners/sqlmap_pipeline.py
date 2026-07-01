"""
scanners/sqlmap_pipeline.py

Day 10 — SQLi discovery + injection pipeline.

Combines param_discovery (find candidate URLs) with sqlmap_scanner
(test each candidate) into one opt-in deep-scan step. Kept as its
own thin module rather than merged into either piece, so discovery
and injection stay independently testable/auditable.
"""

import logging

from app.scanners.param_discovery import discover_injectable_targets, DEFAULT_MAX_PARAMS
from app.scanners.sqlmap_scanner import run_sqlmap_scan

logger = logging.getLogger("shieldlabs.sqlmap_pipeline")


def run_sqli_deep_scan(base_url: str, max_params: int = DEFAULT_MAX_PARAMS) -> list[dict]:
    """
    Discovers candidate injectable URLs on base_url, then runs sqlmap
    against each one. Fails safe throughout — any failure in either
    stage degrades to fewer/no findings, never raises.
    """
    candidates = discover_injectable_targets(base_url, max_params=max_params)
    if not candidates:
        logger.info("No SQLi candidates discovered for %s.", base_url)
        return []

    all_findings = []
    for url in candidates:
        try:
            findings = run_sqlmap_scan(url)
            all_findings.extend(findings)
        except Exception:
            logger.exception("sqlmap scan failed for discovered candidate %s.", url)

    logger.info("SQLi deep scan for %s: %d total finding(s) across %d candidate(s).", base_url, len(all_findings), len(candidates))
    return all_findings