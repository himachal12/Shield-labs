"""
scanners/sqlmap_scanner.py

Day 10 — sqlmap integration.

Wraps the sqlmap CLI (pure Python, invoked via subprocess) to test a
target URL/parameter for SQL injection. Follows the same pattern as
nuclei_scanner.py: hardcoded path w/ env override, narrow/safe scan
scope, hard timeout, fail-safe (never raises, returns [] on failure).

Deliberately conservative by default: --risk=1 --level=1 are the
lowest, least destructive settings sqlmap offers. This is an active,
injecting scanner (unlike Nuclei's read-only detection) — it must
never run against a target without explicit consent, which is why
this is wired up as an opt-in step, not a default part of every scan.
"""

import glob
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

logger = logging.getLogger("shieldlabs.sqlmap_scanner")

SQLMAP_PATH = os.environ.get(
    "SQLMAP_PATH",
    r"C:\Users\acer\Downloads\sqlmap-master\sqlmap-master\sqlmap.py",
)

DEFAULT_TIMEOUT_SECONDS = 120

# Regex to pull each "Parameter: ... Type: ... Title: ... Payload: ..." block
_PARAM_BLOCK_RE = re.compile(
    r"Parameter:\s*(?P<param>\S+)\s*\((?P<method>[^)]+)\)\s*"
    r"(?P<body>(?:\s+Type:.*?\n\s+Title:.*?\n\s+Payload:.*?\n)+)",
    re.MULTILINE,
)
_TRIPLE_RE = re.compile(
    r"Type:\s*(?P<type>.+?)\s*\n\s*Title:\s*(?P<title>.+?)\s*\n\s*Payload:\s*(?P<payload>.+?)\s*\n"
)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>.+)")

# SQLi is always treated as high-severity-minimum, since a confirmed
# injection point is a serious, directly exploitable vulnerability
# regardless of technique.
TECHNIQUE_SEVERITY = {
    "union query": "critical",
    "error-based": "critical",
    "stacked queries": "critical",
    "boolean-based blind": "high",
    "time-based blind": "high",
}


def run_sqlmap_scan(target_url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> list[dict]:
    """
    Runs a scoped sqlmap scan against a single target URL (must
    include a parameter to test, e.g. "http://host/page?id=1") and
    returns normalized findings. Fails safe: any error (missing
    script, timeout, parse failure) logs and returns [] rather than
    raising, so this can't take down a scan pipeline.

    Args:
        target_url: full URL including the parameter(s) to test
        timeout: hard wall-clock limit in seconds

    Returns:
        List of normalized finding dicts (empty if not vulnerable or
        on any failure).
    """
    if not os.path.exists(SQLMAP_PATH):
        logger.warning("sqlmap script not found at %s; skipping sqlmap scan.", SQLMAP_PATH)
        return []

    output_dir = os.path.join(tempfile.gettempdir(), "sqlmap_" + uuid.uuid4().hex[:8])
    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        sys.executable, SQLMAP_PATH,
        "-u", target_url,
        "--batch",
        "--risk=1",
        "--level=1",
        "--output-dir=" + output_dir,
    ]

    try:
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.warning("sqlmap scan for %s exceeded %ds timeout; using partial results if any.", target_url, timeout)
    except Exception:
        logger.exception("sqlmap scan failed for %s.", target_url)
        shutil.rmtree(output_dir, ignore_errors=True)
        return []

    findings = []
    try:
        log_files = glob.glob(os.path.join(output_dir, "*", "log"))
        if not log_files:
            logger.info("sqlmap scan for %s: no log file produced (target not vulnerable or connection failed).", target_url)
            return []

        with open(log_files[0], "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        findings = _parse_sqlmap_log(content, target_url)
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)

    logger.info("sqlmap scan for %s: %d finding(s).", target_url, len(findings))
    return findings


def _parse_sqlmap_log(content: str, target_url: str) -> list[dict]:
    """Parses sqlmap's plaintext log output into normalized findings."""
    findings = []

    dbms_match = _DBMS_RE.search(content)
    dbms = dbms_match.group("dbms").strip() if dbms_match else "Unknown"

    for block_match in _PARAM_BLOCK_RE.finditer(content):
        param = block_match.group("param")
        method = block_match.group("method")
        body = block_match.group("body")

        for triple in _TRIPLE_RE.finditer(body):
            inj_type = triple.group("type").strip()
            title = triple.group("title").strip()
            payload = triple.group("payload").strip()

            severity = TECHNIQUE_SEVERITY.get(inj_type.lower(), "high")

            findings.append({
                "vuln_type": "SQL Injection (" + inj_type + ")",
                "severity": severity,
                "url": target_url,
                "description": title + " — parameter '" + param + "' (" + method + ") is injectable via " + dbms + ".",
                "reason": title,
                "parameter": param,
                "http_method": method,
                "payload": payload,
                "dbms": dbms,
                "source": "sqlmap",
            })

    return findings