"""
scanners/nuclei_scanner.py

Day 8-9 — Nuclei integration.

Wraps the Nuclei CLI binary via subprocess, matching the same pattern
used for Nmap elsewhere in this project. Deliberately scoped narrow
(specific tags, request/rate limits, hard timeout) since a full
default Nuclei run took ~7 minutes in testing — far too slow to run
synchronously inside a web scan request.
"""

import json
import logging
import os
import subprocess
import tempfile
import uuid

logger = logging.getLogger("shieldlabs.nuclei_scanner")

# Hardcode the binary path rather than relying on PATH — one less
# thing that can silently break across machines/environments.
NUCLEI_PATH = os.environ.get(
    "NUCLEI_PATH",
    r"C:\Users\acer\Downloads\nuclei_3.10.0_windows_amd64\nuclei.exe",
)

# Narrow, low-risk template categories only. Full scans (thousands of
# templates) are too slow for a synchronous web scan step; this list
# favors detection/misconfiguration/exposure checks over intrusive
# exploit-attempt templates.
DEFAULT_TAGS = "exposure,misconfig,tech,default-login"

DEFAULT_RATE_LIMIT = 15
DEFAULT_TIMEOUT_SECONDS = 600


def run_nuclei_scan(target: str, tags: str = DEFAULT_TAGS, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> list[dict]:
    """
    Runs a scoped Nuclei scan against a target URL/domain and returns
    parsed findings. Fails safe: any error (missing binary, timeout,
    malformed output) logs and returns an empty list rather than
    raising, so this can't take down an entire web scan.

    Args:
        target: URL or domain to scan (e.g. "http://example.com")
        tags: comma-separated Nuclei template tags to restrict scope
        timeout: hard wall-clock limit in seconds

    Returns:
        List of normalized finding dicts.
    """
    if not os.path.exists(NUCLEI_PATH):
        logger.warning("Nuclei binary not found at %s; skipping Nuclei scan.", NUCLEI_PATH)
        return []

    output_file = os.path.join(tempfile.gettempdir(), "nuclei_" + uuid.uuid4().hex[:8] + ".jsonl")

    cmd = [
        NUCLEI_PATH,
        "-u", target,
        "-tags", tags,
        "-rate-limit", str(DEFAULT_RATE_LIMIT),
        "-jsonl",
        "-o", output_file,
        "-silent",
        "-no-color",
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
        logger.warning("Nuclei scan for %s exceeded %ds timeout; using partial results if any.", target, timeout)
    except Exception:
        logger.exception("Nuclei scan failed for %s.", target)
        return []

    if not os.path.exists(output_file):
        logger.info("Nuclei scan for %s produced no output file (no matches or early exit).", target)
        return []

    findings = []
    seen = set()
    try:
        with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    normalized = _normalize_finding(raw)
                    # Dedupe: some templates (e.g. missing-security-headers)
                    # emit one identical match per sub-check rather than
                    # one aggregated result. Same template_id + url is a
                    # real duplicate, not a distinct finding.
                    dedupe_key = (normalized["template_id"], normalized["url"])
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    findings.append(normalized)
                except json.JSONDecodeError:
                    logger.warning("Skipping malformed Nuclei JSON line for %s.", target)

    finally:
        try:
            os.remove(output_file)
        except OSError:
            pass

    logger.info("Nuclei scan for %s: %d finding(s).", target, len(findings))
    return findings


def _normalize_finding(raw: dict) -> dict:
    """Maps a raw Nuclei JSONL record into ShieldLabs' finding shape."""
    info = raw.get("info", {})
    severity = (info.get("severity") or "info").lower()
    classification = info.get("classification", {}) or {}

    return {
        "vuln_type": info.get("name", raw.get("template-id", "Nuclei Finding")),
        "severity": severity,
        "url": raw.get("matched-at") or raw.get("url"),
        "description": info.get("description", "").strip(),
        "reason": info.get("description", "").strip(),
        "template_id": raw.get("template-id"),
        "tags": info.get("tags", []),
        "cve_id": classification.get("cve-id"),
        "cwe_id": classification.get("cwe-id"),
        "cvss_score": classification.get("cvss-score"),
        "reference": (info.get("reference") or [None])[0],
        "source": "nuclei",
    }