"""
scanners/web_scanner.py

Day 6 — Web Reconnaissance, Milestone 1.

Pure HTTP-based checks (no external tools required):
- Security header analysis
- Exposed sensitive file detection (.git, .env, etc.)
- Basic technology fingerprinting

Each check returns finding dicts shaped like pattern_detector's output
(including a "line" key, even though it's None for web findings) so
they can flow through the same semantic_analyzer / fix_generator
pipeline used for code findings.
"""

import logging

import requests
from app.scanners.port_scanner import scan_ports

logger = logging.getLogger("shieldlabs.web_scanner")

REQUEST_TIMEOUT = 8

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "reason": "Missing HSTS header allows protocol downgrade attacks (HTTP instead of HTTPS).",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "reason": "Missing X-Frame-Options allows clickjacking via iframe embedding.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "reason": "Missing X-Content-Type-Options allows MIME-sniffing attacks.",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "reason": "Missing Content-Security-Policy increases risk of XSS and data injection attacks.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "reason": "Missing Referrer-Policy may leak sensitive URL data to third parties.",
    },
}

EXPOSED_PATHS = {
    "/.git/config": "Exposed .git directory allows attackers to download entire source code history.",
    "/.git/HEAD": "Exposed .git directory allows attackers to download entire source code history.",
    "/.env": "Exposed .env file may leak API keys, database credentials, and secrets.",
    "/.env.local": "Exposed .env.local file may leak API keys, database credentials, and secrets.",
    "/wp-config.php.bak": "Exposed backup config file may leak database credentials.",
    "/.aws/credentials": "Exposed AWS credentials file allows full cloud account takeover.",
    "/config.json": "Exposed config.json may leak internal configuration or secrets.",
}


def _normalize_url(target: str) -> str:
    """Ensures the target has a scheme; defaults to https."""
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def check_security_headers(target: str) -> list[dict]:
    """
    Fetches the target's headers once and reports any missing
    security-relevant headers. Tries https first, falls back to
    http if the target doesn't serve TLS.

    Returns:
        list of finding dicts (one per missing header)
    """
    url = _normalize_url(target)
    findings = []

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        # https failed — try plain http before giving up entirely
        fallback_url = url.replace("https://", "http://")
        try:
            response = requests.get(fallback_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            url = fallback_url
        except requests.RequestException as exc:
            logger.warning("Could not reach %s for header check: %s", fallback_url, exc)
            return [{
                "vuln_type": "Unreachable Target",
                "url": fallback_url,
                "line": None,
                "confidence": 1.0,
                "reason": "Could not connect to " + fallback_url + ": " + str(exc),
            }]
        
    present_headers = {h.lower() for h in response.headers.keys()}

    for header_name, meta in SECURITY_HEADERS.items():
        if header_name.lower() not in present_headers:
            findings.append({
                "vuln_type": "Missing Security Header: " + header_name,
                "url": url,
                "line": None,
                "confidence": 0.9,
                "reason": meta["reason"],
                "severity_hint": meta["severity"],
            })

    server_header = response.headers.get("Server")
    if server_header:
        findings.append({
            "vuln_type": "Server Header Disclosure",
            "url": url,
            "line": None,
            "confidence": 0.5,
            "reason": "Server header reveals software/version (" + server_header + "), aiding attacker reconnaissance.",
            "severity_hint": "low",
        })

    logger.info("Header check on %s found %d issue(s).", url, len(findings))
    return findings


def check_exposed_files(target: str) -> list[dict]:
    """
    Probes a fixed list of commonly sensitive paths to see if they're
    publicly accessible.

    Returns:
        list of finding dicts (one per exposed path found)
    """
    base_url = _normalize_url(target).rstrip("/")
    findings = []

    for path, reason in EXPOSED_PATHS.items():
        full_url = base_url + path
        try:
            response = requests.get(full_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue

        if response.status_code == 200 and len(response.content) > 0:
            findings.append({
                "vuln_type": "Exposed Sensitive File",
                "url": full_url,
                "line": None,
                "confidence": 0.85,
                "reason": reason,
                "severity_hint": "critical",
            })

    logger.info("Exposed-file check on %s found %d issue(s).", base_url, len(findings))
    return findings

def run_web_recon(target: str) -> list[dict]:
    """
    Runs all web recon checks (headers, exposed files, open ports)
    and combines results.

    Args:
        target: domain or URL, e.g. "example.com" or "https://example.com"

    Returns:
        Combined list of finding dicts from all checks.
    """
    logger.info("Starting web recon for %s", target)

    # scan_ports needs a bare hostname, not a URL with scheme/path
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    findings = []
    findings.extend(check_security_headers(target))
    findings.extend(check_exposed_files(target))
    findings.extend(scan_ports(host))
    logger.info("Web recon complete for %s: %d total finding(s).", target, len(findings))
    return findings