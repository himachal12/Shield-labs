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

import socket
import ssl
from datetime import datetime, timezone
import time

import logging

import requests
from app.scanners.port_scanner import scan_ports

logger = logging.getLogger("shieldlabs.web_scanner")

REQUEST_TIMEOUT = 8
REQUEST_DELAY = 0.5  # seconds between requests, to avoid hammering the target

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
            time.sleep(REQUEST_DELAY)
            continue
        time.sleep(REQUEST_DELAY)

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

COMMON_SUBDOMAINS = ["www", "api", "admin", "dev", "staging", "test", "mail", "ftp", "vpn", "portal"]


def enumerate_subdomains(target: str) -> list[dict]:
    """
    Checks a fixed list of common subdomain prefixes to see which
    resolve and respond. Not exhaustive (that needs DNS brute-forcing
    tools like amass/subfinder) but catches obvious exposed subdomains
    fast without extra dependencies.

    Returns:
        list of finding dicts (one per subdomain found alive)
    """
    root_domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    for prefix in COMMON_SUBDOMAINS:
        subdomain = prefix + "." + root_domain
        url = "https://" + subdomain
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            if response.status_code < 500:
                findings.append({
                    "vuln_type": "Subdomain Discovered: " + subdomain,
                    "url": url,
                    "line": None,
                    "confidence": 0.7,
                    "reason": "Subdomain " + subdomain + " is live and responding. Verify it should be publicly accessible and is not an unpatched/forgotten environment (e.g. staging, dev, admin).",
                    "severity_hint": "medium" if prefix in ("admin", "dev", "staging", "test") else "low",
                })
        except requests.RequestException:
            pass
        time.sleep(REQUEST_DELAY)

    logger.info("Subdomain enum on %s found %d live subdomain(s).", root_domain, len(findings))
    return findings

def check_ssl_tls(target: str) -> list[dict]:
    """
    Connects on port 443 and inspects the certificate for expiration
    and the negotiated protocol for weak/outdated TLS versions.

    Returns:
        list of finding dicts (empty if the site doesn't serve HTTPS,
        or if everything checks out fine)
    """
    hostname = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                protocol = tls_sock.version()
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        logger.info("%s does not serve HTTPS on port 443; skipping SSL/TLS check.", hostname)
        return []
    except ssl.SSLError as exc:
        findings.append({
            "vuln_type": "SSL/TLS Configuration Error",
            "url": hostname,
            "line": None,
            "confidence": 0.9,
            "reason": "SSL/TLS handshake failed: " + str(exc) + ". This may indicate an expired, self-signed, or misconfigured certificate.",
            "severity_hint": "high",
        })
        return findings

    if protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append({
            "vuln_type": "Weak TLS Protocol Version",
            "url": hostname,
            "line": None,
            "confidence": 0.9,
            "reason": "Server negotiated " + protocol + ", which is deprecated and vulnerable to known attacks. Should require TLS 1.2 or higher.",
            "severity_hint": "high",
        })

    not_after = cert.get("notAfter")
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (expiry - datetime.now(timezone.utc)).days
            if days_remaining < 0:
                findings.append({
                    "vuln_type": "Expired SSL Certificate",
                    "url": hostname,
                    "line": None,
                    "confidence": 1.0,
                    "reason": "SSL certificate expired " + str(abs(days_remaining)) + " day(s) ago. Browsers will show security warnings to users.",
                    "severity_hint": "critical",
                })
            elif days_remaining < 30:
                findings.append({
                    "vuln_type": "SSL Certificate Expiring Soon",
                    "url": hostname,
                    "line": None,
                    "confidence": 0.9,
                    "reason": "SSL certificate expires in " + str(days_remaining) + " day(s). Renew before it lapses to avoid an outage.",
                    "severity_hint": "medium",
                })
        except ValueError:
            logger.warning("Could not parse certificate expiry date: %s", not_after)

    logger.info("SSL/TLS check on %s found %d issue(s).", hostname, len(findings))
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
    findings.extend(enumerate_subdomains(target))
    findings.extend(check_ssl_tls(target))
    findings.extend(scan_ports(host))
    logger.info("Web recon complete for %s: %d total finding(s).", target, len(findings))
    return findings