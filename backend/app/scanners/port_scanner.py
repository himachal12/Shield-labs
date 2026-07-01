"""
scanners/port_scanner.py

Day 6 — Web Reconnaissance, Milestone 2.

Nmap-based port scanning and service fingerprinting.

Requires the nmap binary to be installed and on PATH (verified
separately via `nmap --version`). This module shells out to it via
the python-nmap wrapper.
"""

import logging

import nmap

logger = logging.getLogger("shieldlabs.port_scanner")

# Common ports only, for speed — a full 1-65535 scan is too slow for
# a hackathon demo. Covers the ports that matter for typical web apps.
COMMON_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,9200,27017"

RISKY_PORTS = {
    21: {"service": "FTP", "severity": "high", "reason": "FTP transmits credentials in plaintext and is frequently misconfigured for anonymous access."},
    23: {"service": "Telnet", "severity": "critical", "reason": "Telnet transmits all data including credentials in plaintext."},
    3306: {"service": "MySQL", "severity": "high", "reason": "Database port exposed to the internet significantly increases attack surface."},
    5432: {"service": "PostgreSQL", "severity": "high", "reason": "Database port exposed to the internet significantly increases attack surface."},
    6379: {"service": "Redis", "severity": "critical", "reason": "Redis has no authentication by default and is commonly exploited when exposed."},
    27017: {"service": "MongoDB", "severity": "high", "reason": "MongoDB is commonly misconfigured with no authentication when exposed to the internet."},
    3389: {"service": "RDP", "severity": "high", "reason": "Remote Desktop exposed to the internet is a common ransomware entry point."},
    5900: {"service": "VNC", "severity": "high", "reason": "VNC is frequently deployed with weak or no authentication."},
    9200: {"service": "Elasticsearch", "severity": "critical", "reason": "Elasticsearch has no authentication by default and commonly leaks data when exposed."},
    445: {"service": "SMB", "severity": "high", "reason": "SMB exposed to the internet is a common vector for worms and ransomware (e.g. EternalBlue)."},
}


def scan_ports(target: str, ports: str = COMMON_PORTS) -> list[dict]:
    """
    Runs an Nmap TCP connect scan against the target's common ports.

    Args:
        target: domain or IP, e.g. "example.com" or "192.168.1.1"
        ports: comma-separated port list or Nmap-style range string

    Returns:
        list of finding dicts, shaped to match the rest of the pipeline
        (vuln_type, url, line=None, confidence, reason, severity_hint)
    """
    scanner = nmap.PortScanner()
    findings = []

    logger.info("Starting Nmap scan of %s on ports %s", target, ports)

    try:
        # -sT = TCP connect scan (no raw sockets needed, works without admin)
        # -Pn = skip host discovery ping (some hosts block ICMP)
        # --version-light = quick service/version detection
        scanner.scan(target, ports, arguments="-sT -Pn --version-light")
    except nmap.PortScannerError as exc:
        logger.error("Nmap scan failed for %s: %s", target, exc)
        return [{
            "vuln_type": "Port Scan Failed",
            "url": target,
            "line": None,
            "confidence": 1.0,
            "reason": "Nmap could not scan " + target + ": " + str(exc),
        }]

    hosts_found = scanner.all_hosts()
    if not hosts_found:
        logger.warning("Host %s did not respond to scan.", target)
        return []

    # python-nmap keys results by IP, not the original hostname passed in,
    # so we use whatever host key nmap actually returned.
    host_key = hosts_found[0]
    host_info = scanner[host_key]

    for proto in host_info.all_protocols():
        ports_found = host_info[proto].keys()
        for port in ports_found:
            port_info = host_info[proto][port]
            if port_info.get("state") != "open":
                continue

            service_name = port_info.get("name", "unknown")
            product = port_info.get("product", "")
            version = port_info.get("version", "")
            service_detail = (product + " " + version).strip() or service_name

            risky = RISKY_PORTS.get(port)
            if risky:
                findings.append({
                    "vuln_type": "Risky Open Port: " + str(port) + " (" + risky["service"] + ")",
                    "url": target,
                    "line": None,
                    "confidence": 0.85,
                    "reason": risky["reason"] + " Detected service: " + service_detail + ".",
                    "severity_hint": risky["severity"],
                })
            else:
                findings.append({
                    "vuln_type": "Open Port: " + str(port),
                    "url": target,
                    "line": None,
                    "confidence": 0.6,
                    "reason": "Port " + str(port) + " (" + service_name + ") is open. Detected: " + service_detail + ". Verify this service should be publicly accessible.",
                    "severity_hint": "low",
                })

    logger.info("Nmap scan of %s complete: %d open port(s) found.", target, len(findings))
    return findings