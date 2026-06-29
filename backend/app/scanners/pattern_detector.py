"""
scanners/pattern_detector.py

Fast, regex-based detection for the 13 vulnerability types listed
in the ShieldLabs roadmap. This runs BEFORE any LLM call — it's
milliseconds per file and catches the majority of real-world cases.

Each detector function takes the full source text of a file and
returns a list of finding dicts:

{
    "vuln_type": "SQL Injection",
    "file": "app.py",
    "line": 42,
    "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
    "confidence": 0.95,
    "reason": "String concatenation in SQL query allows injection"
}

Day 4 afternoon will take the LOW/MEDIUM confidence findings here
and send them to the LLM (Qwen 2.5) for a second opinion, to cut
down false positives before they ever reach the database.
"""

import re
import logging

logger = logging.getLogger("shieldlabs.pattern_detector")


# ─────────────────────────────────────────────
# HELPER — shared by every detector
# ─────────────────────────────────────────────

def _scan_lines(source: str, pattern: re.Pattern, vuln_type: str,
                 file_path: str, reason: str, confidence: float) -> list[dict]:
    """
    Runs one compiled regex against every line of source and builds
    a finding dict for each match.

    Args:
        source: Full file content
        pattern: Compiled regex to test each line against
        vuln_type: Human-readable vulnerability name
        file_path: Path of the file being scanned (for the report)
        reason: Why this pattern is dangerous (shown to the user)
        confidence: 0.0-1.0 — how sure we are this is a real issue
                    (regex-only findings should rarely be above 0.9;
                    save 0.95+ for things that are almost always bad,
                    like a hardcoded private key)

    Returns:
        List of finding dicts, one per matching line
    """
    findings = []
    for line_no, line in enumerate(source.splitlines(), start=1):
        if pattern.search(line):
            findings.append({
                "vuln_type": vuln_type,
                "file": file_path,
                "line": line_no,
                "code_snippet": line.strip(),
                "confidence": confidence,
                "reason": reason,
            })
    return findings


# ─────────────────────────────────────────────
# 1. SQL INJECTION
# ─────────────────────────────────────────────
# Looks for SQL keywords combined with string concatenation (+) or
# f-strings/format — both classic signs that user input is being
# glued directly into a query instead of using parameters.
SQL_INJECTION_PATTERN = re.compile(
    r'(SELECT|INSERT|UPDATE|DELETE)\b.*?(\+\s*\w+|f["\']|%s|\.format\()',
    re.IGNORECASE
)


def detect_sql_injection(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, SQL_INJECTION_PATTERN, "SQL Injection", file_path,
        reason="SQL query appears to be built using string concatenation "
               "or formatting instead of parameterized queries, allowing "
               "an attacker to inject arbitrary SQL.",
        confidence=0.75  # regex can't tell if the variable is actually user input
    )


# ─────────────────────────────────────────────
# 2. HARDCODED SECRETS
# ─────────────────────────────────────────────
HARDCODED_SECRET_PATTERN = re.compile(
    r'(API_KEY|SECRET_KEY|PASSWORD|TOKEN|ACCESS_KEY|PRIVATE_KEY)\s*=\s*["\'][^"\']{8,}["\']',
    re.IGNORECASE
)


def detect_hardcoded_secrets(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, HARDCODED_SECRET_PATTERN, "Hardcoded Secret", file_path,
        reason="A credential or key is hardcoded directly in source code. "
               "Anyone with access to the repo (or its git history) can "
               "read and reuse it.",
        confidence=0.8
    )


# ─────────────────────────────────────────────
# 3. WEAK HASHING
# ─────────────────────────────────────────────
WEAK_HASH_PATTERN = re.compile(
    r'(hashlib\.md5|hashlib\.sha1|md5\(|sha1\()',
    re.IGNORECASE
)


def detect_weak_hashing(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, WEAK_HASH_PATTERN, "Weak Hashing", file_path,
        reason="MD5 and SHA1 are cryptographically broken for security "
               "purposes (passwords, signatures). Use bcrypt, scrypt, or "
               "Argon2 for passwords; SHA-256+ for integrity checks.",
        confidence=0.85
    )


# ─────────────────────────────────────────────
# 4. MISSING CSRF PROTECTION
# ─────────────────────────────────────────────
# Heuristic: a POST/PUT/DELETE route defined without any nearby
# mention of csrf in the same line. This is intentionally narrow —
# CSRF is hard to detect reliably with regex, so confidence stays low.
CSRF_ROUTE_PATTERN = re.compile(
    r'@\w+\.(route|post|put|delete)\([^)]*\)',
    re.IGNORECASE
)
CSRF_TOKEN_PATTERN = re.compile(r'csrf', re.IGNORECASE)


def detect_missing_csrf(source: str, file_path: str) -> list[dict]:
    findings = []
    lines = source.splitlines()
    for line_no, line in enumerate(lines, start=1):
        if CSRF_ROUTE_PATTERN.search(line) and "GET" not in line.upper():
            # Look at the next 5 lines for any CSRF mention
            window = "\n".join(lines[line_no - 1: line_no + 5])
            if not CSRF_TOKEN_PATTERN.search(window):
                findings.append({
                    "vuln_type": "Missing CSRF Protection",
                    "file": file_path,
                    "line": line_no,
                    "code_snippet": line.strip(),
                    "confidence": 0.4,  # low — many frameworks handle CSRF globally
                    "reason": "A state-changing route (POST/PUT/DELETE) was "
                              "found with no visible CSRF token check nearby. "
                              "Verify the framework isn't handling this globally.",
                })
    return findings


# ─────────────────────────────────────────────
# 5. XSS (Cross-Site Scripting)
# ─────────────────────────────────────────────
# Jinja2 {{ var }} without |escape or |e, or raw HTML response building
XSS_PATTERN = re.compile(
    r'\{\{\s*[\w.]+\s*\}\}(?!\s*\|\s*(escape|e)\b)'
)


def detect_xss(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, XSS_PATTERN, "Cross-Site Scripting (XSS)", file_path,
        reason="A template variable is rendered without an explicit "
               "escape filter. If autoescaping is disabled or this is "
               "rendered as raw HTML, user input could execute as script.",
        confidence=0.5  # many template engines autoescape by default
    )


# ─────────────────────────────────────────────
# 6. WEAK JWT
# ─────────────────────────────────────────────
WEAK_JWT_PATTERN = re.compile(
    r'jwt\.decode\([^)]*verify\s*=\s*False|jwt\.decode\([^)]*verify_signature["\']?\s*:\s*False',
    re.IGNORECASE
)


def detect_weak_jwt(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, WEAK_JWT_PATTERN, "Weak JWT Implementation", file_path,
        reason="JWT signature verification is explicitly disabled. This "
               "allows an attacker to forge tokens with arbitrary claims "
               "(e.g. impersonate an admin).",
        confidence=0.95  # almost never a false positive
    )


# ─────────────────────────────────────────────
# 7. INSECURE DESERIALIZATION
# ─────────────────────────────────────────────
INSECURE_DESERIALIZATION_PATTERN = re.compile(
    r'(pickle\.loads?\(|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|eval\(|exec\()'
)


def detect_insecure_deserialization(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, INSECURE_DESERIALIZATION_PATTERN, "Insecure Deserialization", file_path,
        reason="Deserializing untrusted data with pickle/yaml.load, or "
               "running it through eval()/exec(), can lead to arbitrary "
               "code execution if an attacker controls the input.",
        confidence=0.7
    )


# ─────────────────────────────────────────────
# 8. COMMAND INJECTION
# ─────────────────────────────────────────────
COMMAND_INJECTION_PATTERN = re.compile(
    r'(os\.system\(|subprocess\.(call|run|Popen)\([^)]*\+|subprocess\.(call|run|Popen)\(f["\'])'
)


def detect_command_injection(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, COMMAND_INJECTION_PATTERN, "Command Injection", file_path,
        reason="A shell command is built using string concatenation or "
               "an f-string. If any part comes from user input, an "
               "attacker can inject arbitrary shell commands.",
        confidence=0.8
    )


# ─────────────────────────────────────────────
# 9. MISSING SECURITY HEADERS
# ─────────────────────────────────────────────
# Heuristic only: flag files that build HTTP responses but never
# mention common security headers anywhere in the file.
SECURITY_HEADER_NAMES = ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]
RESPONSE_BUILDING_PATTERN = re.compile(r'(make_response|Response\(|HttpResponse\(|res\.send)')


def detect_missing_security_headers(source: str, file_path: str) -> list[dict]:
    if not RESPONSE_BUILDING_PATTERN.search(source):
        return []  # file doesn't build responses at all, not relevant

    if any(header in source for header in SECURITY_HEADER_NAMES):
        return []  # at least one header is set somewhere — good enough for regex pass

    return [{
        "vuln_type": "Missing Security Headers",
        "file": file_path,
        "line": 1,
        "code_snippet": "(file-level finding — no specific line)",
        "confidence": 0.3,  # low — headers are often set in middleware elsewhere
        "reason": "This file builds HTTP responses but no Content-Security-Policy, "
                  "X-Frame-Options, or Strict-Transport-Security header was found "
                  "anywhere in it. Verify these are set in middleware/config instead.",
    }]


# ─────────────────────────────────────────────
# 10. DEPENDENCY VULNERABILITIES
# ─────────────────────────────────────────────
# This one works on requirements.txt content, not arbitrary code files.
# Flags unpinned versions and a short list of known-old package names
# as a placeholder — Day 6+ could wire this into a real CVE database.
UNPINNED_DEP_PATTERN = re.compile(r'^([\w-]+)\s*$', re.MULTILINE)
KNOWN_OLD_PACKAGES = {"flask": "1.", "django": "1.", "requests": "2.0", "pyyaml": "3."}


def detect_dependency_vulnerabilities(source: str, file_path: str) -> list[dict]:
    if not file_path.endswith("requirements.txt"):
        return []

    findings = []
    for line_no, line in enumerate(source.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "==" not in line and ">=" not in line:
            findings.append({
                "vuln_type": "Dependency Vulnerability (Unpinned Version)",
                "file": file_path,
                "line": line_no,
                "code_snippet": line,
                "confidence": 0.4,
                "reason": "This dependency has no pinned version, so builds "
                          "can silently pull in a newer (or vulnerable) "
                          "release without anyone noticing.",
            })
            continue

        pkg_name = line.split("==")[0].split(">=")[0].strip().lower()
        version = line.split("==")[-1].split(">=")[-1].strip() if "==" in line or ">=" in line else ""
        if pkg_name in KNOWN_OLD_PACKAGES and version.startswith(KNOWN_OLD_PACKAGES[pkg_name]):
            findings.append({
                "vuln_type": "Dependency Vulnerability (Outdated Package)",
                "file": file_path,
                "line": line_no,
                "code_snippet": line,
                "confidence": 0.6,
                "reason": f"{pkg_name} version {version} is an old major "
                          f"release that may have known CVEs. Check for "
                          f"a security advisory before upgrading.",
            })

    return findings


# ─────────────────────────────────────────────
# 11. WEAK CRYPTOGRAPHY
# ─────────────────────────────────────────────
WEAK_CRYPTO_PATTERN = re.compile(
    r'(MODE\.ECB|mode\s*=\s*["\']?ECB|DES\.new|RC4|key_size\s*=\s*(?:64|128)\b)',
    re.IGNORECASE
)


def detect_weak_crypto(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, WEAK_CRYPTO_PATTERN, "Weak Cryptography", file_path,
        reason="ECB mode, DES, RC4, or short key sizes are cryptographically "
               "weak and can be broken with known attacks. Use AES-GCM or "
               "AES-CBC with a random IV and a 256-bit key instead.",
        confidence=0.75
    )


# ─────────────────────────────────────────────
# 12. MISSING RATE LIMITING
# ─────────────────────────────────────────────
# Heuristic: a login/auth route with no rate-limit decorator anywhere nearby
RATE_LIMIT_ROUTE_PATTERN = re.compile(
    r'@\w+\.(route|post)\([^)]*["\']\/(login|signin|auth|register)',
    re.IGNORECASE
)
RATE_LIMIT_DECORATOR_PATTERN = re.compile(r'(limiter|rate_limit|@limit)', re.IGNORECASE)


def detect_missing_rate_limiting(source: str, file_path: str) -> list[dict]:
    findings = []
    lines = source.splitlines()
    for line_no, line in enumerate(lines, start=1):
        if RATE_LIMIT_ROUTE_PATTERN.search(line):
            window = "\n".join(lines[max(0, line_no - 4): line_no + 2])
            if not RATE_LIMIT_DECORATOR_PATTERN.search(window):
                findings.append({
                    "vuln_type": "Missing Rate Limiting",
                    "file": file_path,
                    "line": line_no,
                    "code_snippet": line.strip(),
                    "confidence": 0.4,
                    "reason": "An authentication-related route was found with "
                              "no visible rate limiter nearby. Without this, "
                              "attackers can brute-force credentials.",
                })
    return findings


# ─────────────────────────────────────────────
# 13. UNVALIDATED REDIRECTS
# ─────────────────────────────────────────────
UNVALIDATED_REDIRECT_PATTERN = re.compile(
    r'redirect\(\s*request\.(args|GET|query_params)\.get\(',
    re.IGNORECASE
)


def detect_unvalidated_redirects(source: str, file_path: str) -> list[dict]:
    return _scan_lines(
        source, UNVALIDATED_REDIRECT_PATTERN, "Unvalidated Redirect", file_path,
        reason="A redirect target comes directly from a query parameter "
               "with no allow-list check. Attackers can craft links that "
               "redirect victims to phishing sites while looking trusted.",
        confidence=0.8
    )


# ─────────────────────────────────────────────
# DISPATCHER — runs every applicable detector on a file
# ─────────────────────────────────────────────

# Detectors that run on every code file (not requirements.txt-specific)
CODE_DETECTORS = [
    detect_sql_injection,
    detect_hardcoded_secrets,
    detect_weak_hashing,
    detect_missing_csrf,
    detect_xss,
    detect_weak_jwt,
    detect_insecure_deserialization,
    detect_command_injection,
    detect_missing_security_headers,
    detect_weak_crypto,
    detect_missing_rate_limiting,
    detect_unvalidated_redirects,
]

# Detectors that only make sense on dependency manifest files
DEPENDENCY_DETECTORS = [
    detect_dependency_vulnerabilities,
]


def scan_file_for_patterns(file_path: str, source: str) -> list[dict]:
    """
    Runs every relevant detector against one file's source code.

    Args:
        file_path: Path of the file (used to decide which detectors apply,
                   and included in each finding for reporting)
        source: Full text content of the file

    Returns:
        Combined list of finding dicts from every detector that ran
    """
    findings = []

    detectors = CODE_DETECTORS + DEPENDENCY_DETECTORS

    for detector in detectors:
        try:
            findings.extend(detector(source, file_path))
        except Exception as e:
            # One bad regex/file combo should never crash the whole scan
            logger.warning(f"Detector {detector.__name__} failed on {file_path}: {e}")

    logger.info(f"Found {len(findings)} pattern matches in {file_path}")
    return findings