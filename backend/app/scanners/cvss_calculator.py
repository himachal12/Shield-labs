"""
scanners/cvss_calculator.py

Day 7-8 — Severity Reasoning, deterministic half.

Computes a CVSS 3.1 base score from a heuristic mapping of vuln_type
to the standard CVSS metrics (AV/AC/PR/UI/S/C/I/A). This is a
reasonable-default mapping per vulnerability category, not a
per-instance forensic analysis — exact CVSS scoring requires details
(auth requirements, exact deployment context) we don't have.
"""

import logging

logger = logging.getLogger("shieldlabs.cvss_calculator")

AV_WEIGHTS = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
AC_WEIGHTS = {"low": 0.77, "high": 0.44}
PR_WEIGHTS_UNCHANGED = {"none": 0.85, "low": 0.62, "high": 0.27}
PR_WEIGHTS_CHANGED = {"none": 0.85, "low": 0.68, "high": 0.5}
UI_WEIGHTS = {"none": 0.85, "required": 0.62}
CIA_WEIGHTS = {"none": 0.0, "low": 0.22, "high": 0.56}

VULN_CVSS_DEFAULTS = {
    "sql injection": ("network", "low", "none", "none", False, "high", "high", "low"),
    "command injection": ("network", "low", "none", "none", True, "high", "high", "high"),
    "hardcoded secret": ("network", "low", "none", "none", False, "high", "low", "none"),
    "weak hashing": ("network", "high", "none", "none", False, "high", "none", "none"),
    "weak jwt": ("network", "low", "none", "none", False, "high", "high", "none"),
    "insecure deserialization": ("network", "low", "none", "none", True, "high", "high", "high"),
    "xss": ("network", "low", "none", "required", False, "low", "low", "none"),
    "csrf": ("network", "low", "none", "required", False, "none", "high", "none"),
    "unvalidated redirect": ("network", "low", "none", "required", False, "low", "none", "none"),
    "missing rate limiting": ("network", "low", "none", "none", False, "none", "none", "low"),
    "missing security header": ("network", "high", "none", "required", False, "low", "low", "none"),
    "exposed sensitive file": ("network", "low", "none", "none", False, "high", "low", "none"),
    "risky open port": ("network", "low", "none", "none", False, "high", "high", "low"),
    "open port": ("network", "high", "none", "none", False, "low", "none", "none"),
    "weak tls protocol version": ("network", "high", "none", "none", False, "low", "none", "none"),
    "expired ssl certificate": ("network", "low", "none", "required", False, "low", "low", "none"),
    "subdomain discovered": ("network", "high", "none", "none", False, "none", "none", "none"),
    "server header disclosure": ("network", "high", "none", "none", False, "none", "none", "none"),
}

DEFAULT_METRICS = ("network", "high", "low", "required", False, "low", "low", "low")


def _match_defaults(vuln_type: str):
    key = vuln_type.lower()
    for pattern, metrics in VULN_CVSS_DEFAULTS.items():
        if pattern in key:
            return metrics
    logger.info("No CVSS default for vuln_type '%s'; using conservative fallback.", vuln_type)
    return DEFAULT_METRICS


def calculate_cvss(vuln_type: str) -> dict:
    """
    Computes a CVSS 3.1 base score and vector string for a vuln_type,
    using the heuristic default metrics for that category.

    Returns:
        dict with cvss_score (float), cvss_vector (str)
    """
    av, ac, pr, ui, scope_changed, c, i, a = _match_defaults(vuln_type)

    av_val = AV_WEIGHTS[av]
    ac_val = AC_WEIGHTS[ac]
    pr_weights = PR_WEIGHTS_CHANGED if scope_changed else PR_WEIGHTS_UNCHANGED
    pr_val = pr_weights[pr]
    ui_val = UI_WEIGHTS[ui]
    c_val = CIA_WEIGHTS[c]
    i_val = CIA_WEIGHTS[i]
    a_val = CIA_WEIGHTS[a]

    iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0:
        base_score = 0.0
    elif scope_changed:
        base_score = min(10.0, round(1.08 * (impact + exploitability), 1))
    else:
        base_score = min(10.0, round(impact + exploitability, 1))

    base_score = round(min(base_score, 10.0), 1)

    vector = (
        "CVSS:3.1/AV:" + av[0].upper() +
        "/AC:" + ac[0].upper() +
        "/PR:" + pr[0].upper() +
        "/UI:" + ui[0].upper() +
        "/S:" + ("C" if scope_changed else "U") +
        "/C:" + c[0].upper() +
        "/I:" + i[0].upper() +
        "/A:" + a[0].upper()
    )

    return {"cvss_score": base_score, "cvss_vector": vector}