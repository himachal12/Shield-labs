"""
utils/pdf_generator_html.py

HTML/Jinja2-based PDF report generator (Day 8-9, v2).

Renders app/templates/report_template.html with full CSS control —
colors, borders, readable typography — and converts it to PDF via
xhtml2pdf. Pure-Python conversion path (no GTK/Chromium binary
needed), which matters for a smooth setup on Windows.

Runs alongside the original ReportLab generator (pdf_generator.py) —
not a replacement yet, so nothing already wired to it breaks.
"""

import logging
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape
from xhtml2pdf import pisa

logger = logging.getLogger("shieldlabs.pdf_generator_html")

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


def _calculate_security_score(findings: list[dict]) -> dict:
    if not findings:
        return {"score": 100, "rating": "Excellent"}
    deduction = sum(SEVERITY_WEIGHTS.get((f.get("severity") or "info").lower(), 0) for f in findings)
    score = max(0, 100 - deduction)
    if score >= 90:
        rating = "Excellent"
    elif score >= 75:
        rating = "Good"
    elif score >= 50:
        rating = "Needs Attention"
    elif score >= 25:
        rating = "Poor"
    else:
        rating = "Critical Risk"
    return {"score": score, "rating": rating}


def generate_pdf_report_html(scan: dict, findings: list[dict], chains: list[dict] | None = None) -> str:
    """
    Generates a styled PDF security report via Jinja2 HTML + xhtml2pdf
    and saves it to REPORTS_DIR.

    Args:
        scan: dict with target, scan_id, scan_type, etc.
        findings: list of finding dicts (cvss, fixes, reviews already included)
        chains: optional list of attack chain dicts

    Returns:
        The absolute file path of the generated PDF.
    """
    chains = chains or []
    os.makedirs(REPORTS_DIR, exist_ok=True)

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    total = len(findings) or 1
    percentages = {sev: round(counts.get(sev, 0) / total * 100, 1) for sev in SEVERITY_ORDER}

    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index((f.get("severity") or "info").lower())
        if (f.get("severity") or "info").lower() in SEVERITY_ORDER else 99
    )
    critical_and_high = [f for f in sorted_findings if (f.get("severity") or "").lower() in ("critical", "high")]

    score_info = _calculate_security_score(findings)
    score = score_info["score"]
    if score >= 75:
        score_color = "#16A34A"
    elif score >= 50:
        score_color = "#CA8A04"
    else:
        score_color = "#DC2626"

    sev_colors = {
        "critical": "#DC2626",
        "high": "#EA580C",
        "medium": "#CA8A04",
        "low": "#2563EB",
        "info": "#6B7280",
    }

    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report_template.html")

    html = template.render(
        scan=scan,
        findings=sorted_findings,
        critical_and_high=critical_and_high,
        chains=chains,
        counts=counts,
        percentages=percentages,
        score=score_info["score"],
        rating=score_info["rating"],
        score_color=score_color,
        sev_colors=sev_colors,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )

    filename = "report_" + scan.get("scan_id", "unknown") + ".pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "wb") as pdf_file:
        result = pisa.CreatePDF(src=html, dest=pdf_file)

    if result.err:
        logger.error("xhtml2pdf reported %d error(s) generating %s", result.err, filepath)
        raise RuntimeError("PDF generation failed with " + str(result.err) + " error(s) — check logs.")

    logger.info("Generated HTML-based PDF report: %s", filepath)
    return filepath