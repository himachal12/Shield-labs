"""
utils/pdf_generator.py

Day 8-9 — PDF Report Generation.

Builds a professional multi-page PDF security report from a scan's
findings (and any attack chains), using ReportLab's Platypus layout
engine. Saved to a local reports/ folder — matches the project's
existing local-SQLite, no-cloud-storage architecture.
"""

import logging
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.lib.enums import TA_CENTER

logger = logging.getLogger("shieldlabs.pdf_generator")

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")

SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#CA8A04"),
    "low": colors.HexColor("#2563EB"),
    "info": colors.HexColor("#6B7280"),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


def _add_page_number(canvas, doc):
    """Footer callback: draws 'Page X' on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    page_text = "Page %d" % canvas.getPageNumber()
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, page_text)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.75 * inch, 0.5 * inch, "ShieldLabs Security Report")
    canvas.restoreState()


def _calculate_security_score(findings: list[dict]) -> dict:
    """
    Deterministic 0-100 security score (100 = clean). A weighted
    deduction over severity counts — no LLM call, fast and
    reproducible run to run.
    """
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


def _severity_bar_chart(counts: dict, total: int) -> Table:
    """
    Builds a horizontal bar per severity level using colored table
    cells as bars — avoids reportlab.graphics complexity while still
    giving a real visual, not just numbers.
    """
    rows = []
    max_bar_width = 4.0  # inches, at 100%

    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        pct = (count / total * 100) if total else 0
        bar_width = max(0.05, max_bar_width * (pct / 100))

        label_cell = Paragraph(
            "<b>" + sev.upper() + "</b>",
            ParagraphStyle("SevLabel", fontSize=9, textColor=SEVERITY_COLORS.get(sev, colors.grey))
        )
        count_cell = Paragraph(
            str(count) + " (" + str(round(pct, 1)) + "%)",
            ParagraphStyle("SevCount", fontSize=9)
        )

        bar_table = Table([[""]], colWidths=[bar_width * inch], rowHeights=[0.18 * inch])
        bar_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS.get(sev, colors.grey)),
        ]))

        rows.append([label_cell, bar_table, count_cell])

    dashboard = Table(rows, colWidths=[1.0 * inch, 4.2 * inch, 1.3 * inch])
    dashboard.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return dashboard


def _score_badge(score_info: dict) -> Table:
    """Large colored score badge for the cover page."""
    score = score_info["score"]
    rating = score_info["rating"]

    if score >= 75:
        badge_color = colors.HexColor("#16A34A")
    elif score >= 50:
        badge_color = colors.HexColor("#CA8A04")
    else:
        badge_color = colors.HexColor("#DC2626")

    score_style = ParagraphStyle("ScoreNum", fontSize=36, alignment=TA_CENTER, textColor=colors.white, fontName="Helvetica-Bold")
    rating_style = ParagraphStyle("ScoreRating", fontSize=12, alignment=TA_CENTER, textColor=colors.white)

    cell_content = [
        Paragraph(str(score), score_style),
        Paragraph(rating, rating_style),
    ]

    badge = Table([[cell_content]], colWidths=[2.2 * inch], rowHeights=[1.3 * inch])
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), badge_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return badge


def generate_pdf_report(scan: dict, findings: list[dict], chains: list[dict] | None = None) -> str:
    """
    Generates a PDF security report and saves it to REPORTS_DIR.

    Args:
        scan: dict with target, scan_id, scan_type, total_findings, etc.
        findings: list of finding dicts (already includes cvss, fixes, etc.)
        chains: optional list of attack chain dicts

    Returns:
        The absolute file path of the generated PDF.
    """
    os.makedirs(REPORTS_DIR, exist_ok=True)
    chains = chains or []

    filename = "report_" + scan.get("scan_id", "unknown") + ".pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        filepath, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=24, spaceAfter=6)
    subtitle_style = ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=12, textColor=colors.grey, alignment=TA_CENTER)
    h2_style = ParagraphStyle("H2", parent=styles["Heading2"], spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14)
    code_style = ParagraphStyle("Code", parent=styles["Code"], fontSize=8, leading=11, backColor=colors.HexColor("#F3F4F6"))

    story = []

    # --- Cover / Executive Summary ---
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    score_info = _calculate_security_score(findings)

    story.append(Spacer(1, 0.6 * inch))
    story.append(Paragraph("ShieldLabs Security Report", title_style))
    story.append(Paragraph(scan.get("target", "Unknown target"), subtitle_style))
    story.append(Spacer(1, 0.35 * inch))

    info_table = Table(
        [["Scan Type", scan.get("scan_type", "N/A").upper()],
         ["Scan ID", scan.get("scan_id", "N/A")],
         ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")],
         ["Total Findings", str(len(findings))],
         ["Attack Chains", str(len(chains))]],
        colWidths=[1.6 * inch, 2.6 * inch],
    )
    info_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    header_row = Table(
        [[_score_badge(score_info), info_table]],
        colWidths=[2.4 * inch, 4.2 * inch],
    )
    header_row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(header_row)
    story.append(Spacer(1, 0.4 * inch))

    story.append(Paragraph("Severity Breakdown", h2_style))
    story.append(_severity_bar_chart(counts, len(findings)))
    story.append(PageBreak())

    # --- Critical Findings Callout ---
    critical_and_high = [f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")]
    if critical_and_high:
        story.append(Paragraph("Critical &amp; High-Risk Findings — Immediate Attention Required", h2_style))
        for f in critical_and_high:
            sev = (f.get("severity") or "info").lower()
            line = "<b>[" + sev.upper() + "]</b> " + f.get("vuln_type", "Unknown") + " — " + (f.get("file") or f.get("url") or "N/A")
            story.append(Paragraph(line, ParagraphStyle("CriticalLine", parent=body_style, textColor=SEVERITY_COLORS.get(sev, colors.black), spaceAfter=6)))
        story.append(PageBreak())

    # --- Findings Summary Table ---
    story.append(Paragraph("Findings Summary", h2_style))
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index((f.get("severity") or "info").lower()) if (f.get("severity") or "info").lower() in SEVERITY_ORDER else 99
    )

    table_data = [["Severity", "Vulnerability", "Location", "CVSS"]]
    row_colors = []
    for f in sorted_findings:
        sev = (f.get("severity") or "info").lower()
        location = f.get("file") or f.get("url") or "N/A"
        if f.get("line"):
            location += ":" + str(f["line"])
        table_data.append([
            sev.upper(),
            f.get("vuln_type", "Unknown")[:40],
            location[:35],
            str(f.get("cvss_score", "N/A")),
        ])
        row_colors.append(SEVERITY_COLORS.get(sev, colors.grey))

    findings_table = Table(table_data, colWidths=[0.9 * inch, 2.3 * inch, 2.3 * inch, 0.7 * inch], repeatRows=1)
    table_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, color in enumerate(row_colors):
        table_style_cmds.append(("TEXTCOLOR", (0, i + 1), (0, i + 1), color))
        table_style_cmds.append(("FONTNAME", (0, i + 1), (0, i + 1), "Helvetica-Bold"))
    findings_table.setStyle(TableStyle(table_style_cmds))
    story.append(findings_table)
    story.append(PageBreak())

    # --- Attack Chains ---
    if chains:
        story.append(Paragraph("Attack Chains", h2_style))
        for chain in chains:
            sev = (chain.get("severity") or "medium").lower()
            chain_title = "Chain (" + sev.upper() + ") — Time to Exploit: " + (chain.get("time_to_exploit") or "Unknown")
            story.append(Paragraph(chain_title, ParagraphStyle("ChainTitle", parent=body_style, textColor=SEVERITY_COLORS.get(sev, colors.black), fontName="Helvetica-Bold", spaceBefore=10)))
            story.append(Paragraph(chain.get("description", ""), body_style))
            if chain.get("impact"):
                story.append(Paragraph("<b>Impact:</b> " + chain["impact"], body_style))
            story.append(Spacer(1, 0.15 * inch))
        story.append(PageBreak())

    # --- Detailed Findings ---
    story.append(Paragraph("Detailed Findings", h2_style))
    for i, f in enumerate(sorted_findings, 1):
        sev = (f.get("severity") or "info").lower()
        header = str(i) + ". " + f.get("vuln_type", "Unknown")
        story.append(Paragraph(header, ParagraphStyle("FindingHeader", parent=styles["Heading3"], textColor=SEVERITY_COLORS.get(sev, colors.black), spaceBefore=14)))

        meta_bits = []
        if f.get("file"):
            meta_bits.append("File: " + f["file"] + (":" + str(f["line"]) if f.get("line") else ""))
        if f.get("url"):
            meta_bits.append("URL: " + f["url"])
        if f.get("cvss_score"):
            meta_bits.append("CVSS: " + str(f["cvss_score"]) + " (" + str(f.get("cvss_vector", "")) + ")")
        if meta_bits:
            story.append(Paragraph(" | ".join(meta_bits), ParagraphStyle("Meta", parent=body_style, textColor=colors.grey, fontSize=8)))

        if f.get("code"):
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph("Vulnerable code:", body_style))
            story.append(Paragraph(_escape(f["code"]), code_style))

        if f.get("fix"):
            story.append(Spacer(1, 0.05 * inch))
            story.append(Paragraph("Suggested fix:", body_style))
            story.append(Paragraph(_escape(f["fix"]), code_style))

        if f.get("agent_review_notes"):
            story.append(Paragraph("<b>AI Review:</b> " + f["agent_review_notes"], body_style))

        if f.get("business_impact"):
            story.append(Paragraph("<b>Business Impact:</b> " + f["business_impact"], body_style))

        story.append(Spacer(1, 0.1 * inch))

    doc.build(story, onFirstPage=_add_page_number, onLaterPages=_add_page_number)
    logger.info("Generated PDF report: %s", filepath)
    return filepath


def _escape(text: str) -> str:
    """Escapes text for safe inclusion in ReportLab Paragraph markup."""
    if not text:
        return ""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )