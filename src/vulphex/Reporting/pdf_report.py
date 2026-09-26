from __future__ import annotations

from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)

from .report import AssessmentReport


def _safe(value: Any) -> str:
    if value is None:
        return "Not available"

    if isinstance(value, (dict, list)):
        return str(value)

    return str(value)


def _styles():
    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="VulphexTitle",
            parent=styles["Title"],
            fontSize=26,
            leading=30,
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VulphexSubtitle",
            parent=styles["Normal"],
            fontSize=14,
            leading=18,
            alignment=TA_CENTER,
            spaceAfter=20,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VulphexHeading",
            parent=styles["Heading2"],
            fontSize=16,
            leading=20,
            spaceBefore=12,
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VulphexSmall",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VulphexBody",
            parent=styles["BodyText"],
            fontSize=9.5,
            leading=14,
            spaceAfter=6,
        )
    )

    return styles


def _metadata_table(report: AssessmentReport, styles):
    data = [
        ["Target", _safe(report.target)],
        ["Generated", _safe(report.generated_at)],
        ["Tool", _safe(report.tool)],
        ["Tool Version", _safe(report.tool_version)],
        ["Assessment Results", _safe(report.result_count)],
        ["Potential Findings", _safe(report.summary.get("potential_findings", 0))],
    ]

    table = Table(data, colWidths=[45 * mm, 125 * mm])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E5E7EB")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#111827")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    return table


def _summary_table(report: AssessmentReport):
    summary = report.summary

    rows = [
        ["Metric", "Value"],
        ["Assessment Results", str(report.result_count)],
        ["Potential Findings", str(summary.get("potential_findings", 0))],
    ]

    findings_by_severity = summary.get("findings_by_severity", {})

    for severity in ("High", "Medium", "Low", "Informational"):
        rows.append(
            [
                severity,
                str(findings_by_severity.get(severity, 0)),
            ]
        )

    table = Table(rows, colWidths=[90 * mm, 80 * mm])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    return table


def _finding_block(finding: dict[str, Any], styles):
    finding_id = _safe(finding.get("finding_id"))
    title = _safe(finding.get("title"))
    severity = _safe(finding.get("severity"))
    status = _safe(finding.get("status"))
    method = _safe(finding.get("method"))
    endpoint = _safe(
        finding.get("endpoint_path")
        or finding.get("target")
    )

    description = _safe(finding.get("description"))
    recommendation = _safe(finding.get("recommendation"))
    evidence = finding.get("evidence", {})

    story = [
        Paragraph(
            f"<b>{finding_id}</b> — {title}",
            styles["Heading3"],
        ),
    ]

    overview = Table(
        [
            ["Severity", severity],
            ["Status", status],
            ["Endpoint", f"{method} {endpoint}"],
        ],
        colWidths=[35 * mm, 135 * mm],
    )

    overview.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F3F4F6")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )

    story.append(overview)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Description</b>", styles["VulphexBody"]))
    story.append(Paragraph(description, styles["VulphexBody"]))

    story.append(
        Paragraph(
            "<b>Recommended Action</b>",
            styles["VulphexBody"],
        )
    )
    story.append(
        Paragraph(
            recommendation,
            styles["VulphexBody"],
        )
    )

    story.append(
        Paragraph(
            "<b>Technical Evidence</b>",
            styles["VulphexBody"],
        )
    )

    evidence_text = _safe(evidence)
    story.append(
        Paragraph(
            evidence_text.replace("\n", "<br/>"),
            styles["VulphexSmall"],
        )
    )

    return KeepTogether(story)


def _footer(canvas, doc):
    canvas.saveState()

    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#6B7280"))

    canvas.drawString(
        18 * mm,
        10 * mm,
        "Generated by VULPHEX",
    )

    canvas.drawRightString(
        192 * mm,
        10 * mm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


def render_pdf_report(
    report: AssessmentReport,
    path: str | Path,
) -> Path:
    """Generate a PDF assessment report from an AssessmentReport."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    styles = _styles()

    document = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="VULPHEX API Security Assessment",
        author="VULPHEX",
    )

    story = []

    # Cover
    story.append(Spacer(1, 45 * mm))
    story.append(Paragraph("VULPHEX", styles["VulphexTitle"]))
    story.append(
        Paragraph(
            "API Security Assessment Report",
            styles["VulphexSubtitle"],
        )
    )

    story.append(_metadata_table(report, styles))
    story.append(PageBreak())

    # Executive Summary
    story.append(
        Paragraph(
            "Executive Summary",
            styles["VulphexHeading"],
        )
    )

    executive_summary = report.summary.get(
        "executive_summary",
        "Automated API security assessment generated by VULPHEX.",
    )

    story.append(
        Paragraph(
            _safe(executive_summary),
            styles["VulphexBody"],
        )
    )

    story.append(
        Paragraph(
            "Assessment Summary",
            styles["VulphexHeading"],
        )
    )

    story.append(_summary_table(report))
    story.append(PageBreak())

    # Findings
    story.append(
        Paragraph(
            "Detailed Findings",
            styles["VulphexHeading"],
        )
    )

    findings = report.findings

    if not findings:
        story.append(
            Paragraph(
                "No findings were generated by the assessment.",
                styles["VulphexBody"],
            )
        )
    else:
        for index, finding in enumerate(findings):
            story.append(_finding_block(finding, styles))

            if index < len(findings) - 1:
                story.append(Spacer(1, 10))

    story.append(PageBreak())

    # Methodology
    story.append(
        Paragraph(
            "Methodology",
            styles["VulphexHeading"],
        )
    )

    story.append(
        Paragraph(
            "VULPHEX performs bounded API security assessments using "
            "the configured discovery and security-test modules. "
            "Assessment results are evidence-based observations and "
            "potential findings require appropriate validation.",
            styles["VulphexBody"],
        )
    )

    # Limitations
    story.append(
        Paragraph(
            "Limitations",
            styles["VulphexHeading"],
        )
    )

    story.append(
        Paragraph(
            "Results are limited to the endpoints, authentication "
            "contexts, request parameters, and bounded test cases "
            "available during the assessment. A result indicating "
            "that a condition was not observed does not prove that "
            "the condition cannot exist elsewhere.",
            styles["VulphexBody"],
        )
    )

    document.build(
        story,
        onFirstPage=_footer,
        onLaterPages=_footer,
    )

    return output_path


def write_pdf_report(
    report: AssessmentReport,
    path: str | Path,
) -> Path:
    """Write a PDF assessment report to disk."""

    return render_pdf_report(report, path)