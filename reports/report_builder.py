"""Phase 11 — Seven-section daily PDF security report (ReportLab).

Sections: Executive Summary, Traffic Overview, Risk Analysis,
Suspicious Devices, Blocked Requests, Historical Trend, Hourly
Breakdown, and an auto-generated Conclusion.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from reports.report_data import build_report_context

NAVY = colors.HexColor("#0D1B2A")
RED = colors.HexColor("#3d1515")
GREEN = colors.HexColor("#14351d")


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], spaceAfter=8, textColor=NAVY))
    styles.add(ParagraphStyle(name="Small", parent=styles["Normal"], fontSize=9, leading=12))
    return styles


def _table(data: list[list[str]], *, header_bg=NAVY, col_widths=None) -> Table:
    table = Table(data, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), header_bg),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#eeeeee")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def build_daily_report_pdf(context: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = _styles()
    story: list[Any] = []

    report_date = context["report_date"]
    summary = context["executive_summary"]
    traffic = context["traffic_overview"]
    risk = context["risk_analysis"]
    counts = risk.get("counts", {})

    # --- Title -------------------------------------------------------
    story.append(Paragraph("SecureGate AI — Daily Security Report", styles["Title"]))
    story.append(Paragraph(f"Report Date: {report_date}", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    # --- 1. Executive Summary ----------------------------------------
    story.append(Paragraph("1. Executive Summary", styles["Section"]))
    for line in [
        f"Total devices monitored: <b>{summary.get('total_devices', 0)}</b>",
        f"Total events captured: <b>{summary.get('total_events', 0)}</b>",
        f"High-risk events: <b>{summary.get('high_risk_count', 0)}</b>",
        f"Blocked devices: <b>{summary.get('blocked_devices', 0)}</b>",
        f"Average risk score: <b>{float(summary.get('avg_risk_score', 0) or 0):.2f}</b> / 100",
    ]:
        story.append(Paragraph(line, styles["Normal"]))
    story.append(Spacer(1, 0.18 * inch))

    # --- 2. Traffic Overview ------------------------------------------
    story.append(Paragraph("2. Traffic Overview", styles["Section"]))
    story.append(_table([
        ["Protocol", "Event Count"],
        ["DNS", str(traffic.get("dns_events", 0))],
        ["TCP", str(traffic.get("tcp_events", 0))],
        ["ICMP", str(traffic.get("icmp_events", 0))],
        ["Total", str(traffic.get("total_events", 0))],
    ], col_widths=[2.5 * inch, 2 * inch]))
    story.append(Spacer(1, 0.18 * inch))

    # --- 3. Risk Analysis ----------------------------------------------
    story.append(Paragraph("3. Risk Analysis", styles["Section"]))
    total_risk = int(counts.get("total") or 0) or 1
    story.append(_table([
        ["Category", "Count", "% of Total"],
        ["Low", str(counts.get("low_count", 0)), f"{int(counts.get('low_count') or 0) / total_risk:.0%}"],
        ["Medium", str(counts.get("medium_count", 0)), f"{int(counts.get('medium_count') or 0) / total_risk:.0%}"],
        ["High", str(counts.get("high_count", 0)), f"{int(counts.get('high_count') or 0) / total_risk:.0%}"],
    ], header_bg=RED, col_widths=[2 * inch, 1.5 * inch, 1.5 * inch]))
    story.append(Paragraph(
        f"Average risk score: {float(counts.get('avg_score', 0) or 0):.2f} · "
        f"Maximum risk score: {float(counts.get('max_score', 0) or 0):.2f}",
        styles["Small"],
    ))
    story.append(Spacer(1, 0.18 * inch))

    # --- 4. Suspicious Devices ------------------------------------------
    story.append(Paragraph("4. Top Suspicious Devices", styles["Section"]))
    top_devices = risk.get("top_suspicious_devices", [])
    if top_devices:
        rows = [["Source IP", "Avg Risk Score", "Events"]]
        for device in top_devices[:10]:
            rows.append([
                str(device.get("source_ip", "")),
                f"{float(device.get('avg_risk_score') or 0):.1f}",
                str(device.get("event_count", 0)),
            ])
        story.append(_table(rows, col_widths=[2.5 * inch, 1.75 * inch, 1.25 * inch]))
    else:
        story.append(Paragraph("No risk assessments recorded for this date.", styles["Normal"]))
    story.append(Spacer(1, 0.18 * inch))

    # --- 5. Blocked Requests ---------------------------------------------
    story.append(Paragraph("5. Blocked Requests", styles["Section"]))
    blocked = context.get("blocked_requests", [])
    if blocked:
        rows = [["IP Address", "Device Type", "Reason", "Decided At"]]
        for item in blocked[:15]:
            rows.append([
                str(item.get("ip_address", "")),
                str(item.get("device_type") or "unknown"),
                (item.get("reason") or "")[:40],
                str(item.get("decided_at", ""))[:19],
            ])
        story.append(_table(rows, header_bg=RED, col_widths=[1.5 * inch, 1.2 * inch, 2.3 * inch, 1.5 * inch]))
    else:
        story.append(Paragraph("No block decisions were recorded for this date.", styles["Normal"]))
    story.append(Spacer(1, 0.18 * inch))

    # --- 6. Historical Trend ----------------------------------------------
    story.append(Paragraph("6. Historical Trend (Last 7 Days)", styles["Section"]))
    trend = context.get("historical_trend", [])
    if trend:
        rows = [["Date", "Events", "High", "Medium", "Low", "Blocked", "Devices"]]
        for row in trend:
            rows.append([
                str(row.get("summary_date", "")),
                str(row.get("total_events", 0)),
                str(row.get("high_risk_count", 0)),
                str(row.get("medium_risk_count", 0)),
                str(row.get("low_risk_count", 0)),
                str(row.get("blocked_requests", 0)),
                str(row.get("unique_devices", row.get("total_devices", 0))),
            ])
        story.append(_table(rows, header_bg=GREEN))
    else:
        story.append(Paragraph("No historical summary data available yet.", styles["Normal"]))
    story.append(Spacer(1, 0.18 * inch))

    # --- 7. Hourly Breakdown ----------------------------------------------
    story.append(Paragraph("7. Hourly Breakdown", styles["Section"]))
    hourly = context.get("hourly_breakdown", [])
    if hourly:
        rows = [["Hour", "DNS", "TCP", "ICMP", "Total"]]
        for row in hourly:
            rows.append([
                f"{int(row.get('hour', 0)):02d}:00",
                str(row.get("dns_count", 0)),
                str(row.get("tcp_count", 0)),
                str(row.get("icmp_count", 0)),
                str(row.get("total", 0)),
            ])
        story.append(_table(rows))
    else:
        story.append(Paragraph("No hourly activity recorded for this date.", styles["Normal"]))
    story.append(Spacer(1, 0.2 * inch))

    # --- Conclusion --------------------------------------------------------
    story.append(Paragraph("Conclusion", styles["Section"]))
    story.append(Paragraph(context.get("conclusion", ""), styles["Normal"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.read()


def generate_report(report_date: str | None = None, output_dir: str = "reports/output") -> tuple[bytes, str]:
    """Build the full 7-section PDF report and persist it to disk."""
    context = build_report_context(report_date)
    target_date = context["report_date"]

    pdf_bytes = build_daily_report_pdf(context)
    filename = f"securegate_report_{target_date}.pdf"

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    (out_path / filename).write_bytes(pdf_bytes)

    return pdf_bytes, filename


def list_generated_reports(output_dir: str = "reports/output") -> list[dict[str, Any]]:
    """List previously generated PDF reports for GET /report/list."""
    out_path = Path(output_dir)
    if not out_path.exists():
        return []

    reports = []
    for pdf_file in sorted(out_path.glob("*.pdf"), reverse=True):
        stat = pdf_file.stat()
        reports.append({
            "filename": pdf_file.name,
            "size_kb": round(stat.st_size / 1024, 1),
            "created_at": stat.st_mtime,
        })
    return reports
