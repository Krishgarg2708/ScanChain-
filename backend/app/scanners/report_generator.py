"""
Report Generator
Produces HTML, Markdown, CSV, and PDF reports from a completed scan's
findings + risk summary. PDF is rendered from the HTML report so there's
a single source of truth for layout.
"""
import csv
import io
import html
import datetime

SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#3b82f6", "info": "#64748b"}


def generate_markdown(project_name: str, scan: dict) -> str:
    risk = scan["summary"]["risk"]
    lines = [
        f"# Security Report — {project_name}",
        f"_Generated {datetime.datetime.utcnow().isoformat()}Z_",
        "",
        f"**Overall Risk Score:** {scan['risk_score']}/100",
        "",
        "## Severity Breakdown",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev, count in risk["severity_counts"].items():
        lines.append(f"| {sev} | {count} |")
    lines += ["", "## Findings", ""]
    for f in scan["findings"]:
        lines.append(f"### [{f['severity'].upper()}] {f['title']}")
        lines.append(f"- **Scanner:** {f['scanner']}")
        lines.append(f"- **Location:** `{f['location']}`")
        if f.get("cve_id"):
            lines.append(f"- **CVE:** {f['cve_id']}")
        if f.get("cvss") is not None:
            lines.append(f"- **CVSS:** {f['cvss']}")
        lines.append(f"- **Description:** {f['description']}")
        if f.get("remediation"):
            lines.append(f"- **Remediation:** {f['remediation']}")
        lines.append("")
    return "\n".join(lines)


def generate_html(project_name: str, scan: dict) -> str:
    risk = scan["summary"]["risk"]
    rows = "".join(
        f"""<tr style="border-top:1px solid #2d3348">
            <td style="padding:8px"><span style="background:{SEV_COLOR.get(f['severity'],'#64748b')}22;
                color:{SEV_COLOR.get(f['severity'],'#64748b')};padding:2px 8px;border-radius:12px;
                font-size:12px">{html.escape(f['severity'])}</span></td>
            <td style="padding:8px">{html.escape(f['title'])}<br>
                <span style="color:#94a3b8;font-size:12px">{html.escape(f['description'])}</span></td>
            <td style="padding:8px;font-family:monospace;font-size:12px">{html.escape(str(f['location'] or ''))}</td>
            <td style="padding:8px">{f['cvss'] if f['cvss'] is not None else '—'}</td>
        </tr>"""
        for f in scan["findings"]
    )
    sev_rows = "".join(
        f"<tr><td style='padding:4px 12px'>{sev}</td><td style='padding:4px 12px'>{count}</td></tr>"
        for sev, count in risk["severity_counts"].items()
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Report — {html.escape(project_name)}</title></head>
<body style="background:#0a0e17;color:#e2e8f0;font-family:system-ui,sans-serif;padding:32px">
  <h1 style="margin-bottom:4px">Security Report — {html.escape(project_name)}</h1>
  <p style="color:#94a3b8">Generated {datetime.datetime.utcnow().isoformat()}Z</p>
  <h2 style="color:{'#ef4444' if scan['risk_score']>60 else '#f97316' if scan['risk_score']>30 else '#22c55e'}">
    Overall Risk Score: {scan['risk_score']}/100
  </h2>
  <table style="margin:16px 0">{sev_rows}</table>
  <h2>Findings ({len(scan['findings'])})</h2>
  <table style="width:100%;border-collapse:collapse;background:#141a29;border-radius:8px;overflow:hidden">
    <thead><tr style="background:#1c2333;text-align:left;font-size:12px;color:#94a3b8;text-transform:uppercase">
      <th style="padding:8px">Severity</th><th style="padding:8px">Finding</th>
      <th style="padding:8px">Location</th><th style="padding:8px">CVSS</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body></html>"""


def generate_csv(scan: dict) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["scanner", "severity", "title", "description", "location", "cve_id", "cvss", "remediation"])
    for f in scan["findings"]:
        writer.writerow([f["scanner"], f["severity"], f["title"], f["description"],
                          f["location"], f.get("cve_id") or "", f.get("cvss") or "", f.get("remediation") or ""])
    return output.getvalue()


def generate_pdf(project_name: str, scan: dict) -> bytes:
    """Renders the HTML report to PDF. Uses reportlab as a pure-Python fallback
    (no headless-browser dependency needed) if xhtml2pdf/weasyprint aren't present."""
    try:
        from xhtml2pdf import pisa
        html_str = generate_html(project_name, scan)
        buf = io.BytesIO()
        pisa.CreatePDF(io.StringIO(html_str), dest=buf)
        return buf.getvalue()
    except ImportError:
        return _generate_pdf_reportlab(project_name, scan)


def _generate_pdf_reportlab(project_name: str, scan: dict) -> bytes:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleX", parent=styles["Title"], textColor=colors.HexColor("#1e1b4b"))
    story = [
        Paragraph(f"Security Report — {project_name}", title_style),
        Paragraph(f"Generated {datetime.datetime.utcnow().isoformat()}Z", styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"Overall Risk Score: {scan['risk_score']}/100", styles["Heading2"]),
        Spacer(1, 12),
    ]

    risk = scan["summary"]["risk"]
    sev_table_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in risk["severity_counts"].items()]
    sev_table = Table(sev_table_data, colWidths=[150, 80])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#312e81")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"Findings ({len(scan['findings'])})", styles["Heading2"]))
    story.append(Spacer(1, 8))

    for f in scan["findings"]:
        story.append(Paragraph(f"<b>[{f['severity'].upper()}] {html.escape(f['title'])}</b>", styles["Normal"]))
        story.append(Paragraph(
            f"Scanner: {f['scanner']} | Location: {html.escape(str(f['location'] or ''))} | "
            f"CVSS: {f['cvss'] if f['cvss'] is not None else '—'}", styles["Normal"]))
        story.append(Paragraph(html.escape(f["description"]), styles["Normal"]))
        if f.get("remediation"):
            story.append(Paragraph(f"<i>Remediation: {html.escape(f['remediation'])}</i>", styles["Normal"]))
        story.append(Spacer(1, 10))

    doc.build(story)
    return buf.getvalue()
