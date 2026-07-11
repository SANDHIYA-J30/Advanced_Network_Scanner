from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def generate_host_pdf(host, ports, vulnerabilities, security_score):

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    # Title
    elements.append(
        Paragraph("<b>Advanced Network Scanner Report</b>", styles["Title"])
    )

    elements.append(Spacer(1, 20))

    # Host Information
    elements.append(
        Paragraph("<b>Host Information</b>", styles["Heading2"])
    )

    elements.append(
        Paragraph(f"IP Address : {host.ip_address}", styles["Normal"])
    )

    elements.append(
        Paragraph(f"Hostname : {host.hostname}", styles["Normal"])
    )

    elements.append(
        Paragraph(f"Operating System : {host.operating_system}", styles["Normal"])
    )

    elements.append(
        Paragraph(f"Status : {host.status}", styles["Normal"])
    )

    elements.append(
        Paragraph(f"Security Score : {security_score}/100", styles["Normal"])
    )

    elements.append(Spacer(1, 20))

    # Open Ports
    elements.append(
        Paragraph("<b>Open Ports</b>", styles["Heading2"])
    )

    port_data = [["Port", "Protocol", "Service", "State"]]

    for port in ports:
        port_data.append([
            port.port_number,
            port.protocol,
            port.service,
            port.state
        ])

    port_table = Table(port_data)

    port_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
    ]))

    elements.append(port_table)

    elements.append(Spacer(1, 20))

    # Vulnerabilities
    elements.append(
        Paragraph("<b>Detected Vulnerabilities</b>", styles["Heading2"])
    )

    vuln_data = [["Name", "Severity", "CVE"]]

    if vulnerabilities:
        for vuln in vulnerabilities:
            vuln_data.append([
                vuln.name,
                vuln.severity,
                vuln.cve_id or "-"
            ])
    else:
        vuln_data.append([
            "No Vulnerabilities",
            "-",
            "-"
        ])

    vuln_table = Table(vuln_data)

    vuln_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.red),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
    ]))

    elements.append(vuln_table)

    doc.build(elements)

    pdf = buffer.getvalue()

    buffer.close()

    return pdf