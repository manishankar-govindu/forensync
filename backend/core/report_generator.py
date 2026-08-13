# report_generator.py - Forensic Report Generator for ForenSync
# Generates HTML and PDF case reports from the SQLite database.
# Uses reportlab for PDF generation (falls back gracefully if not installed).
# Compatible with Python 3.9 (Rule 1).

import os
import json
from datetime import datetime


# =============================================================================
# HTML REPORT GENERATOR
# =============================================================================

def generate_html_report(case, evidence_list, audit_logs, output_dir):
    """
    Generate a self-contained HTML forensic case report.

    Args:
        case: Case model instance (or dict with same keys from to_dict())
        evidence_list: List of Evidence model instances or dicts
        audit_logs: List of AuditLog model instances or dicts
        output_dir: Directory where the report file will be saved

    Returns:
        str: Absolute path to the generated HTML file.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Normalize to dicts if model instances are passed
    if hasattr(case, 'to_dict'):
        case_data = case.to_dict()
    else:
        case_data = case

    evidence_dicts = []
    for e in evidence_list:
        if hasattr(e, 'to_dict'):
            evidence_dicts.append(e.to_dict())
        else:
            evidence_dicts.append(e)

    log_dicts = []
    for log in audit_logs:
        if hasattr(log, 'to_dict'):
            log_dicts.append(log.to_dict())
        else:
            log_dicts.append(log)

    # Build evidence rows HTML
    evidence_rows = ''
    for ev in evidence_dicts:
        analysis_badge = (
            '<span style="color:#27ae60;font-weight:bold;">&#10003; Analyzed</span>'
            if ev.get('analysis_status') == 'completed'
            else '<span style="color:#e67e22;">Pending</span>'
        )
        evidence_rows += '''
        <tr>
            <td>{original_filename}</td>
            <td>{file_size_human}</td>
            <td><code style="font-size:11px;">{md5_hash}</code></td>
            <td><code style="font-size:11px;">{sha256_hash}</code></td>
            <td>{uploaded_at}</td>
            <td>{analysis_badge}</td>
        </tr>'''.format(
            original_filename=ev.get('original_filename', 'N/A'),
            file_size_human=ev.get('file_size_human', 'N/A'),
            md5_hash=ev.get('md5_hash', 'N/A'),
            sha256_hash=ev.get('sha256_hash', 'N/A'),
            uploaded_at=ev.get('uploaded_at', 'N/A'),
            analysis_badge=analysis_badge
        )

    # Build audit log rows HTML
    audit_rows = ''
    for log in log_dicts[-50:]:  # Show last 50 entries
        audit_rows += '''
        <tr>
            <td>{timestamp}</td>
            <td><strong>{action}</strong></td>
            <td>{resource_type}</td>
            <td>{resource_id}</td>
        </tr>'''.format(
            timestamp=log.get('timestamp', ''),
            action=log.get('action', ''),
            resource_type=log.get('resource_type', ''),
            resource_id=log.get('resource_id', '')
        )

    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForenSync Forensic Case Report — {case_number}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 13px;
            color: #1a1a2e;
            background: #f4f6f9;
            padding: 20px;
        }}
        .report-wrapper {{
            max-width: 1100px;
            margin: 0 auto;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
            overflow: hidden;
        }}
        .report-header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: #fff;
            padding: 32px 40px;
        }}
        .report-header h1 {{
            font-size: 26px;
            letter-spacing: 1px;
            margin-bottom: 6px;
        }}
        .report-header .subtitle {{
            color: #a0b4d6;
            font-size: 13px;
        }}
        .report-header .badge {{
            display: inline-block;
            background: #e94560;
            color: #fff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            letter-spacing: 1px;
            text-transform: uppercase;
            margin-top: 10px;
        }}
        .section {{
            padding: 28px 40px;
            border-bottom: 1px solid #eef0f5;
        }}
        .section:last-child {{ border-bottom: none; }}
        .section h2 {{
            font-size: 16px;
            font-weight: 700;
            color: #0f3460;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid #e94560;
            display: inline-block;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
            gap: 16px;
            margin-top: 12px;
        }}
        .meta-item label {{
            display: block;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: #8a93a2;
            margin-bottom: 4px;
        }}
        .meta-item span {{
            font-weight: 600;
            color: #1a1a2e;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }}
        th {{
            background: #f0f3fa;
            color: #0f3460;
            font-weight: 700;
            padding: 10px 12px;
            text-align: left;
            border-bottom: 2px solid #dee2ea;
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 9px 12px;
            border-bottom: 1px solid #f0f2f7;
            vertical-align: top;
        }}
        tr:hover td {{ background: #f9faff; }}
        code {{ font-family: 'Courier New', monospace; color: #c0392b; }}
        .report-footer {{
            background: #f0f3fa;
            padding: 18px 40px;
            font-size: 11px;
            color: #8a93a2;
            text-align: center;
        }}
        .stat-boxes {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            margin-top: 12px;
        }}
        .stat-box {{
            background: #f0f3fa;
            border-left: 4px solid #0f3460;
            padding: 12px 18px;
            border-radius: 4px;
            min-width: 120px;
        }}
        .stat-box .stat-val {{
            font-size: 24px;
            font-weight: 700;
            color: #0f3460;
        }}
        .stat-box .stat-lbl {{
            font-size: 10px;
            color: #8a93a2;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        @media print {{
            body {{ background: #fff; padding: 0; }}
            .report-wrapper {{ box-shadow: none; border-radius: 0; }}
        }}
    </style>
</head>
<body>
<div class="report-wrapper">

    <!-- HEADER -->
    <div class="report-header">
        <h1>&#128274; ForenSync Forensic Case Report</h1>
        <div class="subtitle">Digital Forensics Investigation Platform</div>
        <div class="badge">Official Report</div>
    </div>

    <!-- CASE DETAILS -->
    <div class="section">
        <h2>Case Information</h2>
        <div class="meta-grid">
            <div class="meta-item">
                <label>Case Number</label>
                <span>{case_number}</span>
            </div>
            <div class="meta-item">
                <label>Case Title</label>
                <span>{case_title}</span>
            </div>
            <div class="meta-item">
                <label>Status</label>
                <span>{case_status}</span>
            </div>
            <div class="meta-item">
                <label>Priority</label>
                <span>{case_priority}</span>
            </div>
            <div class="meta-item">
                <label>Case Type</label>
                <span>{case_type}</span>
            </div>
            <div class="meta-item">
                <label>Created At</label>
                <span>{case_created_at}</span>
            </div>
            <div class="meta-item">
                <label>Description</label>
                <span>{case_description}</span>
            </div>
            <div class="meta-item">
                <label>Report Generated</label>
                <span>{generated_at}</span>
            </div>
        </div>
    </div>

    <!-- STATISTICS -->
    <div class="section">
        <h2>Summary Statistics</h2>
        <div class="stat-boxes">
            <div class="stat-box">
                <div class="stat-val">{evidence_count}</div>
                <div class="stat-lbl">Evidence Items</div>
            </div>
            <div class="stat-box">
                <div class="stat-val">{analyzed_count}</div>
                <div class="stat-lbl">Analyzed</div>
            </div>
            <div class="stat-box">
                <div class="stat-val">{audit_count}</div>
                <div class="stat-lbl">Audit Events</div>
            </div>
        </div>
    </div>

    <!-- EVIDENCE TABLE -->
    <div class="section">
        <h2>Evidence Chain of Custody</h2>
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>MD5 Hash</th>
                    <th>SHA-256 Hash</th>
                    <th>Uploaded At</th>
                    <th>Analysis</th>
                </tr>
            </thead>
            <tbody>
                {evidence_rows}
            </tbody>
        </table>
    </div>

    <!-- AUDIT LOG TABLE -->
    <div class="section">
        <h2>Audit Trail (Last 50 Events)</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Action</th>
                    <th>Resource Type</th>
                    <th>Resource ID</th>
                </tr>
            </thead>
            <tbody>
                {audit_rows}
            </tbody>
        </table>
    </div>

    <!-- FOOTER -->
    <div class="report-footer">
        Generated by <strong>ForenSync</strong> Digital Forensics Platform &nbsp;|&nbsp;
        Report Date: {generated_at} &nbsp;|&nbsp;
        Case: {case_number} &nbsp;|&nbsp;
        <em>This report is generated for authorized forensic investigation purposes only.</em>
    </div>

</div>
</body>
</html>'''.format(
        case_number=case_data.get('case_number', 'N/A'),
        case_title=case_data.get('title', 'N/A'),
        case_status=case_data.get('status', 'N/A').upper(),
        case_priority=case_data.get('priority', 'N/A').upper(),
        case_type=case_data.get('case_type', 'N/A') or 'N/A',
        case_created_at=case_data.get('created_at', 'N/A'),
        case_description=case_data.get('description', '') or 'No description provided.',
        generated_at=generated_at,
        evidence_count=len(evidence_dicts),
        analyzed_count=sum(
            1 for e in evidence_dicts if e.get('analysis_status') == 'completed'
        ),
        audit_count=len(log_dicts),
        evidence_rows=evidence_rows if evidence_rows else '<tr><td colspan="6" style="text-align:center;color:#aaa;">No evidence uploaded yet.</td></tr>',
        audit_rows=audit_rows if audit_rows else '<tr><td colspan="4" style="text-align:center;color:#aaa;">No audit events recorded.</td></tr>'
    )

    report_filename = 'forensync_report_{0}_{1}.html'.format(
        case_data.get('case_number', 'unknown').replace('-', '_'),
        datetime.now().strftime('%Y%m%d_%H%M%S')
    )
    report_path = os.path.join(output_dir, report_filename)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return report_path


# =============================================================================
# PDF REPORT GENERATOR
# =============================================================================

def generate_pdf_report(case, evidence_list, audit_logs, output_dir):
    """
    Generate a PDF forensic case report using reportlab.

    Falls back gracefully if reportlab is not installed — returns None
    with an explanatory message.

    Returns:
        (str, None): Path to PDF file, or (None, error_message) if failed.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
    except ImportError:
        return None, (
            'reportlab is not installed. '
            'Run: pip install reportlab   then retry.'
        )

    os.makedirs(output_dir, exist_ok=True)

    # Normalize data
    if hasattr(case, 'to_dict'):
        case_data = case.to_dict()
    else:
        case_data = case

    evidence_dicts = [
        e.to_dict() if hasattr(e, 'to_dict') else e for e in evidence_list
    ]
    log_dicts = [
        log.to_dict() if hasattr(log, 'to_dict') else log for log in audit_logs
    ]

    report_filename = 'forensync_report_{0}_{1}.pdf'.format(
        case_data.get('case_number', 'unknown').replace('-', '_'),
        datetime.now().strftime('%Y%m%d_%H%M%S')
    )
    report_path = os.path.join(output_dir, report_filename)

    doc = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )

    styles = getSampleStyleSheet()
    dark_blue = colors.HexColor('#0f3460')
    red_accent = colors.HexColor('#e94560')
    light_bg = colors.HexColor('#f0f3fa')

    title_style = ParagraphStyle(
        'Title', parent=styles['Title'],
        fontSize=20, textColor=dark_blue,
        spaceAfter=6
    )
    heading_style = ParagraphStyle(
        'Heading', parent=styles['Heading2'],
        fontSize=13, textColor=dark_blue,
        spaceBefore=14, spaceAfter=6
    )
    normal_style = styles['Normal']
    small_style = ParagraphStyle(
        'Small', parent=styles['Normal'],
        fontSize=8, textColor=colors.grey
    )

    story = []

    # Title
    story.append(Paragraph('ForenSync Forensic Case Report', title_style))
    story.append(Paragraph(
        'Case: {0} | Generated: {1}'.format(
            case_data.get('case_number', 'N/A'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ),
        small_style
    ))
    story.append(HRFlowable(width='100%', thickness=2, color=red_accent))
    story.append(Spacer(1, 0.4 * cm))

    # Case details table
    story.append(Paragraph('Case Information', heading_style))
    case_table_data = [
        ['Field', 'Value'],
        ['Case Number', case_data.get('case_number', 'N/A')],
        ['Title', case_data.get('title', 'N/A')],
        ['Status', str(case_data.get('status', 'N/A')).upper()],
        ['Priority', str(case_data.get('priority', 'N/A')).upper()],
        ['Case Type', str(case_data.get('case_type', 'N/A') or 'N/A')],
        ['Created At', str(case_data.get('created_at', 'N/A'))],
        ['Description', str(case_data.get('description', '') or 'N/A')],
    ]
    case_table = Table(case_table_data, colWidths=[5 * cm, 12 * cm])
    case_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), dark_blue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 1), (0, -1), light_bg),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2ea')),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(case_table)
    story.append(Spacer(1, 0.5 * cm))

    # Evidence table
    story.append(Paragraph(
        'Evidence Chain of Custody ({0} items)'.format(len(evidence_dicts)),
        heading_style
    ))
    ev_header = ['Filename', 'Size', 'MD5 Hash', 'Uploaded At', 'Status']
    ev_rows = [ev_header]
    for ev in evidence_dicts:
        ev_rows.append([
            str(ev.get('original_filename', 'N/A'))[:40],
            str(ev.get('file_size_human', 'N/A')),
            str(ev.get('md5_hash', 'N/A'))[:20] + '...' if ev.get('md5_hash') else 'N/A',
            str(ev.get('uploaded_at', 'N/A'))[:19],
            str(ev.get('analysis_status', 'pending')).upper()
        ])
    if len(ev_rows) == 1:
        ev_rows.append(['No evidence uploaded yet', '', '', '', ''])

    ev_table = Table(ev_rows, colWidths=[5 * cm, 2 * cm, 4 * cm, 4 * cm, 2 * cm])
    ev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), dark_blue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2ea')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 0.5 * cm))

    # Audit log table (last 30)
    story.append(Paragraph(
        'Audit Trail (Last 30 events of {0} total)'.format(len(log_dicts)),
        heading_style
    ))
    audit_header = ['Timestamp', 'Action', 'Resource Type', 'Resource ID']
    audit_rows_data = [audit_header]
    for log in log_dicts[-30:]:
        audit_rows_data.append([
            str(log.get('timestamp', ''))[:19],
            str(log.get('action', '')),
            str(log.get('resource_type', '') or ''),
            str(log.get('resource_id', '') or '')[:20]
        ])
    if len(audit_rows_data) == 1:
        audit_rows_data.append(['No audit events yet', '', '', ''])

    audit_table = Table(
        audit_rows_data, colWidths=[4.5 * cm, 3.5 * cm, 4 * cm, 5 * cm]
    )
    audit_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), dark_blue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, light_bg]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2ea')),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(audit_table)
    story.append(Spacer(1, 0.8 * cm))

    # Footer note
    story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#dee2ea')))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        'Generated by ForenSync Digital Forensics Platform. '
        'This report is for authorized investigative use only.',
        small_style
    ))

    doc.build(story)
    return report_path, None


# =============================================================================
# JSON REPORT EXPORT
# =============================================================================

def generate_json_report(case, evidence_list, audit_logs, output_dir):
    """
    Export all case data to a structured JSON file.

    Returns:
        str: Absolute path to the generated JSON file.
    """
    os.makedirs(output_dir, exist_ok=True)

    case_data = case.to_dict() if hasattr(case, 'to_dict') else case
    evidence_dicts = [
        e.to_dict() if hasattr(e, 'to_dict') else e for e in evidence_list
    ]
    log_dicts = [
        log.to_dict() if hasattr(log, 'to_dict') else log for log in audit_logs
    ]

    report = {
        'generated_at': datetime.now().isoformat(),
        'tool': 'ForenSync v1.0.0',
        'report_type': 'case_export',
        'case': case_data,
        'evidence': evidence_dicts,
        'audit_log': log_dicts,
        'statistics': {
            'evidence_count': len(evidence_dicts),
            'analyzed_count': sum(
                1 for e in evidence_dicts if e.get('analysis_status') == 'completed'
            ),
            'audit_event_count': len(log_dicts)
        }
    }

    report_filename = 'forensync_report_{0}_{1}.json'.format(
        case_data.get('case_number', 'unknown').replace('-', '_'),
        datetime.now().strftime('%Y%m%d_%H%M%S')
    )
    report_path = os.path.join(output_dir, report_filename)
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)

    return report_path
