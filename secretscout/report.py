"""
Report Generation Module for SecretScout
Generates HTML and PDF reports from scan results
"""

import json
import os
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path

from .storage import Finding, Severity, DataClass
from .engine import ScanResult
from . import TECHNIQUES


def generate_report(result: ScanResult, 
                   output_path: str, 
                   mode: str = 'full', 
                   reveal_secrets: bool = False,
                   format: str = 'html'):
    """
    Generate a report from scan results
    
    Args:
        result: ScanResult containing findings
        output_path: Path to save the report
        mode: 'full' for technical report, 'simple' for plain-English
        reveal_secrets: Whether to reveal full secret values
        format: 'html' or 'pdf'
    """
    if mode == 'simple':
        if format == 'html':
            generate_plain_english_html_report(result, output_path, reveal_secrets)
        elif format == 'pdf':
            generate_plain_english_pdf_report(result, output_path, reveal_secrets)
    else:
        if format == 'html':
            generate_full_html_report(result, output_path, reveal_secrets)
        elif format == 'pdf':
            generate_full_pdf_report(result, output_path, reveal_secrets)


def generate_plain_english_report(result: ScanResult, 
                                 output_path: str, 
                                 reveal_secrets: bool = False,
                                 format: str = 'html'):
    """Generate a plain-English report"""
    if format == 'html':
        generate_plain_english_html_report(result, output_path, reveal_secrets)
    elif format == 'pdf':
        generate_plain_english_pdf_report(result, output_path, reveal_secrets)


def generate_full_html_report(result: ScanResult, output_path: str, reveal_secrets: bool = False):
    """Generate a full technical HTML report"""
    summary = result.get_summary()
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretScout PRO - Vulnerability Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card h3 {{
            margin-top: 0;
            color: #667eea;
            font-size: 2em;
        }}
        .summary-card p {{
            margin-bottom: 0;
            color: #666;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
        }}
        .risk-critical {{ background-color: #dc3545; }}
        .risk-high {{ background-color: #fd7e14; }}
        .risk-medium {{ background-color: #ffc107; color: #333; }}
        .risk-low {{ background-color: #28a745; }}
        .risk-info {{ background-color: #17a2b8; }}
        .findings-section {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .findings-section h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .finding {{
            border: 1px solid #e0e0e0;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
            background: #f9f9f9;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
            margin: 0;
        }}
        .finding-severity {{
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
        }}
        .severity-critical {{ background-color: #dc3545; }}
        .severity-high {{ background-color: #fd7e14; }}
        .severity-medium {{ background-color: #ffc107; color: #333; }}
        .severity-low {{ background-color: #28a745; }}
        .severity-info {{ background-color: #17a2b8; }}
        .finding-details {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #e0e0e0;
        }}
        .finding-detail {{
            margin-bottom: 8px;
        }}
        .finding-detail strong {{
            color: #667eea;
            min-width: 120px;
            display: inline-block;
        }}
        .secret-value {{
            font-family: monospace;
            background: #f0f0f0;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 0.9em;
        }}
        .code-block {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.9em;
            margin: 10px 0;
        }}
        .confidential-watermark {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(255, 0, 0, 0.1);
            padding: 10px 20px;
            border-radius: 5px;
            font-size: 0.8em;
            color: #dc3545;
            transform: rotate(-15deg);
        }}
        .attack-chain {{
            background: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
            border-left: 4px solid #ffc107;
        }}
        .attack-chain h4 {{
            margin-top: 0;
            color: #856404;
        }}
        .attack-chain-steps {{
            list-style: none;
            padding: 0;
        }}
        .attack-chain-steps li {{
            padding: 5px 0;
            position: relative;
            padding-left: 25px;
        }}
        .attack-chain-steps li:before {{
            content: "→";
            position: absolute;
            left: 0;
            color: #856404;
        }}
        @media (max-width: 768px) {{
            .summary {{
                grid-template-columns: 1fr;
            }}
            .finding-header {{
                flex-direction: column;
                align-items: flex-start;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 SecretScout PRO</h1>
        <p class="subtitle">Professional API Vulnerability Detection Report</p>
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>{summary.get('total_findings', 0)}</h3>
            <p>Total Findings</p>
        </div>
        <div class="summary-card">
            <h3><span class="risk-badge risk-{summary.get('risk_level', 'info')}">{summary.get('risk_level', 'info').upper()}</span></h3>
            <p>Risk Level</p>
        </div>
        <div class="summary-card">
            <h3>{summary.get('risk_score', 0):.1f}/100</h3>
            <p>Risk Score</p>
        </div>
        <div class="summary-card">
            <h3>{summary.get('live_keys_confirmed', 0)}</h3>
            <p>Live Keys Confirmed</p>
        </div>
    </div>
    
    <div class="findings-section">
        <h2>📊 Executive Summary</h2>
        <p><strong>Scan ID:</strong> {summary.get('scan_id', 'N/A')}</p>
        <p><strong>Target:</strong> {summary.get('target_url', '') or summary.get('target_project', '') or 'N/A'}</p>
        <p><strong>Scan Duration:</strong> {result.duration:.2f} seconds</p>
        <p><strong>Techniques Used:</strong> {', '.join(summary.get('techniques_used', []))}</p>
        
        <h3>Risk Assessment</h3>
        <p>The scan identified <strong>{summary.get('total_findings', 0)}</strong> vulnerabilities with an overall risk score of <strong>{summary.get('risk_score', 0):.1f}/100</strong> ({summary.get('risk_level', 'info').upper()} risk level).</p>
        
        {'<p><strong>⚠️ CONFIDENTIAL: This report contains sensitive information. Keep it secure.</strong></p>' if reveal_secrets else ''}
    </div>
    
    <div class="findings-section">
        <h2>📈 Findings by Severity</h2>
        <div style="display: flex; gap: 20px; flex-wrap: wrap;">
            {''.join([f'<div style="flex: 1; min-width: 200px;"><h3 style="color: #dc3545;">CRITICAL: {count}</h3></div>' for severity, count in summary.get('findings_by_severity', {}).items() if severity == 'critical'])}
            {''.join([f'<div style="flex: 1; min-width: 200px;"><h3 style="color: #fd7e14;">HIGH: {count}</h3></div>' for severity, count in summary.get('findings_by_severity', {}).items() if severity == 'high'])}
            {''.join([f'<div style="flex: 1; min-width: 200px;"><h3 style="color: #ffc107;">MEDIUM: {count}</h3></div>' for severity, count in summary.get('findings_by_severity', {}).items() if severity == 'medium'])}
            {''.join([f'<div style="flex: 1; min-width: 200px;"><h3 style="color: #28a745;">LOW: {count}</h3></div>' for severity, count in summary.get('findings_by_severity', {}).items() if severity == 'low'])}
            {''.join([f'<div style="flex: 1; min-width: 200px;"><h3 style="color: #17a2b8;">INFO: {count}</h3></div>' for severity, count in summary.get('findings_by_severity', {}).items() if severity == 'info'])}
        </div>
    </div>
    
    <div class="findings-section">
        <h2>🔍 Detailed Findings</h2>
        {'<p><em>Showing full secret values (CONFIDENTIAL)</em></p>' if reveal_secrets else '<p><em>Secret values are redacted. Use --reveal to see full values.</em></p>'}
        
        {''.join([generate_finding_html(finding, reveal_secrets) for finding in result.store.findings])}
    </div>
    
    {'<div class="confidential-watermark">CONFIDENTIAL - Contains Sensitive Information</div>' if reveal_secrets else ''}
    
    <div style="text-align: center; margin-top: 30px; color: #666; font-size: 0.9em;">
        Generated by SecretScout PRO on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    </div>
</body>
</html>"""
    
    # Write to file
    with open(output_path, 'w') as f:
        f.write(html)
    
    print(f"Full HTML report generated: {output_path}")


def generate_finding_html(finding: Finding, reveal_secrets: bool = False) -> str:
    """Generate HTML for a single finding"""
    secret_value = finding.secret_value if reveal_secrets and finding.secret_value else finding.redacted_value
    
    html = f"""
    <div class="finding">
        <div class="finding-header">
            <h3 class="finding-title">{finding.title}</h3>
            <span class="finding-severity severity-{finding.severity.value}">{finding.severity.value.upper()}</span>
        </div>
        <div class="finding-details">
            <div class="finding-detail">
                <strong>Technique:</strong> {finding.technique} - {finding.technique_name}
            </div>
            <div class="finding-detail">
                <strong>Data Class:</strong> {finding.data_class.value}
            </div>
            <div class="finding-detail">
                <strong>URL:</strong> <code>{finding.url}</code>
            </div>
            {'<div class="finding-detail"><strong>Secret:</strong> <span class="secret-value">{secret_value}</span></div>' if secret_value else ''}
            <div class="finding-detail">
                <strong>Provider:</strong> {finding.provider or 'N/A'}
            </div>
            <div class="finding-detail">
                <strong>Impact:</strong> {finding.impact}
            </div>
            <div class="finding-detail">
                <strong>Remediation:</strong> {finding.remediation}
            </div>
            <div class="finding-detail">
                <strong>Description:</strong> {finding.description}
            </div>
            {'<div class="finding-detail"><strong>Status:</strong> <span style="color: #dc3545; font-weight: bold;">CONFIRMED LIVE</span></div>' if finding.confirmed_live else ''}
            {''.join([f'<div class="attack-chain"><h4>Attack Chain</h4><ul class="attack-chain-steps">{ "".join([f"<li>{step}</li>" for step in finding.attack_chain]) }</ul></div>' if finding.attack_chain else ''])}
            {'<div class="code-block">{finding.evidence[:500]}...</div>' if finding.evidence and len(finding.evidence) > 100 else ''}
        </div>
    </div>
    """
    return html


def generate_plain_english_html_report(result: ScanResult, output_path: str, reveal_secrets: bool = False):
    """Generate a plain-English HTML report"""
    summary = result.get_summary()
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretScout PRO - Plain English Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f9f9f9;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2em;
        }}
        .section {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .section h2 {{
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
        }}
        .step {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }}
        .step h3 {{
            margin-top: 0;
            color: #333;
        }}
        .step p {{
            margin-bottom: 10px;
        }}
        .step-data {{
            background: white;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }}
        .risk-indicator {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
        }}
        .risk-high {{ background-color: #dc3545; }}
        .risk-medium {{ background-color: #ffc107; color: #333; }}
        .risk-low {{ background-color: #28a745; }}
        @media (max-width: 768px) {{
            body {{
                padding: 10px;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 SecretScout PRO</h1>
        <p>Plain English Security Report</p>
    </div>
    
    <div class="section">
        <h2>📋 Report Overview</h2>
        <p>This report explains the security issues found on <strong>{summary.get('target_url', '') or summary.get('target_project', '') or 'the scanned target'}</strong> in simple terms that anyone can understand.</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Issues Found:</strong> {summary.get('total_findings', 0)}</p>
        <p><strong>Overall Risk:</strong> <span class="risk-indicator risk-{summary.get('risk_level', 'low')}">{summary.get('risk_level', 'low').upper()}</span></p>
    </div>
    
    <div class="section">
        <h2>🚨 What This Means for Your Business</h2>
        <p>This scan found security vulnerabilities that could put your business at risk. Here's what each issue means in practical terms:</p>
        
        {''.join([generate_plain_english_finding_html(finding, reveal_secrets) for finding in result.store.findings])}
    </div>
    
    <div class="section">
        <h2>🎯 Recommended Actions</h2>
        <ol>
            {''.join([f'<li>Fix the {finding.severity.value.upper()} issue: {finding.title} (see step-by-step instructions above)</li>' for finding in sorted(result.store.findings, key=lambda x: x.get_severity_weight(), reverse=True)])}
        </ol>
    </div>
    
    <div class="section">
        <h2>📞 Next Steps</h2>
        <p>1. Review each issue above and follow the step-by-step instructions to fix them</p>
        <p>2. For critical issues, consider taking the affected systems offline until fixed</p>
        <p>3. Rotate any exposed API keys, passwords, or credentials immediately</p>
        <p>4. Schedule regular security scans to prevent future issues</p>
        <p>5. Consider hiring a security professional for a comprehensive audit</p>
    </div>
    
    <div style="text-align: center; margin-top: 30px; color: #666; font-size: 0.9em;">
        Generated by SecretScout PRO - Professional API Vulnerability Detection
    </div>
</body>
</html>"""
    
    # Write to file
    with open(output_path, 'w') as f:
        f.write(html)
    
    print(f"Plain English HTML report generated: {output_path}")


def generate_plain_english_finding_html(finding: Finding, reveal_secrets: bool = False) -> str:
    """Generate plain English HTML for a single finding"""
    secret_value = finding.secret_value if reveal_secrets and finding.secret_value else finding.redacted_value
    
    # Create plain English descriptions based on finding type
    plain_english = {
        'OpenAI API Key': 'An artificial intelligence service access code that could allow others to use your AI services at your expense.',
        'AWS Access Key ID': 'An Amazon Web Services access code that could allow access to your cloud infrastructure.',
        'GitHub Token': 'A code that allows access to your GitHub repositories and code.',
        'Stripe Secret Key': 'A payment processing code that could allow others to process payments through your account.',
        'Razorpay Key Secret': 'A payment processing code for Razorpay that could allow unauthorized transactions.',
        'Generic API Key': 'A code that allows access to some external service or API.',
        'Private Key': 'A cryptographic key that could allow decryption of sensitive data.',
        'JWT Token': 'An authentication token that could allow access to user accounts.',
        'Database Connection String': 'A connection string that could allow direct access to your database.',
        'Credit Card Number': 'A payment card number that should never be stored in plain text.',
        'US Social Security Number': 'A sensitive personal identifier that requires protection.',
        'Email Address': 'Personal contact information that should be protected.',
    }
    
    description = plain_english.get(finding.title.split(' found')[0], finding.description)
    
    html = f"""
    <div class="step">
        <h3>Issue: {finding.title}</h3>
        <p><strong>Risk Level:</strong> <span class="risk-indicator risk-{finding.severity.value}">{finding.severity.value.upper()}</span></p>
        <p><strong>What this means:</strong> {description}</p>
        <p><strong>Where it was found:</strong> {finding.url}</p>
        {'<p><strong>The exposed information:</strong> <code>{secret_value}</code></p>' if secret_value else ''}
        <p><strong>Why this is a problem:</strong> {finding.impact}</p>
        
        <h4>How to see this issue yourself:</h4>
        <ol>
            <li>Open your web browser</li>
            <li>Go to: <code>{finding.url}</code></li>
            <li>Look at the page content or source code</li>
            <li>You should see the exposed information mentioned above</li>
        </ol>
        
        <h4>How to fix this issue:</h4>
        <p>{finding.remediation}</p>
        
        {'<div class="step-data">{finding.evidence[:200]}...</div>' if finding.evidence and len(finding.evidence) > 50 else ''}
        
        {'<p><strong>⚠️ IMPORTANT:</strong> This issue has been confirmed to be active and accessible.</p>' if finding.confirmed_live else ''}
    </div>
    """
    return html


def generate_full_pdf_report(result: ScanResult, output_path: str, reveal_secrets: bool = False):
    """Generate a full PDF report"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Add header
        story.append(Paragraph("🔍 SecretScout PRO - Vulnerability Report", title_style))
        story.append(Paragraph("Professional API Vulnerability Detection", styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Add summary
        summary = result.get_summary()
        story.append(Paragraph("Scan Summary", heading_style))
        
        summary_data = [
            ['Scan ID', summary.get('scan_id', 'N/A')],
            ['Target', summary.get('target_url', '') or summary.get('target_project', '') or 'N/A'],
            ['Duration', f"{result.duration:.2f} seconds"],
            ['Total Findings', str(summary.get('total_findings', 0))],
            ['Risk Level', summary.get('risk_level', 'info').upper()],
            ['Risk Score', f"{summary.get('risk_score', 0):.1f}/100"],
            ['Live Keys Confirmed', str(summary.get('live_keys_confirmed', 0))],
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Add findings by severity
        story.append(Paragraph("Findings by Severity", heading_style))
        
        severity_data = []
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = summary.get('findings_by_severity', {}).get(severity, 0)
            if count > 0:
                severity_data.append([severity.upper(), str(count)])
        
        if severity_data:
            severity_table = Table(severity_data, colWidths=[2*inch, 4*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(severity_table)
        
        story.append(Spacer(1, 0.5*inch))
        
        # Add detailed findings
        story.append(Paragraph("Detailed Findings", heading_style))
        
        for finding in result.store.findings:
            story.append(Paragraph(f"[{finding.severity.value.upper()}] {finding.title}", styles['Heading3']))
            
            finding_data = [
                ['Technique', f"{finding.technique} - {finding.technique_name}"],
                ['URL', finding.url],
                ['Data Class', finding.data_class.value],
                ['Impact', finding.impact],
                ['Remediation', finding.remediation],
            ]
            
            if finding.secret_value and reveal_secrets:
                finding_data.append(['Secret Value', finding.secret_value])
            elif finding.redacted_value:
                finding_data.append(['Secret Value', finding.redacted_value])
            
            if finding.confirmed_live:
                finding_data.append(['Status', 'CONFIRMED LIVE'])
            
            finding_table = Table(finding_data, colWidths=[1.5*inch, 4.5*inch])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(finding_table)
            story.append(Spacer(1, 0.2*inch))
        
        # Build PDF
        doc.build(story)
        print(f"Full PDF report generated: {output_path}")
        
    except ImportError:
        print("Error: reportlab library required for PDF generation. Install with: pip install reportlab")
    except Exception as e:
        print(f"Error generating PDF report: {str(e)}")


def generate_plain_english_pdf_report(result: ScanResult, output_path: str, reveal_secrets: bool = False):
    """Generate a plain English PDF report"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#667eea'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Add header
        story.append(Paragraph("🔍 SecretScout PRO - Plain English Report", title_style))
        story.append(Paragraph("Security Issues Explained Simply", styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Add overview
        summary = result.get_summary()
        story.append(Paragraph("Report Overview", heading_style))
        
        overview_text = f"""This report explains the security issues found on {summary.get('target_url', '') or summary.get('target_project', '') or 'the scanned target'} in simple terms.

Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Issues Found: {summary.get('total_findings', 0)}
Overall Risk: {summary.get('risk_level', 'low').upper()}

This scan found security vulnerabilities that could put your business at risk. Below are the issues explained in practical terms."""
        
        story.append(Paragraph(overview_text, styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Add findings
        story.append(Paragraph("What This Means for Your Business", heading_style))
        
        for i, finding in enumerate(result.store.findings, 1):
            story.append(Paragraph(f"Issue {i}: {finding.title}", styles['Heading3']))
            
            # Create plain English description
            plain_english = {
                'OpenAI API Key': 'An artificial intelligence service access code that could allow others to use your AI services at your expense.',
                'AWS Access Key ID': 'An Amazon Web Services access code that could allow access to your cloud infrastructure.',
                'GitHub Token': 'A code that allows access to your GitHub repositories and code.',
                'Stripe Secret Key': 'A payment processing code that could allow others to process payments through your account.',
                'Razorpay Key Secret': 'A payment processing code for Razorpay that could allow unauthorized transactions.',
                'Generic API Key': 'A code that allows access to some external service or API.',
                'Private Key': 'A cryptographic key that could allow decryption of sensitive data.',
                'JWT Token': 'An authentication token that could allow access to user accounts.',
                'Database Connection String': 'A connection string that could allow direct access to your database.',
                'Credit Card Number': 'A payment card number that should never be stored in plain text.',
                'US Social Security Number': 'A sensitive personal identifier that requires protection.',
                'Email Address': 'Personal contact information that should be protected.',
            }
            
            description = plain_english.get(finding.title.split(' found')[0], finding.description)
            
            finding_text = f"""<b>Risk Level:</b> {finding.severity.value.upper()}

<b>What this means:</b> {description}

<b>Where it was found:</b> {finding.url}

<b>Why this is a problem:</b> {finding.impact}

<b>How to fix this issue:</b> {finding.remediation}"""
            
            story.append(Paragraph(finding_text, styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
        
        # Add recommended actions
        story.append(Paragraph("Recommended Actions", heading_style))
        
        actions_text = """1. Review each issue above and follow the instructions to fix them
2. For critical issues, consider taking the affected systems offline until fixed
3. Rotate any exposed API keys, passwords, or credentials immediately
4. Schedule regular security scans to prevent future issues
5. Consider hiring a security professional for a comprehensive audit"""
        
        story.append(Paragraph(actions_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        print(f"Plain English PDF report generated: {output_path}")
        
    except ImportError:
        print("Error: reportlab library required for PDF generation. Install with: pip install reportlab")
    except Exception as e:
        print(f"Error generating PDF report: {str(e)}")
