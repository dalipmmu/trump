"""
NSA-Grade Command & Control Interface for SecretScout
Elite-level CLI with advanced features
"""

import click
import json
import uuid
from datetime import datetime
from typing import Optional, List
from pathlib import Path

from .engine import Engine, ScanConfig, ScanResult
from .storage import FindingStore
from .report import generate_report, generate_plain_english_report, nsa_report_generator, generate_nsa_report
from .persistence import NSAFindingStore, nsa_store
from . import TECHNIQUES, ALL_TECHNIQUE_IDS


@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--config', '-c', type=click.Path(), help='Config file path')
@click.option('--output', '-o', type=click.Path(), help='Output directory')
@click.option('--log-level', type=click.Choice(['debug', 'info', 'warning', 'error']), default='info', help='Logging level')
@click.pass_context
def cli(ctx, verbose, config, output, log_level):
    """NSA-Grade Secret Scanner - Command & Control Interface"""
    
    ctx.ensure_object(dict)
    ctx.obj['VERBOSE'] = verbose
    ctx.obj['CONFIG'] = config
    ctx.obj['OUTPUT'] = output
    ctx.obj['LOG_LEVEL'] = log_level
    
    if config:
        load_config(config)


@cli.command()
@click.argument('target')
@click.option('--scan-id', type=str, help='Custom scan ID')
@click.option('--techniques', '-t', type=str, default='all', help='Techniques to run (comma-separated: t1,t2,t3 or "all")')
@click.option('--exclude', '-e', type=str, help='Techniques to exclude (comma-separated)')
@click.option('--crawl', '-c', is_flag=True, help='Crawl the website')
@click.option('--max-pages', '-p', type=int, default=50, help='Maximum pages to crawl')
@click.option('--max-depth', '-d', type=int, default=5, help='Maximum crawl depth')
@click.option('--same-host-only', is_flag=True, default=True, help='Only scan same host')
@click.option('--validate', '-V', is_flag=True, help='Validate discovered API keys')
@click.option('--no-validate', is_flag=True, help='Skip key validation')
@click.option('--reveal', '-r', is_flag=True, help='Reveal full secret values in output')
@click.option('--output-format', '-f', type=click.Choice(['json', 'html', 'pdf', 'nsa']), default='json', help='Output format')
@click.option('--output-file', '-O', type=str, help='Output file path')
@click.option('--webhook', '-w', type=str, help='Webhook URL for alerts')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low', 'all']), default='all', help='Minimum severity to report')
@click.option('--no-cache', is_flag=True, help='Disable caching')
@click.option('--parallel', type=int, default=None, help='Number of parallel workers (default: CPU count)')
@click.pass_context
def scan(ctx, target, scan_id, techniques, exclude, crawl, max_pages, max_depth, 
        same_host_only, validate, no_validate, reveal, output_format, output_file,
        webhook, severity, no_cache, parallel):
    """Scan a target for secrets using NSA-grade techniques"""
    
    # Generate scan ID if not provided
    scan_id = scan_id or str(uuid.uuid4())
    
    # Parse techniques
    if techniques == 'all':
        selected_techniques = ALL_TECHNIQUE_IDS
    else:
        selected_techniques = [t.strip() for t in techniques.split(',') if t.strip()]
    
    # Apply exclusions
    if exclude:
        excluded = [t.strip() for t in exclude.split(',') if t.strip()]
        selected_techniques = [t for t in selected_techniques if t not in excluded]
    
    # Parse severity filter
    min_severity = severity if severity != 'all' else None
    
    # Create scan config
    config = ScanConfig(
        url=target if not target.startswith('http') else target,
        project_path=target if target.startswith('/') or target.startswith('.') else None,
        scan_id=scan_id,
        techniques=selected_techniques,
        crawl=crawl,
        max_pages=max_pages,
        max_depth=max_depth,
        same_host_only=same_host_only,
        validate_keys=validate and not no_validate,
        reveal_secrets=reveal,
        output_format=output_format,
        output_file=output_file,
        verbose=ctx.obj.get('VERBOSE', False),
        parallel_workers=parallel
    )
    
    # Create engine
    engine = Engine(config)
    
    # Run scan
    click.echo(f"[NSA] Starting scan {scan_id} on {target}")
    click.echo(f"[NSA] Techniques: {', '.join(selected_techniques)}")
    
    result = engine.scan()
    
    # Output results
    if output_format == 'nsa':
        output_path = output_file or f"nsa_report_{scan_id}.json"
        generate_nsa_report(result, output_path, reveal)
        click.echo(f"[NSA] NSA-grade report saved to: {output_path}")
    elif output_format == 'json':
        output_path = output_file or f"report_{scan_id}.json"
        with open(output_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        click.echo(f"[NSA] JSON report saved to: {output_path}")
    elif output_format == 'html':
        output_path = output_file or f"report_{scan_id}.html"
        generate_report(result, output_path, 'full', reveal, 'html')
        click.echo(f"[NSA] HTML report saved to: {output_path}")
    elif output_format == 'pdf':
        output_path = output_file or f"report_{scan_id}.pdf"
        generate_report(result, output_path, 'full', reveal, 'pdf')
        click.echo(f"[NSA] PDF report saved to: {output_path}")
    
    # Send to webhook if configured
    if webhook and result.store and result.store.findings:
        send_webhook_alert(webhook, result)
        click.echo(f"[NSA] Alert sent to webhook: {webhook}")
    
    # Print summary
    click.echo(f"\n[NSA] Scan Summary:")
    click.echo(f"  Target: {target}")
    click.echo(f"  Scan ID: {scan_id}")
    click.echo(f"  Findings: {len(result.store.findings) if result.store else 0}")
    
    if result.store and result.store.findings:
        by_severity = {}
        for f in result.store.findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        for sev, count in sorted(by_severity.items(), key=lambda x: x[0], reverse=True):
            click.echo(f"    {sev.upper()}: {count}")


@cli.command()
@click.argument('scan_id')
@click.option('--revalidate', '-r', is_flag=True, help='Revalidate all keys')
@click.option('--export', '-e', type=click.Choice(['json', 'html', 'pdf', 'nsa']), help='Export format')
@click.option('--output-file', '-O', type=str, help='Output file path')
@click.option('--reveal', is_flag=True, help='Reveal full secret values')
def results(scan_id, revalidate, export, output_file, reveal):
    """Get results for a specific scan"""
    
    # Get findings from persistence
    findings = nsa_store.get_findings(scan_id=scan_id)
    
    if not findings:
        click.echo(f"[NSA] No findings found for scan {scan_id}")
        return
    
    click.echo(f"[NSA] Found {len(findings)} findings for scan {scan_id}")
    
    # Revalidate if requested
    if revalidate:
        engine = Engine(ScanConfig(validate_keys=True))
        for finding in findings:
            if finding.provider:
                finding.confirmed_live = engine._validate_key(finding.secret_value, finding.provider)
                nsa_store.add_finding(finding, scan_id)
        click.echo(f"[NSA] Revalidated {len(findings)} findings")
    
    # Export if requested
    if export:
        output_path = output_file or f"{scan_id}_export.{export}"
        
        if export == 'nsa':
            # Create a mock ScanResult for NSA report
            from .engine import ScanResult
            result = ScanResult(
                scan_id=scan_id,
                config=ScanConfig(scan_id=scan_id),
                store=FindingStore()
            )
            result.store.findings = findings
            generate_nsa_report(result, output_path, reveal)
        elif export == 'json':
            data = [{
                'title': f.title,
                'technique': f.technique,
                'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                'url': f.url,
                'secret_value': f.secret_value if reveal else f.redacted_value,
                'provider': f.provider,
                'confirmed_live': f.confirmed_live
            } for f in findings]
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        click.echo(f"[NSA] Exported to: {output_path}")
    else:
        # Print findings
        for i, finding in enumerate(findings, 1):
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            click.echo(f"\n[{i}] {finding.title}")
            click.echo(f"    Technique: {finding.technique}")
            click.echo(f"    Severity: {sev.upper()}")
            click.echo(f"    URL: {finding.url}")
            click.echo(f"    Provider: {finding.provider or 'N/A'}")
            click.echo(f"    Live: {'YES' if finding.confirmed_live else 'NO'}")
            if reveal:
                click.echo(f"    Secret: {finding.secret_value}")


@cli.command()
@click.option('--all', '-a', is_flag=True, help='Show all scans')
@click.option('--limit', '-l', type=int, default=10, help='Limit number of results')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low']), help='Filter by severity')
@click.option('--export', '-e', type=click.Choice(['json', 'csv']), help='Export format')
@click.option('--output-file', '-O', type=str, help='Output file path')
def history(all, limit, severity, export, output_file):
    """Show scan history"""
    
    scans = nsa_store.get_scans(limit=limit if not all else None, severity=severity)
    
    if not scans:
        click.echo("[NSA] No scans found in history")
        return
    
    if export:
        if export == 'json':
            output_path = output_file or 'scan_history.json'
            with open(output_path, 'w') as f:
                json.dump(scans, f, indent=2)
            click.echo(f"[NSA] Exported history to: {output_path}")
        return
    
    click.echo(f"[NSA] Scan History ({len(scans)} scans):\n")
    
    for scan in scans:
        click.echo(f"ID: {scan['scan_id']}")
        click.echo(f"  Target: {scan['target']}")
        click.echo(f"  Started: {scan['start_time']}")
        click.echo(f"  Findings: {scan['finding_count']} ({scan['critical_count']} critical, {scan['high_count']} high)")
        click.echo(f"  Classification: {scan['classification']}")
        click.echo()


@cli.command('false-positive')
@click.argument('scan_id')
@click.argument('finding_id', type=int)
@click.option('--reason', '-r', required=True, help='Reason for false positive')
def false_positive(scan_id, finding_id, reason):
    """Mark a finding as false positive"""
    
    nsa_store.mark_false_positive(finding_id, reason)
    click.echo(f"[NSA] Marked finding {finding_id} from scan {scan_id} as false positive")
    click.echo(f"    Reason: {reason}")


@cli.command()
@click.option('--stats', '-s', is_flag=True, help='Show statistics')
@click.option('--clear', '-c', is_flag=True, help='Clear all data')
def status(stats, clear):
    """Show system status"""
    
    if clear:
        # Clear database
        import os
        db_path = 'findings.db'
        if os.path.exists(db_path):
            os.remove(db_path)
            click.echo(f"[NSA] Cleared database: {db_path}")
        else:
            click.echo(f"[NSA] Database not found: {db_path}")
        return
    
    if stats:
        database_stats = nsa_store.get_stats()
        click.echo("[NSA] Database Statistics:")
        click.echo(f"  Total Findings: {database_stats['total_findings']}")
        click.echo(f"  Live Validated: {database_stats['live_findings']}")
        click.echo(f"  False Positives: {database_stats['false_positives']}")
        
        for severity, data in database_stats['by_severity'].items():
            click.echo(f"  {severity.upper()}: {data['total']} (Live: {data['live']}, FP: {data['false_positives']})")
    else:
        click.echo("[NSA] SecretScout PRO - NSA-Grade Edition")
        click.echo("  Status: OPERATIONAL")
        click.echo("  Version: 2.0.0")
        click.echo("  Techniques: 18 (t1-t18)")
        click.echo("  Features: Context-Aware Scanning, Live Validation, NSA-Grade Reporting")


@cli.command('add-false-positive')
@click.argument('secret_value')
@click.option('--reason', '-r', help='Reason for adding')
def add_false_positive(secret_value, reason):
    """Add a secret to the false positives list"""
    
    nsa_store.add_false_positive(secret_value, reason)
    click.echo(f"[NSA] Added secret to false positives list")
    if reason:
        click.echo(f"    Reason: {reason}")


@cli.command('check-false-positive')
@click.argument('secret_value')
def check_false_positive(secret_value):
    """Check if a secret is a known false positive"""
    
    is_fp = nsa_store.is_known_false_positive(secret_value)
    click.echo(f"[NSA] Secret: {secret_value[:20]}...")
    click.echo(f"    False Positive: {'YES' if is_fp else 'NO'}")


@cli.command()
@click.option('--port', '-p', type=int, default=5000, help='Port to run on')
@click.option('--host', '-H', type=str, default='127.0.0.1', help='Host to bind to')
@click.option('--api-token', '-t', type=str, help='API token for authentication')
@click.option('--debug', '-d', is_flag=True, help='Enable debug mode')
def ui(port, host, api_token, debug):
    """Start the web dashboard"""
    
    from .webapp import create_app
    
    app = create_app(api_token=api_token, debug=debug)
    
    click.echo(f"[NSA] Starting dashboard at http://{host}:{port}")
    click.echo(f"[NSA] API Token: {'Set' if api_token else 'Not set (read-only)'}")
    
    app.run(host=host, port=port, debug=debug)


@cli.command('list-techniques')
def list_techniques():
    """List all available scanning techniques"""
    
    click.echo("[NSA] Available Scanning Techniques:\n")
    
    for tech_id, tech_info in sorted(TECHNIQUES.items()):
        click.echo(f"  {tech_id}: {tech_info['name']}")
        click.echo(f"    {tech_info['description']}")
        click.echo()


def send_webhook_alert(webhook_url: str, result: ScanResult):
    """Send alert to webhook"""
    try:
        import requests
        
        findings = result.store.findings if result.store else []
        
        payload = {
            'event': 'scan_completed',
            'scan_id': result.config.scan_id if result.config else 'unknown',
            'target': result.config.url if result.config else 'unknown',
            'timestamp': datetime.now().isoformat(),
            'findings_count': len(findings),
            'critical_count': len([f for f in findings if (f.severity.value if hasattr(f.severity, 'value') else f.severity) == 'critical']),
            'high_count': len([f for f in findings if (f.severity.value if hasattr(f.severity, 'value') else f.severity) == 'high']),
            'findings': [
                {
                    'title': f.title,
                    'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    'technique': f.technique,
                    'url': f.url,
                    'provider': f.provider
                }
                for f in findings[:10]  # Limit to first 10 findings
            ]
        }
        
        headers = {'Content-Type': 'application/json'}
        response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
        
        if response.status_code != 200:
            click.echo(f"[NSA] Webhook alert failed: {response.status_code}")
        
    except Exception as e:
        click.echo(f"[NSA] Webhook alert error: {e}")


def load_config(config_path: str):
    """Load configuration from file"""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Apply configuration
        click.echo(f"[NSA] Loaded config from: {config_path}")
        
    except Exception as e:
        click.echo(f"[NSA] Error loading config: {e}")


if __name__ == '__main__':
    cli()
