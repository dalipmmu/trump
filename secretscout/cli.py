"""
Command Line Interface for SecretScout
Handles command-line arguments and orchestrates scanning
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import Optional, List

from .engine import Engine, ScanConfig, ScanResult
from .storage import FindingStore
from .report import generate_report, generate_plain_english_report
from . import TECHNIQUES, ALL_TECHNIQUE_IDS


def create_parser():
    """Create the argument parser"""
    parser = argparse.ArgumentParser(
        description="SecretScout PRO - Professional API Vulnerability Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m secretscout.cli scan https://example.com
  python -m secretscout.cli scan https://example.com --crawl --max-pages 100
  python -m secretscout.cli scan https://example.com --only t1,t2,t3 --reveal
  python -m secretscout.cli scan --project ./my-app --only t4
  python -m secretscout.cli ui --port 5000 --api-token MY_TOKEN
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run a vulnerability scan')
    scan_parser.add_argument('url', nargs='?', help='URL to scan')
    scan_parser.add_argument('--project', help='Local project path to scan')
    scan_parser.add_argument('--only', help='Only run specific techniques (comma-separated, e.g., t1,t2,t3)')
    scan_parser.add_argument('--exclude', help='Exclude specific techniques (comma-separated)')
    scan_parser.add_argument('--crawl', action='store_true', help='Crawl the entire website')
    scan_parser.add_argument('--max-pages', type=int, default=50, help='Maximum pages to crawl')
    scan_parser.add_argument('--max-depth', type=int, default=5, help='Maximum crawl depth')
    scan_parser.add_argument('--same-host-only', action='store_true', default=True, help='Only scan same host')
    scan_parser.add_argument('--reveal', action='store_true', help='Reveal full secret values in output')
    scan_parser.add_argument('--validate', action='store_true', help='Validate discovered API keys')
    scan_parser.add_argument('--no-home-check', action='store_true', help='Skip home directory check')
    scan_parser.add_argument('--out', help='Output file path')
    scan_parser.add_argument('--format', choices=['json', 'html', 'pdf'], default='json', help='Output format')
    scan_parser.add_argument('--report-mode', choices=['full', 'simple'], default='full', help='Report mode (full or simple)')
    scan_parser.add_argument('--html-out', help='Output HTML report file')
    scan_parser.add_argument('--pdf-out', help='Output PDF report file')
    scan_parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests in seconds')
    scan_parser.add_argument('--max-concurrent', type=int, default=10, help='Maximum concurrent requests')
    
    # UI command
    ui_parser = subparsers.add_parser('ui', help='Start the web dashboard')
    ui_parser.add_argument('--port', type=int, default=5000, help='Port to run the dashboard on')
    ui_parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    ui_parser.add_argument('--api-token', help='API token for protecting the REST API')
    ui_parser.add_argument('--no-api', action='store_true', help='Disable the REST API')
    ui_parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    # List techniques command
    list_parser = subparsers.add_parser('list-techniques', help='List all available techniques')
    
    return parser


def parse_techniques(techniques_str: Optional[str]) -> List[str]:
    """Parse comma-separated techniques string"""
    if not techniques_str:
        return []
    
    return [t.strip() for t in techniques_str.split(',') if t.strip()]


def main():
    """Main entry point for CLI"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        run_scan(args)
    elif args.command == 'ui':
        run_ui(args)
    elif args.command == 'list-techniques':
        list_techniques()
    else:
        parser.print_help()
        sys.exit(1)


def run_scan(args):
    """Run a vulnerability scan"""
    # Validate arguments
    if not args.url and not args.project:
        print("Error: Please provide either a URL or a project path to scan")
        sys.exit(1)
    
    # Parse techniques
    only_techniques = parse_techniques(args.only) if args.only else []
    exclude_techniques = parse_techniques(args.exclude) if args.exclude else []
    
    # Determine which techniques to run
    if only_techniques:
        techniques = only_techniques
    else:
        # Start with all techniques
        techniques = ALL_TECHNIQUE_IDS.copy()
        # Remove excluded techniques
        for tech in exclude_techniques:
            if tech in techniques:
                techniques.remove(tech)
    
    # Create scan config
    config = ScanConfig(
        url=args.url,
        project_path=args.project,
        techniques=techniques,
        crawl=args.crawl,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        same_host_only=args.same_host_only,
        reveal_secrets=args.reveal,
        validate_keys=args.validate,
        delay=args.delay,
        max_concurrent=args.max_concurrent,
        output_format=args.format,
        output_file=args.out
    )
    
    # Create and run engine
    engine = Engine(config)
    
    # Set up progress callback
    def on_progress(progress):
        if args.crawl:
            print(f"\rCrawling: {progress.get('visited', 0)} pages visited, {progress.get('queue', 0)} in queue...", end="")
    
    config.on_progress = on_progress
    
    # Set up finding callback
    def on_finding(finding):
        if args.reveal:
            print(f"[+] {finding.severity.value.upper()} - {finding.title} - {finding.secret_value}")
        else:
            print(f"[+] {finding.severity.value.upper()} - {finding.title} - {finding.redacted_value}")
    
    config.on_finding = on_finding
    
    print(f"Starting scan of {args.url or args.project}")
    print(f"Techniques: {', '.join(techniques)}")
    print(f"Crawl: {'Yes' if args.crawl else 'No'}")
    print("-" * 50)
    
    # Run scan
    result = engine.scan(config)
    
    # Print summary
    print("\n" + "=" * 50)
    print("SCAN SUMMARY")
    print("=" * 50)
    
    summary = result.get_summary()
    
    print(f"Scan ID: {summary['scan_id']}")
    print(f"Target: {summary['target_url'] or summary['target_project'] or 'Unknown'}")
    print(f"Duration: {result.duration:.2f} seconds")
    print(f"Total Findings: {summary['total_findings']}")
    
    if 'findings_by_severity' in summary:
        print("\nFindings by Severity:")
        for severity, count in summary['findings_by_severity'].items():
            print(f"  {severity.upper()}: {count}")
    
    if 'findings_by_technique' in summary:
        print("\nFindings by Technique:")
        for technique, count in summary['findings_by_technique'].items():
            tech_name = TECHNIQUES.get(technique, {}).get('name', technique)
            print(f"  {technique} ({tech_name}): {count}")
    
    if 'risk_score' in summary:
        print(f"\nRisk Score: {summary['risk_score']:.1f}/100 ({summary['risk_level'].upper()})")
    
    # Save output if requested
    if args.out:
        save_output(result, args.out, args.format, args.reveal)
    
    if args.html_out:
        generate_report(result, args.html_out, args.report_mode, args.reveal)
        print(f"\nHTML report saved to: {args.html_out}")
    
    if args.pdf_out:
        generate_report(result, args.pdf_out, args.report_mode, args.reveal, format='pdf')
        print(f"PDF report saved to: {args.pdf_out}")
    
    # Print findings
    if result.store.findings:
        print("\n" + "=" * 50)
        print("FINDINGS")
        print("=" * 50)
        
        for finding in result.store.findings:
            print(f"\n[{finding.severity.value.upper()}] {finding.title}")
            print(f"  Technique: {finding.technique} - {finding.technique_name}")
            print(f"  URL: {finding.url}")
            print(f"  Data Class: {finding.data_class.value}")
            if args.reveal and finding.secret_value:
                print(f"  Secret: {finding.secret_value}")
            else:
                print(f"  Secret: {finding.redacted_value}")
            print(f"  Impact: {finding.impact}")
            print(f"  Remediation: {finding.remediation}")
            if finding.confirmed_live:
                print("  STATUS: CONFIRMED LIVE")
    
    # Print errors if any
    if result.errors:
        print("\n" + "=" * 50)
        print("ERRORS")
        print("=" * 50)
        for error in result.errors:
            print(f"  - {error}")


def run_ui(args):
    """Start the web dashboard"""
    from .webapp import create_app
    
    app = create_app(
        api_token=args.api_token,
        enable_api=not args.no_api,
        debug=args.debug
    )
    
    print(f"Starting SecretScout dashboard on {args.host}:{args.port}")
    print(f"API enabled: {'Yes' if not args.no_api else 'No'}")
    if args.api_token:
        print(f"API token: {args.api_token}")
    print("Press Ctrl+C to stop")
    
    app.run(host=args.host, port=args.port, debug=args.debug)


def list_techniques():
    """List all available techniques"""
    print("Available Techniques:")
    print("=" * 50)
    
    for tech_id, tech_info in TECHNIQUES.items():
        print(f"{tech_id}: {tech_info['name']}")
        print(f"   Description: {tech_info['description']}")
        print()


def save_output(result: ScanResult, filename: str, format: str, reveal: bool):
    """Save scan results to a file"""
    if format == 'json':
        with open(filename, 'w') as f:
            json.dump(result.store.to_dict(reveal), f, indent=2, default=str)
        print(f"JSON output saved to: {filename}")
    elif format == 'html':
        generate_report(result, filename, 'full', reveal)
        print(f"HTML output saved to: {filename}")
    elif format == 'pdf':
        generate_report(result, filename, 'full', reveal, format='pdf')
        print(f"PDF output saved to: {filename}")


if __name__ == "__main__":
    main()