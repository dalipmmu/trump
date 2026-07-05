"""
Web Application Module for SecretScout
Flask-based dashboard and REST API
"""

import os
import json
import threading
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, session
from werkzeug.utils import secure_filename

from .engine import Engine, ScanConfig, ScanResult
from .storage import FindingStore, Severity, DataClass
from .report import generate_report, generate_plain_english_report
from . import TECHNIQUES, ALL_TECHNIQUE_IDS


def create_app(api_token: Optional[str] = None, 
              enable_api: bool = True,
              debug: bool = False):
    """Create and configure the Flask application"""
    
    app = Flask(__name__, 
                static_folder='static',
                template_folder='templates')
    
    # Configure app
    app.secret_key = os.environ.get('SECRET_KEY', 'secret-scout-secret-key-change-me')
    app.config['API_TOKEN'] = api_token
    app.config['ENABLE_API'] = enable_api
    app.config['DEBUG'] = debug
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
    
    # Store active scans
    app.active_scans = {}
    app.scan_history = []
    
    # Register blueprints and routes
    register_routes(app)
    
    return app


def register_routes(app):
    """Register all routes for the application"""
    
    @app.route('/')
    def index():
        """Main dashboard page"""
        return render_template('dashboard.html', 
                             techniques=TECHNIQUES,
                             scan_history=app.scan_history[-10:] if hasattr(app, 'scan_history') else [])
    
    @app.route('/scan', methods=['POST'])
    def start_scan():
        """Start a new scan via web interface"""
        try:
            data = request.form
            
            # Create scan config
            config = ScanConfig(
                url=data.get('url'),
                project_path=data.get('project_path'),
                techniques=parse_techniques(data.get('techniques', '')),
                crawl=data.get('crawl') == 'true',
                max_pages=int(data.get('max_pages', 50)),
                max_depth=int(data.get('max_depth', 5)),
                same_host_only=data.get('same_host_only') != 'false',
                reveal_secrets=data.get('reveal_secrets') == 'true',
                validate_keys=data.get('validate_keys') == 'true',
                delay=float(data.get('delay', 0.1)),
                max_concurrent=int(data.get('max_concurrent', 10))
            )
            
            # Create engine
            engine = Engine(config)
            
            # Store scan in active scans
            scan_id = engine.store.scan_id
            app.active_scans[scan_id] = {
                'engine': engine,
                'config': config,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'progress': {}
            }
            
            # Run scan in background thread
            def run_scan_background():
                try:
                    result = engine.scan(config)
                    app.active_scans[scan_id]['status'] = 'completed'
                    app.active_scans[scan_id]['result'] = result
                    app.active_scans[scan_id]['end_time'] = datetime.now().isoformat()
                    
                    # Add to history
                    app.scan_history.append({
                        'scan_id': scan_id,
                        'target': config.url or config.project_path or 'Unknown',
                        'start_time': app.active_scans[scan_id]['start_time'],
                        'end_time': app.active_scans[scan_id]['end_time'],
                        'findings_count': len(result.store.findings),
                        'risk_level': result.get_summary().get('risk_level', 'unknown')
                    })
                    
                except Exception as e:
                    app.active_scans[scan_id]['status'] = 'failed'
                    app.active_scans[scan_id]['error'] = str(e)
            
            thread = threading.Thread(target=run_scan_background)
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'message': 'Scan started successfully'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
    
    @app.route('/scan/<scan_id>/status')
    def scan_status(scan_id):
        """Get status of a running scan"""
        scan = app.active_scans.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify({
            'scan_id': scan_id,
            'status': scan.get('status', 'unknown'),
            'start_time': scan.get('start_time'),
            'end_time': scan.get('end_time'),
            'progress': scan.get('progress', {})
        })
    
    @app.route('/scan/<scan_id>/results')
    def scan_results(scan_id):
        """Get results of a completed scan"""
        scan = app.active_scans.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.get('status') != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        result = scan.get('result')
        if not result:
            return jsonify({'error': 'No results available'}), 404
        
        # Return results as JSON
        return jsonify(result.store.to_dict(scan['config'].reveal_secrets))
    
    @app.route('/scan/<scan_id>/summary')
    def scan_summary(scan_id):
        """Get summary of a scan"""
        scan = app.active_scans.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.get('status') != 'completed':
            return jsonify({'error': 'Scan not completed yet'}), 400
        
        result = scan.get('result')
        if not result:
            return jsonify({'error': 'No results available'}), 404
        
        return jsonify(result.get_summary())
    
    @app.route('/scan/<scan_id>/cancel', methods=['POST'])
    def cancel_scan(scan_id):
        """Cancel a running scan"""
        scan = app.active_scans.get(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Mark as cancelled (actual cancellation would require more complex implementation)
        scan['status'] = 'cancelled'
        scan['end_time'] = datetime.now().isoformat()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'status': 'cancelled'
        })
    
    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        """REST API endpoint for scanning"""
        if not app.config.get('ENABLE_API'):
            return jsonify({'error': 'API is disabled'}), 403
        
        # Check API token
        api_token = app.config.get('API_TOKEN')
        if api_token:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            
            provided_token = auth_header.split(' ')[1]
            if provided_token != api_token:
                return jsonify({'error': 'Invalid API token'}), 401
        
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body must be JSON'}), 400
            
            # Create scan config
            config = ScanConfig(
                url=data.get('url'),
                project_path=data.get('project'),
                techniques=parse_techniques(data.get('only', '')),
                crawl=data.get('crawl', False),
                max_pages=data.get('max_pages', 50),
                max_depth=data.get('max_depth', 5),
                same_host_only=data.get('same_host_only', True),
                reveal_secrets=data.get('reveal', False),
                validate_keys=data.get('validate', False),
                delay=data.get('delay', 0.1),
                max_concurrent=data.get('max_concurrent', 10)
            )
            
            # Create engine
            engine = Engine(config)
            
            # Run scan synchronously for API
            result = engine.scan(config)
            
            # Return results
            return jsonify({
                'success': True,
                'scan_id': result.scan_id,
                'summary': result.get_summary(),
                'findings': [f.to_dict(config.reveal_secrets) for f in result.store.findings]
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500
    
    @app.route('/api/health')
    def api_health():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'version': '2.0.0',
            'active_scans': len(app.active_scans),
            'total_scans': len(app.scan_history)
        })
    
    @app.route('/download/report/<scan_id>', methods=['GET'])
    def download_report(scan_id):
        """Download a report for a scan"""
        scan = app.active_scans.get(scan_id)
        if not scan:
            return "Scan not found", 404
        
        if scan.get('status') != 'completed':
            return "Scan not completed yet", 400
        
        result = scan.get('result')
        if not result:
            return "No results available", 404
        
        # Generate report
        report_format = request.args.get('format', 'json')
        report_mode = request.args.get('mode', 'full')
        reveal = request.args.get('reveal', 'false').lower() == 'true'
        
        # Create temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=f'.{report_format}', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            if report_format == 'json':
                with open(tmp_path, 'w') as f:
                    json.dump(result.store.to_dict(reveal), f, indent=2, default=str)
            elif report_format == 'html':
                if report_mode == 'simple':
                    generate_plain_english_report(result, tmp_path, reveal, 'html')
                else:
                    generate_report(result, tmp_path, 'full', reveal, 'html')
            elif report_format == 'pdf':
                if report_mode == 'simple':
                    generate_plain_english_report(result, tmp_path, reveal, 'pdf')
                else:
                    generate_report(result, tmp_path, 'full', reveal, 'pdf')
            else:
                return "Unsupported format", 400
            
            # Send file
            return send_file(
                tmp_path,
                as_attachment=True,
                download_name=f"secretscout_report_{scan_id}.{report_format}"
            )
            
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    @app.route('/download/walkthrough/<scan_id>', methods=['GET'])
    def download_walkthrough(scan_id):
        """Download plain-English walkthrough for a scan"""
        scan = app.active_scans.get(scan_id)
        if not scan:
            return "Scan not found", 404
        
        if scan.get('status') != 'completed':
            return "Scan not completed yet", 400
        
        result = scan.get('result')
        if not result:
            return "No results available", 404
        
        # Generate plain English report
        report_format = request.args.get('format', 'html')
        reveal = request.args.get('reveal', 'false').lower() == 'true'
        
        # Create temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=f'.{report_format}', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        try:
            generate_plain_english_report(result, tmp_path, reveal, report_format)
            
            # Send file
            return send_file(
                tmp_path,
                as_attachment=True,
                download_name=f"secretscout_walkthrough_{scan_id}.{report_format}"
            )
            
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    @app.route('/history')
    def scan_history():
        """Get scan history"""
        return jsonify({
            'scans': app.scan_history[-50:] if hasattr(app, 'scan_history') else []
        })
    
    @app.route('/clear-history', methods=['POST'])
    def clear_history():
        """Clear scan history"""
        app.scan_history = []
        return jsonify({'success': True, 'message': 'History cleared'})


def parse_techniques(techniques_str: str) -> List[str]:
    """Parse comma-separated techniques string"""
    if not techniques_str:
        return []
    
    return [t.strip() for t in techniques_str.split(',') if t.strip()]


def create_dashboard_template():
    """Create the dashboard HTML template"""
    template_dir = Path(__file__).parent / 'templates'
    template_dir.mkdir(exist_ok=True)
    
    template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecretScout PRO - Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            color: #667eea;
            font-size: 2em;
            margin: 0;
        }
        
        .header .subtitle {
            color: #666;
            font-size: 1.1em;
        }
        
        .nav {
            display: flex;
            gap: 20px;
        }
        
        .nav a {
            color: #667eea;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .nav a:hover {
            background: #667eea;
            color: white;
        }
        
        .main-content {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 30px;
        }
        
        .sidebar {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            height: fit-content;
        }
        
        .sidebar h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.3em;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-group input[type="text"],
        .form-group input[type="url"],
        .form-group input[type="number"],
        .form-group input[type="password"],
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .checkbox-group input[type="checkbox"] {
            width: auto;
            height: 18px;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 8px;
            font-size: 1em;
            cursor: pointer;
            transition: all 0.3s;
            width: 100%;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        
        .btn-secondary {
            background: white;
            color: #667eea;
            border: 2px solid #667eea;
        }
        
        .btn-secondary:hover {
            background: #667eea;
            color: white;
        }
        
        .content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .content h2 {
            color: #667eea;
            margin-bottom: 20px;
        }
        
        .scan-form {
            display: grid;
            gap: 20px;
        }
        
        .techniques-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 10px;
        }
        
        .technique-option {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .technique-option input[type="checkbox"] {
            width: auto;
        }
        
        .technique-option label {
            margin: 0;
            font-weight: normal;
            cursor: pointer;
        }
        
        .results-section {
            margin-top: 30px;
        }
        
        .scan-status {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        
        .status-badge {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        
        .status-running {
            background: #007bff;
            color: white;
        }
        
        .status-completed {
            background: #28a745;
            color: white;
        }
        
        .status-failed {
            background: #dc3545;
            color: white;
        }
        
        .status-cancelled {
            background: #6c757d;
            color: white;
        }
        
        .progress-bar {
            width: 100%;
            height: 20px;
            background: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 0.3s;
        }
        
        .findings-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        
        .summary-card h3 {
            color: #667eea;
            margin-bottom: 5px;
        }
        
        .summary-card p {
            color: #666;
            margin: 0;
        }
        
        .findings-list {
            margin-top: 20px;
        }
        
        .finding-item {
            border: 1px solid #e0e0e0;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .finding-item:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-title {
            font-weight: bold;
            color: #333;
        }
        
        .finding-severity {
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.8em;
            color: white;
        }
        
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; }
        .severity-info { background: #17a2b8; }
        
        .finding-details {
            font-size: 0.9em;
            color: #666;
        }
        
        .history-section {
            margin-top: 30px;
        }
        
        .history-item {
            padding: 15px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .history-item:hover {
            background: #f8f9fa;
        }
        
        .download-buttons {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }
        
        .download-buttons .btn {
            width: auto;
            padding: 8px 15px;
        }
        
        .toggle-secrets {
            display: flex;
            align-items: center;
            gap: 10px;
            margin: 20px 0;
        }
        
        .toggle-secrets label {
            cursor: pointer;
        }
        
        .toggle-secrets input[type="checkbox"] {
            width: auto;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .error-message {
            color: #dc3545;
            background: #f8d7da;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }
        
        @media (max-width: 768px) {
            .main-content {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                text-align: center;
                gap: 15px;
            }
            
            .nav {
                flex-wrap: wrap;
                justify-content: center;
            }
            
            .techniques-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>🔍 SecretScout PRO</h1>
                <p class="subtitle">Professional API Vulnerability Detection</p>
            </div>
            <div class="nav">
                <a href="/">Dashboard</a>
                <a href="#history">History</a>
                <a href="#settings">Settings</a>
            </div>
        </div>
        
        <div class="main-content">
            <div class="sidebar">
                <h2>🎯 Quick Scan</h2>
                <form id="scanForm" class="scan-form">
                    <div class="form-group">
                        <label for="url">Website URL</label>
                        <input type="url" id="url" name="url" placeholder="https://example.com" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="project_path">Local Project Path (optional)</label>
                        <input type="text" id="project_path" name="project_path" placeholder="/path/to/project">
                    </div>
                    
                    <div class="form-group">
                        <label>Techniques</label>
                        <div class="techniques-grid">
                            {% for tech_id, tech_info in techniques.items() %}
                            <div class="technique-option">
                                <input type="checkbox" id="tech_{{ tech_id }}" name="techniques" value="{{ tech_id }}" checked>
                                <label for="tech_{{ tech_id }}">{{ tech_id }} - {{ tech_info.name }}</label>
                            </div>
                            {% endfor %}
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="crawl" name="crawl" checked>
                            <label for="crawl">Crawl entire website</label>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="validate_keys" name="validate_keys">
                            <label for="validate_keys">Validate API keys (read-only)</label>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="reveal_secrets" name="reveal_secrets">
                            <label for="reveal_secrets">Show full secret values</label>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="max_pages">Max Pages (if crawling)</label>
                        <input type="number" id="max_pages" name="max_pages" value="50" min="1" max="1000">
                    </div>
                    
                    <button type="submit" class="btn">Start Scan</button>
                </form>
            </div>
            
            <div class="content">
                <h2>📊 Dashboard</h2>
                
                <div id="scanStatus" class="results-section" style="display: none;">
                    <div class="scan-status">
                        <h3>Scan in Progress</h3>
                        <span id="statusBadge" class="status-badge status-running">RUNNING</span>
                    </div>
                    <div class="progress-bar">
                        <div id="progressFill" class="progress-fill" style="width: 0%"></div>
                    </div>
                    <p id="progressText">Starting scan...</p>
                    <button id="cancelScan" class="btn btn-secondary" style="display: none;">Cancel Scan</button>
                </div>
                
                <div id="scanResults" class="results-section" style="display: none;">
                    <div class="scan-status">
                        <h3>Scan Results</h3>
                        <span id="resultStatus" class="status-badge"></span>
                    </div>
                    
                    <div id="summaryCards" class="findings-summary"></div>
                    
                    <div class="toggle-secrets">
                        <input type="checkbox" id="toggleSecrets">
                        <label for="toggleSecrets">Show full secret values</label>
                    </div>
                    
                    <div id="findingsList" class="findings-list"></div>
                    
                    <div class="download-buttons">
                        <button id="downloadJson" class="btn">Download JSON</button>
                        <button id="downloadHtml" class="btn">Download HTML</button>
                        <button id="downloadPdf" class="btn">Download PDF</button>
                        <button id="downloadWalkthrough" class="btn btn-secondary">Plain English Report</button>
                    </div>
                </div>
                
                <div id="historySection" class="history-section">
                    <h2 id="history">📜 Scan History</h2>
                    <div id="historyList"></div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let currentScanId = null;
        let revealSecrets = false;
        
        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadHistory();
            
            // Handle form submission
            document.getElementById('scanForm').addEventListener('submit', function(e) {
                e.preventDefault();
                startScan();
            });
            
            // Handle toggle secrets
            document.getElementById('toggleSecrets').addEventListener('change', function() {
                revealSecrets = this.checked;
                updateFindingsDisplay();
            });
        });
        
        function startScan() {
            const form = document.getElementById('scanForm');
            const formData = new FormData(form);
            
            // Get selected techniques
            const techniques = [];
            const checkboxes = document.querySelectorAll('input[name="techniques"]:checked');
            checkboxes.forEach(cb => techniques.push(cb.value));
            
            // Prepare data
            const data = {
                url: formData.get('url'),
                project_path: formData.get('project_path'),
                techniques: techniques.join(','),
                crawl: formData.get('crawl') === 'on',
                validate_keys: formData.get('validate_keys') === 'on',
                reveal_secrets: formData.get('reveal_secrets') === 'on',
                max_pages: formData.get('max_pages') || 50,
                max_depth: 5,
                same_host_only: true,
                delay: 0.1,
                max_concurrent: 10
            };
            
            // Show scan status
            document.getElementById('scanStatus').style.display = 'block';
            document.getElementById('scanResults').style.display = 'none';
            document.getElementById('progressFill').style.width = '0%';
            document.getElementById('progressText').textContent = 'Starting scan...';
            document.getElementById('cancelScan').style.display = 'inline-block';
            
            // Start scan
            fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams(data)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    currentScanId = data.scan_id;
                    pollScanStatus();
                } else {
                    throw new Error(data.error || 'Failed to start scan');
                }
            })
            .catch(error => {
                alert('Error starting scan: ' + error.message);
                document.getElementById('scanStatus').style.display = 'none';
            });
        }
        
        function pollScanStatus() {
            if (!currentScanId) return;
            
            fetch(`/scan/${currentScanId}/status`)
            .then(response => response.json())
            .then(data => {
                if (data.status === 'running') {
                    // Update progress
                    document.getElementById('statusBadge').className = 'status-badge status-running';
                    document.getElementById('statusBadge').textContent = 'RUNNING';
                    document.getElementById('progressText').textContent = `Scanning... (${data.progress.visited || 0} pages visited)`;
                    
                    // Update progress bar
                    const progress = data.progress.visited ? Math.min(100, (data.progress.visited / 50) * 100) : 0;
                    document.getElementById('progressFill').style.width = `${progress}%`;
                    
                    // Poll again
                    setTimeout(pollScanStatus, 2000);
                } else if (data.status === 'completed') {
                    // Scan completed
                    document.getElementById('statusBadge').className = 'status-badge status-completed';
                    document.getElementById('statusBadge').textContent = 'COMPLETED';
                    document.getElementById('progressText').textContent = 'Scan completed!';
                    document.getElementById('progressFill').style.width = '100%';
                    document.getElementById('cancelScan').style.display = 'none';
                    
                    // Load results
                    loadScanResults(currentScanId);
                } else if (data.status === 'failed' || data.status === 'cancelled') {
                    // Scan failed or cancelled
                    document.getElementById('statusBadge').className = `status-badge status-${data.status}`;
                    document.getElementById('statusBadge').textContent = data.status.toUpperCase();
                    document.getElementById('progressText').textContent = 'Scan did not complete.';
                    document.getElementById('cancelScan').style.display = 'none';
                }
            })
            .catch(error => {
                console.error('Error polling status:', error);
            });
        }
        
        function loadScanResults(scanId) {
            fetch(`/scan/${scanId}/summary`)
            .then(response => response.json())
            .then(summary => {
                // Update summary cards
                const summaryHtml = `
                    <div class="summary-card">
                        <h3>${summary.total_findings || 0}</h3>
                        <p>Total Findings</p>
                    </div>
                    <div class="summary-card">
                        <h3><span class="risk-badge risk-${summary.risk_level || 'info'}">${(summary.risk_level || 'info').toUpperCase()}</span></h3>
                        <p>Risk Level</p>
                    </div>
                    <div class="summary-card">
                        <h3>${summary.risk_score || 0}</h3>
                        <p>Risk Score</p>
                    </div>
                    <div class="summary-card">
                        <h3>${summary.live_keys_confirmed || 0}</h3>
                        <p>Live Keys Confirmed</p>
                    </div>
                `;
                document.getElementById('summaryCards').innerHTML = summaryHtml;
                
                // Show results section
                document.getElementById('scanStatus').style.display = 'none';
                document.getElementById('scanResults').style.display = 'block';
                
                // Load detailed findings
                loadDetailedFindings(scanId);
                
                // Load history
                loadHistory();
            })
            .catch(error => {
                console.error('Error loading summary:', error);
            });
        }
        
        function loadDetailedFindings(scanId) {
            fetch(`/scan/${scanId}/results`)
            .then(response => response.json())
            .then(data => {
                const findings = data.findings || [];
                let html = '';
                
                findings.forEach(finding => {
                    const secretValue = revealSecrets && finding.secret_value ? 
                        finding.secret_value : finding.redacted_value;
                    
                    html += `
                        <div class="finding-item">
                            <div class="finding-header">
                                <div class="finding-title">${finding.title}</div>
                                <span class="finding-severity severity-${finding.severity}">${finding.severity.toUpperCase()}</span>
                            </div>
                            <div class="finding-details">
                                <p><strong>Technique:</strong> ${finding.technique} - ${finding.technique_name}</p>
                                <p><strong>URL:</strong> ${finding.url}</p>
                                ${secretValue ? `<p><strong>Secret:</strong> <code>${secretValue}</code></p>` : ''}
                                <p><strong>Impact:</strong> ${finding.impact}</p>
                                <p><strong>Remediation:</strong> ${finding.remediation}</p>
                                ${finding.confirmed_live ? '<p><strong style="color: #dc3545;">STATUS: CONFIRMED LIVE</strong></p>' : ''}
                            </div>
                        </div>
                    `;
                });
                
                document.getElementById('findingsList').innerHTML = html || '<p>No findings discovered.</p>';
                
                // Set up download buttons
                setupDownloadButtons(scanId);
            })
            .catch(error => {
                console.error('Error loading findings:', error);
            });
        }
        
        function updateFindingsDisplay() {
            if (!currentScanId) return;
            loadDetailedFindings(currentScanId);
        }
        
        function setupDownloadButtons(scanId) {
            document.getElementById('downloadJson').onclick = function() {
                window.location.href = `/download/report/${scanId}?format=json&reveal=${revealSecrets}`;
            };
            
            document.getElementById('downloadHtml').onclick = function() {
                window.location.href = `/download/report/${scanId}?format=html&reveal=${revealSecrets}`;
            };
            
            document.getElementById('downloadPdf').onclick = function() {
                window.location.href = `/download/report/${scanId}?format=pdf&reveal=${revealSecrets}`;
            };
            
            document.getElementById('downloadWalkthrough').onclick = function() {
                window.location.href = `/download/walkthrough/${scanId}?format=html&reveal=${revealSecrets}`;
            };
        }
        
        function loadHistory() {
            fetch('/history')
            .then(response => response.json())
            .then(data => {
                const scans = data.scans || [];
                let html = '';
                
                scans.forEach(scan => {
                    html += `
                        <div class="history-item">
                            <div>
                                <strong>${scan.target}</strong>
                                <p style="margin: 5px 0 0 0; color: #666; font-size: 0.9em;">
                                    ${new Date(scan.start_time).toLocaleString()} - ${new Date(scan.end_time).toLocaleString()}
                                </p>
                            </div>
                            <div>
                                <span class="status-badge status-${scan.findings_count > 0 ? 'completed' : 'info'}">
                                    ${scan.findings_count} findings
                                </span>
                                <span class="status-badge status-${scan.risk_level || 'info'}" style="margin-left: 10px;">
                                    ${(scan.risk_level || 'info').toUpperCase()}
                                </span>
                            </div>
                        </div>
                    `;
                });
                
                document.getElementById('historyList').innerHTML = html || '<p>No scan history available.</p>';
            })
            .catch(error => {
                console.error('Error loading history:', error);
            });
        }
        
        function cancelScan() {
            if (!currentScanId) return;
            
            fetch(`/scan/${currentScanId}/cancel`, {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('statusBadge').className = 'status-badge status-cancelled';
                    document.getElementById('statusBadge').textContent = 'CANCELLED';
                    document.getElementById('progressText').textContent = 'Scan cancelled.';
                    document.getElementById('cancelScan').style.display = 'none';
                }
            })
            .catch(error => {
                console.error('Error cancelling scan:', error);
            });
        }
        
        // Set up cancel button
        document.getElementById('cancelScan').addEventListener('click', cancelScan);
    </script>
</body>
</html>"""
    
    with open(template_dir / 'dashboard.html', 'w') as f:
        f.write(template_content)
    
    print(f"Dashboard template created at: {template_dir / 'dashboard.html'}")


# Create the template when this module is imported
create_dashboard_template()