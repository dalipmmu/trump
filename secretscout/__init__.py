"""
SecretScout PRO - Professional API Vulnerability Detection Tool
A comprehensive tool for finding API glitches, leaks, private keys, and security flaws
"""

__version__ = "2.0.0"
__author__ = "SecretScout Team"
__description__ = "Professional API Vulnerability Detection Tool"

# Technique IDs
TECHNIQUES = {
    "t1": {"name": "Hardcoded client-side secrets", "description": "API keys in HTML/JS/CSS sent to the browser"},
    "t2": {"name": "Exposed source maps", "description": "Find .js.map files that rebuild source + hide secrets"},
    "t3": {"name": "Exposed env/config files", "description": "Scan for .env, .git/config, .npmrc, .aws/credentials"},
    "t4": {"name": "Malicious dependencies", "description": "Known-bad/typosquat packages + auth.json exfiltration"},
    "t5": {"name": "Exposed .git repository", "description": "Live .git/ dir → full source + history recoverable"},
    "t6": {"name": "Debug/admin endpoints", "description": "Spring Boot /actuator/env, Go expvar/pprof, phpinfo, etc."},
    "t7": {"name": "Historical exposure (Wayback)", "description": "Archive.org CDX → fetches archived JS/.env/config snapshots"},
    "t8": {"name": "Security headers & TLS posture", "description": "Missing/weak CSP, HSTS, X-Frame-Options, etc."},
    "t9": {"name": "Admin / database / API surfaces", "description": "Reachable admin panels, SQL dumps, open Firebase/Elasticsearch"},
    "t10": {"name": "Subdomain / attack-surface enumeration", "description": "Pulls subdomains from Certificate Transparency logs"},
    "t11": {"name": "API endpoint discovery", "description": "Find all API endpoints and test for vulnerabilities"},
    "t12": {"name": "API key validation", "description": "Live validation of discovered API keys"},
    "t13": {"name": "CORS misconfiguration", "description": "Detect dangerous CORS configurations"},
    "t14": {"name": "Rate limit testing", "description": "Check for missing rate limiting on APIs"},
    "t15": {"name": "Error message analysis", "description": "Find information leaks in error responses"},
    # NSA-Grade Advanced Techniques
    "t16": {"name": "JavaScript Variable Tracing", "description": "Trace JS variables with secret-like names and high-entropy values"},
    "t17": {"name": "GitHub Token Deep Scan", "description": "Advanced detection of all GitHub token types including fine-grained PATs"},
    "t18": {"name": "Database Connection String Deep Scan", "description": "Detect database credentials in connection strings (MongoDB, MySQL, PostgreSQL, Redis)"},
}

# All technique IDs
ALL_TECHNIQUE_IDS = list(TECHNIQUES.keys())

# Import key modules
from .patterns import SECRET_PATTERNS, SENSITIVE_PATTERNS
from .storage import Finding, Severity, DataClass, FindingStore

__all__ = [
    'TECHNIQUES',
    'ALL_TECHNIQUE_IDS',
    'SECRET_PATTERNS',
    'SENSITIVE_PATTERNS',
    'Finding',
    'Severity',
    'DataClass',
    'FindingStore',
    '__version__',
    '__author__',
    '__description__'
]