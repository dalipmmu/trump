"""
Secret Pattern Detection Module
NSA-Grade Advanced pattern matching for API keys, secrets, and sensitive data
"""

import re
import base64
import math
import json
from typing import Dict, List, Tuple, Pattern, Optional, Callable
from dataclasses import dataclass, field


@dataclass
class SecretPattern:
    """Pattern definition for secret detection"""
    name: str
    pattern: Pattern
    secret_group: int = 1
    severity: str = "critical"
    data_class: str = "Credential"
    provider: Optional[str] = None
    allowlist: bool = False  # If True, this is public by design
    entropy_threshold: float = 3.0  # Minimum entropy for generic patterns
    validator: Optional[Callable[[str], bool]] = None  # Custom validation function
    context_keywords: List[str] = field(default_factory=list)  # Keywords that must be nearby
    max_distance: int = 200  # Max characters to look for context keywords


# High-entropy string detection using Shannon entropy
def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    if not data:
        return 0.0
    
    # Focus on alphanumeric characters only
    alphanumeric = re.sub(r'[^a-zA-Z0-9]', '', data)
    if len(alphanumeric) < 4:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = float(alphanumeric.count(chr(x))) / len(alphanumeric)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy


def is_high_entropy_string(text: str, threshold: float = 3.5) -> bool:
    """Check if a string has high entropy (likely a secret)"""
    if not text or len(text) < 8:
        return False
    
    # Common patterns that indicate secrets
    if re.search(r'[A-Za-z0-9]{20,}', text):
        entropy = calculate_shannon_entropy(text)
        return entropy >= threshold
    
    return False


# ============================================================================
# NSA-GRADE RAZORPAY VALIDATION
# ============================================================================

def validate_razorpay_secret(secret: str) -> bool:
    """
    NSA-Grade Razorpay secret validation.
    Real Razorpay secrets have:
    - Exactly 32 lowercase hex chars
    - High entropy (>3.8)
    - No repeating patterns (not like 'aaaa...')
    - Not sequential (not like '1234...')
    - Not all same character
    """
    if not secret:
        return False
    
    # Must be exactly 32 characters
    if len(secret) != 32:
        return False
    
    # Must be all lowercase hex
    if not all(c in '0123456789abcdef' for c in secret):
        return False
    
    # Must have high entropy
    entropy = calculate_shannon_entropy(secret)
    if entropy < 3.8:
        return False
    
    # Check for sequential patterns (common in fake/test keys)
    sequential_patterns = [
        '0123', '1234', '2345', '3456', '4567', '5678', '6789',
        '789a', '89ab', '9abc', 'abcdef', 'fedcba', 'edcba', 'dcba',
        '0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777',
        '8888', '9999', 'aaaa', 'bbbb', 'cccc', 'dddd', 'eeee', 'ffff'
    ]
    
    for pattern in sequential_patterns:
        if pattern in secret.lower():
            return False
    
    # Check for repeating characters (4+ same chars in a row)
    if re.search(r'(.)\1{3,}', secret):
        return False
    
    # Check for common test patterns
    test_patterns = [
        'test', 'demo', 'sample', 'example', 'placeholder',
        'changeme', 'password', 'secret', 'key', '123456',
        'abcdef', 'fedcba', 'qwerty', 'asdfgh', 'zxcvbn'
    ]
    
    secret_lower = secret.lower()
    for pattern in test_patterns:
        if pattern in secret_lower:
            return False
    
    return True


# ============================================================================
# CONTEXT-AWARE SCANNING (NSA SMART DETECTION RULES)
# ============================================================================

def is_in_comment(text: str, position: int) -> bool:
    """Check if a position is inside a comment"""
    # Simple check for // and /* */ comments
    before = text[:position]
    
    # Check for // comment
    last_newline = before.rfind('\n')
    line_start = before[last_newline:] if last_newline != -1 else before
    if '//' in line_start:
        return True
    
    # Check for /* */ comment
    if before.count('/*') > before.count('*/'):
        return True
    
    return False


def is_in_string_literal(text: str, position: int) -> bool:
    """Check if a position is inside a string literal"""
    before = text[:position]
    
    # Count quotes
    single_quotes = before.count("'")
    double_quotes = before.count('"')
    
    # If odd number of quotes, we're inside a string
    if single_quotes % 2 == 1 or double_quotes % 2 == 1:
        return True
    
    return False


def extract_variable_name(text: str, position: int) -> Optional[str]:
    """Extract the variable name at a given position"""
    # Look backwards for variable declaration
    before = text[:position]
    
    # Pattern: var x = or x = or const x =
    var_pattern = re.compile(r'(?:var|let|const|function)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*$')
    match = var_pattern.search(before[max(0, position-100):])
    
    if match:
        return match.group(1)
    
    return None


def is_real_secret(match: re.Match, text: str, pattern: SecretPattern) -> bool:
    """
    NSA-Grade context analysis to determine if a match is a real secret
    """
    secret_value = match.group(0)
    match_start = match.start()
    
    # Rule 1: Check if it's in a comment
    if is_in_comment(text, match_start):
        return False
    
    # Rule 2: Check if it's in a string literal
    if is_in_string_literal(text, match_start):
        # But if the variable name suggests it's a secret, keep it
        var_name = extract_variable_name(text, match_start)
        if var_name:
            secret_keywords = ['key', 'secret', 'token', 'password', 'api', 'auth', 'credential', 'private']
            if any(keyword in var_name.lower() for keyword in secret_keywords):
                return True
        return False
    
    # Rule 3: Check if it's in a test file
    if 'test' in text.lower() or 'spec' in text.lower():
        # But only skip if it's clearly test data
        if 'test' in secret_value.lower() or 'example' in secret_value.lower():
            return False
    
    # Rule 4: Check if it's in documentation
    if text.count('\n') > 50:
        if '.md' in text or '.txt' in text or 'readme' in text.lower():
            return False
    
    # Rule 5: Check entropy - real secrets have HIGH entropy
    if pattern.entropy_threshold > 0:
        if not is_high_entropy_string(secret_value, pattern.entropy_threshold):
            return False
    else:
        # Default entropy check
        if calculate_shannon_entropy(secret_value) < 3.0:
            return False
    
    # Rule 6: Check for placeholder values
    placeholder_patterns = [
        'example', 'test', 'placeholder', 'your_', 'xxx', 'yyy', 'zzz',
        'sample', 'demo', 'dummy', 'fake', 'changeme', 'password123',
        '123456', 'qwerty', 'abc123', 'letmein', 'admin', 'guest'
    ]
    
    secret_lower = secret_value.lower()
    for placeholder in placeholder_patterns:
        if placeholder in secret_lower:
            return False
    
    # Rule 7: Check for sequential/repeating patterns
    if re.search(r'(?:0123|1234|2345|3456|4567|5678|6789|7890|abcdef|fedcba)', secret_lower):
        return False
    if re.search(r'(.)\1{4,}', secret_value):  # 5+ repeating chars
        return False
    
    # Rule 8: Custom validator if provided
    if pattern.validator:
        try:
            if not pattern.validator(secret_value):
                return False
        except Exception:
            return False
    
    # Rule 9: Context keywords check
    if pattern.context_keywords:
        text_lower = text.lower()
        match_end = match.end()
        
        # Look for keywords within max_distance characters
        search_start = max(0, match_start - pattern.max_distance)
        search_end = min(len(text), match_end + pattern.max_distance)
        nearby_text = text_lower[search_start:search_end]
        
        # At least one keyword must be present
        if not any(keyword in nearby_text for keyword in pattern.context_keywords):
            return False
    
    return True





# API Key Patterns
SECRET_PATTERNS: List[SecretPattern] = [
    # OpenAI
    SecretPattern(
        name="OpenAI API Key",
        pattern=re.compile(r'sk-[a-zA-Z0-9]{20,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="openai"
    ),
    
    # Anthropic (Claude)
    SecretPattern(
        name="Anthropic API Key",
        pattern=re.compile(r'sk-ant-[a-zA-Z0-9-]{20,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="anthropic"
    ),
    

    # Razorpay Keys (Critical for bounty hunting - NSA Grade)
    SecretPattern(
        name="Razorpay Key ID",
        pattern=re.compile(r'rzp_(live|test)_[a-zA-Z0-9]{16,}', re.IGNORECASE),
        severity="high",
        data_class="Financial",
        provider="razorpay",
        allowlist=True,  # Key ID is public by design
        context_keywords=["razorpay", "rzp_", "payment", "gateway"],
        max_distance=100
    ),
    SecretPattern(
        name="Razorpay Key Secret",
        pattern=re.compile(r'\b[a-f0-9]{32}\b'),
        severity="critical",
        data_class="Financial",
        provider="razorpay",
        validator=validate_razorpay_secret,
        context_keywords=["razorpay", "rzp_", "payment", "gateway", "secret", "key"],
        max_distance=100
    ),
    
    # Google API Keys
    SecretPattern(
        name="Google API Key",
        pattern=re.compile(r'AIza[0-9A-Za-z\-_]{35,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="google"
    ),
    
    # Google Service Account JSON
    SecretPattern(
        name="Google Service Account",
        pattern=re.compile(r'"private_key_id"\s*:\s*"[^"]+"', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="google"
    ),
    
    # Slack Tokens
    SecretPattern(
        name="Slack Bot Token",
        pattern=re.compile(r'xoxb-[0-9a-zA-Z-]{24,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="slack"
    ),
    SecretPattern(
        name="Slack User Token",
        pattern=re.compile(r'xoxp-[0-9a-zA-Z-]{24,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="slack"
    ),
    
    # SendGrid API Key
    SecretPattern(
        name="SendGrid API Key",
        pattern=re.compile(r'SG\.[a-zA-Z0-9\-_]{22,}\.[a-zA-Z0-9\-_]{22,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="sendgrid"
    ),
    
    # Mailgun API Key
    SecretPattern(
        name="Mailgun API Key",
        pattern=re.compile(r'key-[a-zA-Z0-9]{32,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="mailgun"
    ),
    
    # Twilio API Key
    SecretPattern(
        name="Twilio API Key",
        pattern=re.compile(r'SK[a-fA-F0-9]{32,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="twilio"
    ),
    
    # Hugging Face Token
    SecretPattern(
        name="Hugging Face Token",
        pattern=re.compile(r'hf_[a-zA-Z0-9]{32,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="huggingface"
    ),
    
    # Groq API Key
    SecretPattern(
        name="Groq API Key",
        pattern=re.compile(r'gsk_[a-zA-Z0-9]{40,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="groq"
    ),
    
    # Replicate API Key
    SecretPattern(
        name="Replicate API Key",
        pattern=re.compile(r'r8_[a-zA-Z0-9]{40,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="replicate"
    ),
    
    # Perplexity API Key
    SecretPattern(
        name="Perplexity API Key",
        pattern=re.compile(r'ppx-[a-zA-Z0-9\-_]{40,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="perplexity"
    ),
    

    # Sentry DSN
    SecretPattern(
        name="Sentry DSN",
        pattern=re.compile(r'https://[a-zA-Z0-9@]+@[a-zA-Z0-9\.]+/\d+', re.IGNORECASE),
        severity="medium",
        data_class="Credential",
        provider="sentry",
        allowlist=True  # Public by design
    ),
    

    # JWT Tokens
    SecretPattern(
        name="JWT Token",
        pattern=re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+', re.IGNORECASE),
        severity="high",
        data_class="Credential",
        provider="jwt"
    ),
    
    # Private Keys (PEM format)
    SecretPattern(
        name="Private Key (PEM)",
        pattern=re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----', re.IGNORECASE),
        severity="critical",
        data_class="Credential"
    ),
    
    # SSH Private Key
    SecretPattern(
        name="SSH Private Key",
        pattern=re.compile(r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', re.IGNORECASE),
        severity="critical",
        data_class="Credential"
    ),
]


# Sensitive Data Patterns (PII, Financial, etc.)
SENSITIVE_PATTERNS: List[SecretPattern] = [
    # Social Security Numbers (US)
    SecretPattern(
        name="US Social Security Number",
        pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b', re.IGNORECASE),
        severity="critical",
        data_class="PII"
    ),
    
    # Database Connection Strings
    SecretPattern(
        name="Database Connection String",
        pattern=re.compile(r'mongodb:\/\/[^\s]+|mysql:\/\/[^\s]+|postgresql:\/\/[^\s]+|redis:\/\/[^\s]+', re.IGNORECASE),
        severity="critical",
        data_class="Infra"
    ),
    

    # Internal IP Addresses
    SecretPattern(
        name="Internal IP Address",
        pattern=re.compile(r'\b(?:10|127|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.\d{1,3}\.\d{1,3}\b', re.IGNORECASE),
        severity="medium",
        data_class="Infra"
    ),
    
    # Cloud Metadata References
    SecretPattern(
        name="Cloud Metadata Reference",
        pattern=re.compile(r'169\.254\.169\.254|http://metadata\.google\.internal|http://169\.254\.170\.2', re.IGNORECASE),
        severity="high",
        data_class="Infra"
    ),
]


# Debug/Endpoint Patterns
DEBUG_ENDPOINT_PATTERNS = [
    # Spring Boot Actuator
    r'/actuator/env',
    r'/actuator/heapdump',
    r'/actuator/mappings',
    r'/actuator/beans',
    r'/actuator/configprops',
    
    # Go Debug
    r'/debug/pprof',
    r'/debug/vars',
    r'/debug/expvar',
    
    # PHP
    r'/phpinfo\.php',
    r'/phpinfo',
    
    # Apache
    r'/server-status',
    r'/server-info',
    
    # Symfony
    r'/_profiler',
    r'/_wdt',
    
    # Prometheus
    r'/metrics',
    
    # Django
    r'/admin/',
    r'/admin/login/',
    
    # WordPress
    r'/wp-admin/',
    r'/wp-login\.php',
    
    # phpMyAdmin
    r'/phpmyadmin/',
    r'/pma/',
    
    # Adminer
    r'/adminer/',
    
    # Tomcat
    r'/manager/html',
    r'/host-manager/html',
    
    # Jenkins
    r'/jenkins/',
    r'/job/',
    
    # GitLab
    r'/gitlab/',
    r'/admin/',
    
    # Firebase
    r'/\.json$',
    r'firebaseio\.com',
    
    # Elasticsearch
    r':9200/',
    r'/elasticsearch/',
    
    # Swagger/OpenAPI
    r'/swagger/',
    r'/api-docs',
    r'/openapi\.json',
    r'/swagger\.json',
    
    # GraphQL
    r'/graphql',
    r'/graphiql',
    
    # Robots.txt
    r'/robots\.txt',
    
    # Sitemap
    r'/sitemap\.xml',
]


# Config File Patterns
CONFIG_FILE_PATTERNS = [
    r'\.env',
    r'\.env\.local',
    r'\.env\.prod',
    r'\.env\.development',
    r'\.git/config',
    r'\.git/credentials',
    r'\.npmrc',
    r'config\.json',
    r'config\.yaml',
    r'config\.yml',
    r'secrets\.json',
    r'secrets\.yaml',
    r'auth\.json',
    r'private\.key',
    r'id_rsa',
    r'web\.config',
    r'app\.config',
    r'settings\.py',
    r'\.htpasswd',
    r'\.htaccess',
]


# Source Map Patterns
SOURCE_MAP_PATTERNS = [
    r'\.js\.map$',
    r'\.css\.map$',
    r'\.map$',
]


# Git Repository Patterns
GIT_PATTERNS = [
    r'/\.git/',
    r'/\.git$',
    r'/\.git/HEAD',
    r'/\.git/config',
    r'/\.git/index',
    r'/\.git/logs/',
    r'/\.git/objects/',
    r'/\.git/refs/',
]


def find_secrets_in_text(text: str, context: str = "") -> List[Dict]:
    """
    Find all secrets in the given text using NSA-grade pattern matching and context analysis
    
    Args:
        text: The text to scan
        context: Additional context (e.g., URL, file path)
    
    Returns:
        List of found secrets with metadata
    """
    findings = []
    
    # Check all secret patterns
    for pattern in SECRET_PATTERNS:
        for match in pattern.pattern.finditer(text):
            try:
                # Try to get the secret group, fall back to group 0 if it doesn't exist
                if pattern.secret_group > 0:
                    try:
                        secret_value = match.group(pattern.secret_group)
                    except IndexError:
                        secret_value = match.group(0)
                else:
                    secret_value = match.group(0)
            except IndexError:
                secret_value = match.group(0)
            
            # NSA-Grade: Use context-aware filtering
            if not is_real_secret(match, text, pattern):
                continue
            
            finding = {
                'type': pattern.name,
                'value': secret_value,
                'redacted_value': redact_secret(secret_value),
                'severity': pattern.severity,
                'data_class': pattern.data_class,
                'provider': pattern.provider,
                'allowlist': pattern.allowlist,
                'context': context,
                'pattern': pattern.name
            }
            findings.append(finding)
    
    # Check sensitive data patterns
    for pattern in SENSITIVE_PATTERNS:
        for match in pattern.pattern.finditer(text):
            secret_value = match.group(0)
            
            # NSA-Grade: Apply basic context filtering to sensitive patterns too
            if is_in_comment(text, match.start()):
                continue
            if is_in_string_literal(text, match.start()):
                continue
            
            # Check for placeholders
            placeholder_patterns = [
                'example', 'test', 'placeholder', 'your_', 'xxx', 'yyy', 'zzz',
                'sample', 'demo', 'dummy', 'fake'
            ]
            if any(p in secret_value.lower() for p in placeholder_patterns):
                continue
            
            finding = {
                'type': pattern.name,
                'value': secret_value,
                'redacted_value': redact_secret(secret_value),
                'severity': pattern.severity,
                'data_class': pattern.data_class,
                'provider': pattern.provider if hasattr(pattern, 'provider') else None,
                'allowlist': False,
                'context': context,
                'pattern': pattern.name
            }
            findings.append(finding)
    
    return findings


def redact_secret(secret: str, max_length: int = 8) -> str:
    """Redact a secret, showing only first few characters"""
    if len(secret) <= max_length * 2:
        return secret[:max_length] + '...' if len(secret) > max_length else secret
    return secret[:max_length] + '...' + secret[-max_length:]


def extract_api_keys_from_jwt(token: str) -> Dict:
    """Extract and decode JWT token information"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        
        # Decode header
        header_b64 = parts[0]
        header_b64 += '=' * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        
        # Decode payload
        payload_b64 = parts[1]
        payload_b64 += '=' * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        return {
            'header': header,
            'payload': payload,
            'signature': parts[2],
            'is_valid': True
        }
    except Exception:
        return {'is_valid': False}


def check_jwt_vulnerabilities(jwt_data: Dict) -> List[Dict]:
    """Check JWT for common vulnerabilities"""
    vulnerabilities = []
    
    if not jwt_data.get('is_valid'):
        return vulnerabilities
    
    header = jwt_data.get('header', {})
    payload = jwt_data.get('payload', {})
    
    # Check for alg: none
    if header.get('alg', '').lower() == 'none':
        vulnerabilities.append({
            'type': 'JWT Algorithm None',
            'severity': 'critical',
            'description': 'JWT uses "none" algorithm, allowing signature bypass',
            'data_class': 'Credential'
        })
    
    # Check for missing expiration
    if 'exp' not in payload:
        vulnerabilities.append({
            'type': 'JWT No Expiration',
            'severity': 'high',
            'description': 'JWT token has no expiration time',
            'data_class': 'Credential'
        })
    
    # Check for PII in payload
    for key, value in payload.items():
        if isinstance(value, str):
            if '@' in value and re.match(r'[^@]+@[^@]+\.[^@]+', value):
                vulnerabilities.append({
                    'type': 'JWT Contains Email',
                    'severity': 'medium',
                    'description': f'JWT payload contains email: {key}',
                    'data_class': 'PII'
                })
            if re.match(r'\d{3}-\d{2}-\d{4}', str(value)):
                vulnerabilities.append({
                    'type': 'JWT Contains SSN',
                    'severity': 'critical',
                    'description': f'JWT payload contains SSN: {key}',
                    'data_class': 'PII'
                })
    
    return vulnerabilities
