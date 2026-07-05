"""
Secret Pattern Detection Module
Advanced pattern matching for API keys, secrets, and sensitive data
"""

import re
import base64
import math
import json
from typing import Dict, List, Tuple, Pattern, Optional
from dataclasses import dataclass


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
    
    # AWS Access Key ID
    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(r'AKIA[0-9A-Z]{16,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="aws"
    ),
    
    # AWS Secret Access Key
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(r'[a-zA-Z0-9/+=]{40,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="aws"
    ),
    
    # GitHub Token
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r'ghp_[a-zA-Z0-9]{36,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="github"
    ),
    
    # GitHub OAuth Token
    SecretPattern(
        name="GitHub OAuth Token",
        pattern=re.compile(r'gho_[a-zA-Z0-9]{36,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="github"
    ),
    
    # Stripe API Keys
    SecretPattern(
        name="Stripe Secret Key",
        pattern=re.compile(r'sk_live_[a-zA-Z0-9]{24,}', re.IGNORECASE),
        severity="critical",
        data_class="Financial",
        provider="stripe"
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        pattern=re.compile(r'pk_live_[a-zA-Z0-9]{24,}', re.IGNORECASE),
        severity="high",
        data_class="Financial",
        provider="stripe",
        allowlist=True  # Public by design
    ),
    SecretPattern(
        name="Stripe Test Key",
        pattern=re.compile(r'sk_test_[a-zA-Z0-9]{24,}', re.IGNORECASE),
        severity="high",
        data_class="Financial",
        provider="stripe"
    ),
    
    # Razorpay Keys (Critical for bounty hunting)
    SecretPattern(
        name="Razorpay Key ID",
        pattern=re.compile(r'rzp_live_[a-zA-Z0-9]{16,}', re.IGNORECASE),
        severity="high",
        data_class="Financial",
        provider="razorpay",
        allowlist=True  # Key ID is public by design
    ),
    SecretPattern(
        name="Razorpay Key Secret",
        pattern=re.compile(r'[a-zA-Z0-9]{32,}', re.IGNORECASE),
        severity="critical",
        data_class="Financial",
        provider="razorpay"
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
    
    # Cohere API Key
    SecretPattern(
        name="Cohere API Key",
        pattern=re.compile(r'[a-zA-Z0-9\-_]{40,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="cohere"
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
    
    # Generic API Key patterns
    SecretPattern(
        name="Generic API Key (api_key)",
        pattern=re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        secret_group=1,
        entropy_threshold=3.5
    ),
    SecretPattern(
        name="Generic API Key (apikey)",
        pattern=re.compile(r'apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        secret_group=1,
        entropy_threshold=3.5
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=re.compile(r'secret["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        secret_group=1,
        entropy_threshold=3.5
    ),
    SecretPattern(
        name="Generic Token",
        pattern=re.compile(r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{16,})["\']?', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        secret_group=1,
        entropy_threshold=3.5
    ),
    SecretPattern(
        name="Generic Password",
        pattern=re.compile(r'password["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_!@#$%^&*()]{8,})["\']?', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        secret_group=1,
        entropy_threshold=3.0
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
    # Credit Card Numbers (Luhn validation)
    SecretPattern(
        name="Credit Card Number",
        pattern=re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b', re.IGNORECASE),
        severity="critical",
        data_class="Financial"
    ),
    
    # Social Security Numbers (US)
    SecretPattern(
        name="US Social Security Number",
        pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b', re.IGNORECASE),
        severity="critical",
        data_class="PII"
    ),
    
    # Email Addresses
    SecretPattern(
        name="Email Address",
        pattern=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
        severity="medium",
        data_class="PII"
    ),
    
    # Phone Numbers
    SecretPattern(
        name="Phone Number",
        pattern=re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b', re.IGNORECASE),
        severity="medium",
        data_class="PII"
    ),
    
    # Database Connection Strings
    SecretPattern(
        name="Database Connection String",
        pattern=re.compile(r'mongodb:\/\/[^\s]+|mysql:\/\/[^\s]+|postgresql:\/\/[^\s]+|redis:\/\/[^\s]+', re.IGNORECASE),
        severity="critical",
        data_class="Infra"
    ),
    
    # AWS S3 Buckets
    SecretPattern(
        name="AWS S3 Bucket",
        pattern=re.compile(r'[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]\.s3\.amazonaws\.com|s3:\/\/[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]', re.IGNORECASE),
        severity="medium",
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
    r'\.aws/credentials',
    r'\.aws/config',
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
    Find all secrets in the given text using pattern matching and entropy analysis
    
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
                secret_value = match.group(pattern.secret_group) if pattern.secret_group > 0 else match.group(0)
            except IndexError:
                secret_value = match.group(0)
            
            # Skip if it's a placeholder or test value
            if any(placeholder in secret_value.lower() for placeholder in 
                   ['example', 'test', 'placeholder', 'your_', 'xxx', 'yyy', 'zzz']):
                continue
            
            # For generic patterns, check entropy
            if pattern.entropy_threshold > 0 and not is_high_entropy_string(secret_value, pattern.entropy_threshold):
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
            
            # Skip email addresses in some contexts (too common)
            if pattern.name == "Email Address" and '@' in context:
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


def is_likely_secret(value: str) -> bool:
    """Quick check if a value is likely a secret"""
    if not value or len(value) < 8:
        return False
    
    # Check against known patterns
    for pattern in SECRET_PATTERNS:
        if pattern.pattern.search(value):
            return True
    
    # Check entropy
    return is_high_entropy_string(value)


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
