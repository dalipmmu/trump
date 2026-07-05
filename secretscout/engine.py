"""
Main Engine Module for SecretScout
Orchestrates all scanning techniques and manages the scanning process
"""

import time
import json
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass, field

from .storage import Finding, Severity, DataClass, FindingStore
from .fetcher import Fetcher
from .crawler import Crawler
from .patterns import (
    find_secrets_in_text, redact_secret, SOURCE_MAP_PATTERNS, 
    CONFIG_FILE_PATTERNS, DEBUG_ENDPOINT_PATTERNS, GIT_PATTERNS
)
from . import TECHNIQUES, ALL_TECHNIQUE_IDS


@dataclass
class ScanConfig:
    """Configuration for a scan"""
    
    # Target
    url: Optional[str] = None
    project_path: Optional[str] = None
    
    # Scan options
    techniques: List[str] = field(default_factory=lambda: ["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"])
    crawl: bool = False
    max_pages: int = 50
    max_depth: int = 5
    same_host_only: bool = True
    
    # Output options
    reveal_secrets: bool = False
    output_format: str = "json"
    output_file: Optional[str] = None
    
    # Validation options
    validate_keys: bool = False
    api_token: Optional[str] = None
    
    # Rate limiting
    delay: float = 0.1
    max_concurrent: int = 10
    
    # Callbacks
    on_progress: Optional[Callable] = None
    on_finding: Optional[Callable] = None


@dataclass
class ScanResult:
    """Result of a complete scan"""
    
    scan_id: str
    config: ScanConfig
    store: FindingStore = field(default_factory=FindingStore)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    
    # Statistics
    pages_scanned: int = 0
    assets_scanned: int = 0
    api_endpoints_found: int = 0
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0.0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the scan results"""
        return self.store.generate_summary(
            target_url=self.config.url or "",
            target_project=self.config.project_path,
            techniques_used=self.config.techniques
        ).to_dict()


class Engine:
    """Main scanning engine that orchestrates all techniques"""
    
    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or ScanConfig()
        self.fetcher = Fetcher(
            delay=self.config.delay,
            max_concurrent=self.config.max_concurrent
        )
        self.crawler = Crawler(
            fetcher=self.fetcher,
            max_pages=self.config.max_pages,
            max_depth=self.config.max_depth,
            same_host_only=self.config.same_host_only,
            delay=self.config.delay
        )
        self.store = FindingStore()
        self.errors: List[str] = []
    
    def scan(self, config: Optional[ScanConfig] = None) -> ScanResult:
        """
        Perform a complete scan using the configured techniques
        
        Args:
            config: Scan configuration (overrides instance config)
        
        Returns:
            ScanResult with all findings
        """
        if config:
            self.config = config
        
        result = ScanResult(
            scan_id=self.store.scan_id,
            config=self.config,
            store=self.store
        )
        
        # Start timer
        result.start_time = time.time()
        
        try:
            # If crawling is enabled, do it first
            if self.config.crawl and self.config.url:
                self._crawl_and_scan()
            
            # Run each enabled technique
            for technique_id in self.config.techniques:
                self._run_technique(technique_id)
            
            # Generate summary
            self.store.generate_summary(
                target_url=self.config.url or "",
                target_project=self.config.project_path,
                techniques_used=self.config.techniques
            )
            
        except Exception as e:
            self.errors.append(f"Scan failed: {str(e)}")
            result.errors.append(f"Scan failed: {str(e)}")
        
        # End timer
        result.end_time = time.time()
        result.store = self.store
        result.errors = self.errors
        
        return result
    
    def _run_technique(self, technique_id: str):
        """Run a specific technique"""
        try:
            if technique_id == "t1":
                self._scan_hardcoded_secrets()
            elif technique_id == "t2":
                self._scan_source_maps()
            elif technique_id == "t3":
                self._scan_config_files()
            elif technique_id == "t4":
                self._scan_dependencies()
            elif technique_id == "t5":
                self._scan_git_repo()
            elif technique_id == "t6":
                self._scan_debug_endpoints()
            elif technique_id == "t7":
                self._scan_wayback()
            elif technique_id == "t8":
                self._scan_security_headers()
            elif technique_id == "t9":
                self._scan_admin_surfaces()
            elif technique_id == "t10":
                self._scan_subdomains()
            elif technique_id == "t11":
                self._scan_api_endpoints()
            elif technique_id == "t12":
                if self.config.validate_keys:
                    self._validate_api_keys()
            elif technique_id == "t13":
                self._scan_cors()
            elif technique_id == "t14":
                self._scan_rate_limits()
            elif technique_id == "t15":
                self._scan_error_messages()
        except Exception as e:
            self.errors.append(f"Error in technique {technique_id}: {str(e)}")
    
    def _crawl_and_scan(self):
        """Perform crawling and scan all discovered pages"""
        if not self.config.url:
            return
        
        # Crawl the site
        crawl_result = self.crawler.crawl(
            start_url=self.config.url,
            scan_technique="t1",
            on_progress=self.config.on_progress
        )
        
        self.store.findings.extend(crawl_result.findings)
        
        # Scan all discovered assets
        if crawl_result.assets_found:
            asset_findings = self.crawler.scan_assets(
                list(crawl_result.assets_found),
                scan_technique="t1"
            )
            self.store.findings.extend(asset_findings)
    
    def _scan_hardcoded_secrets(self):
        """Technique 1: Scan for hardcoded secrets in client-side code"""
        if not self.config.url:
            return
        
        result = self.fetcher.fetch(self.config.url)
        
        if result.is_success():
            secrets = find_secrets_in_text(result.content, self.config.url)
            
            for secret in secrets:
                finding = self._create_secret_finding(
                    technique="t1",
                    secret=secret,
                    url=self.config.url,
                    content=result.content,
                    content_type=result.content_type
                )
                self.store.add_finding(finding)
                if self.config.on_finding:
                    self.config.on_finding(finding)
    
    def _scan_source_maps(self):
        """Technique 2: Scan for exposed source maps"""
        if not self.config.url:
            return
        
        result = self.fetcher.fetch(self.config.url)
        
        if result.is_success():
            import re
            for pattern in SOURCE_MAP_PATTERNS:
                matches = re.findall(pattern, result.content, re.IGNORECASE)
                
                for match in matches:
                    source_map_url = self.fetcher._make_absolute(match, self.config.url)
                    if source_map_url:
                        sm_result = self.fetcher.fetch(source_map_url)
                        
                        if sm_result.is_success():
                            finding = Finding(
                                technique="t2",
                                technique_name=TECHNIQUES["t2"]["name"],
                                title=f"Source map exposed at {source_map_url}",
                                description=f"Source map file found at {source_map_url}",
                                severity=Severity.HIGH,
                                data_class=DataClass.SOURCE,
                                url=source_map_url,
                                evidence=sm_result.content[:200] + "...",
                                remediation="Remove source maps from production.",
                                impact="Source maps can reveal original source code and hidden secrets."
                            )
                            self.store.add_finding(finding)
                            
                            # Scan source map for secrets
                            secrets = find_secrets_in_text(sm_result.content, source_map_url)
                            for secret in secrets:
                                secret_finding = self._create_secret_finding(
                                    technique="t2",
                                    secret=secret,
                                    url=source_map_url,
                                    content=sm_result.content,
                                    content_type=sm_result.content_type
                                )
                                self.store.add_finding(secret_finding)
                                if self.config.on_finding:
                                    self.config.on_finding(secret_finding)
                            
                            if self.config.on_finding:
                                self.config.on_finding(finding)
    
    def _scan_config_files(self):
        """Technique 3: Scan for exposed configuration files"""
        if not self.config.url:
            return
        
        for pattern in CONFIG_FILE_PATTERNS:
            config_url = self.fetcher._make_absolute(pattern, self.config.url)
            if config_url:
                result = self.fetcher.fetch(config_url)
                
                if result.is_success():
                    finding = Finding(
                        technique="t3",
                        technique_name=TECHNIQUES["t3"]["name"],
                        title=f"Config file exposed: {pattern}",
                        description=f"Configuration file found at {config_url}",
                        severity=Severity.CRITICAL,
                        data_class=DataClass.SOURCE,
                        url=config_url,
                        evidence=result.content[:200] + "...",
                        remediation=f"Remove {pattern} from web root.",
                        impact="Exposed config files can reveal API keys, database credentials, and application settings."
                    )
                    self.store.add_finding(finding)
                    
                    # Scan for secrets in config file
                    secrets = find_secrets_in_text(result.content, config_url)
                    for secret in secrets:
                        secret_finding = self._create_secret_finding(
                            technique="t3",
                            secret=secret,
                            url=config_url,
                            content=result.content,
                            content_type=result.content_type
                        )
                        self.store.add_finding(secret_finding)
                        if self.config.on_finding:
                            self.config.on_finding(secret_finding)
                    
                    if self.config.on_finding:
                        self.config.on_finding(finding)
    
    def _scan_dependencies(self):
        """Technique 4: Scan for malicious dependencies"""
        if not self.config.project_path:
            return
        
        import os
        from pathlib import Path
        
        project_path = Path(self.config.project_path)
        
        # Load known bad packages
        known_bad_file = Path(__file__).parent / "data" / "known_bad_packages.json"
        known_bad_packages = {}
        if known_bad_file.exists():
            with open(known_bad_file, 'r') as f:
                known_bad_packages = json.load(f)
        
        # Check package.json
        package_json = project_path / "package.json"
        if package_json.exists():
            with open(package_json, 'r') as f:
                try:
                    package_data = json.load(f)
                    dependencies = package_data.get('dependencies', {})
                    dev_dependencies = package_data.get('devDependencies', {})
                    all_deps = {**dependencies, **dev_dependencies}
                    
                    for dep_name, dep_version in all_deps.items():
                        if dep_name in known_bad_packages:
                            finding = Finding(
                                technique="t4",
                                technique_name=TECHNIQUES["t4"]["name"],
                                title=f"Malicious package: {dep_name}@{dep_version}",
                                description=f"Package {dep_name} is known to be malicious",
                                severity=Severity.CRITICAL,
                                data_class=DataClass.SOURCE,
                                url=str(package_json),
                                evidence=f"Found in {package_json}",
                                remediation=f"Remove {dep_name} package.",
                                impact="Malicious packages can execute arbitrary code or steal credentials."
                            )
                            self.store.add_finding(finding)
                            if self.config.on_finding:
                                self.config.on_finding(finding)
                except json.JSONDecodeError:
                    pass
    
    def _scan_git_repo(self):
        """Technique 5: Scan for exposed .git repository"""
        if not self.config.url:
            return
        
        for pattern in GIT_PATTERNS:
            git_url = self.fetcher._make_absolute(pattern, self.config.url)
            if git_url:
                result = self.fetcher.fetch(git_url)
                
                if result.is_success():
                    finding = Finding(
                        technique="t5",
                        technique_name=TECHNIQUES["t5"]["name"],
                        title=f"Exposed .git directory at {git_url}",
                        description=f"Git repository directory found at {git_url}",
                        severity=Severity.CRITICAL,
                        data_class=DataClass.SOURCE,
                        url=git_url,
                        evidence=result.content[:200] + "...",
                        remediation="Remove .git directory from web root.",
                        impact="Exposed .git directories can reveal full source code and history."
                    )
                    self.store.add_finding(finding)
                    if self.config.on_finding:
                        self.config.on_finding(finding)
                    break
    
    def _scan_debug_endpoints(self):
        """Technique 6: Scan for debug/admin endpoints"""
        if not self.config.url:
            return
        
        for pattern in DEBUG_ENDPOINT_PATTERNS:
            endpoint_url = self.fetcher._make_absolute(pattern, self.config.url)
            if endpoint_url:
                result = self.fetcher.fetch(endpoint_url)
                
                if result.is_success():
                    severity = Severity.HIGH
                    if any(debug in pattern for debug in ['/actuator/env', '/heapdump', '/pprof', '/phpinfo']):
                        severity = Severity.CRITICAL
                    
                    finding = Finding(
                        technique="t6",
                        technique_name=TECHNIQUES["t6"]["name"],
                        title=f"Debug endpoint exposed: {pattern}",
                        description=f"Debug endpoint found at {endpoint_url}",
                        severity=severity,
                        data_class=DataClass.SOURCE,
                        url=endpoint_url,
                        evidence=result.content[:200] + "...",
                        remediation=f"Disable or restrict access to {pattern}",
                        impact="Debug endpoints can expose sensitive information like environment variables."
                    )
                    self.store.add_finding(finding)
                    
                    # Scan for secrets in debug output
                    secrets = find_secrets_in_text(result.content, endpoint_url)
                    for secret in secrets:
                        secret_finding = self._create_secret_finding(
                            technique="t6",
                            secret=secret,
                            url=endpoint_url,
                            content=result.content,
                            content_type=result.content_type
                        )
                        self.store.add_finding(secret_finding)
                        if self.config.on_finding:
                            self.config.on_finding(secret_finding)
                    
                    if self.config.on_finding:
                        self.config.on_finding(finding)
    
    def _scan_wayback(self):
        """Technique 7: Scan Wayback Machine for historical exposure"""
        if not self.config.url:
            return
        
        try:
            import requests
            
            parsed = urlparse(self.config.url)
            domain = parsed.netloc
            
            cdx_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
            response = requests.get(cdx_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data[1:]:  # Skip header
                    if len(entry) >= 3:
                        original_url = entry[2]
                        timestamp = entry[1]
                        
                        if any(ext in original_url.lower() for ext in ['.js', '.env', 'config']):
                            archive_url = f"http://web.archive.org/web/{timestamp}/{original_url}"
                            archive_result = self.fetcher.fetch(archive_url)
                            
                            if archive_result.is_success():
                                secrets = find_secrets_in_text(archive_result.content, archive_url)
                                
                                for secret in secrets:
                                    finding = self._create_secret_finding(
                                        technique="t7",
                                        secret=secret,
                                        url=archive_url,
                                        content=archive_result.content,
                                        content_type=archive_result.content_type
                                    )
                                    finding.attack_chain = ["Historical exposure", "Secret extraction"]
                                    self.store.add_finding(finding)
                                    if self.config.on_finding:
                                        self.config.on_finding(finding)
        except Exception as e:
            self.errors.append(f"Wayback scan failed: {str(e)}")
    
    def _scan_security_headers(self):
        """Technique 8: Scan security headers and TLS posture"""
        if not self.config.url:
            return
        
        headers_result = self.fetcher.check_security_headers(self.config.url)
        
        if 'issues' in headers_result and headers_result['issues']:
            for issue in headers_result['issues']:
                finding = Finding(
                    technique="t8",
                    technique_name=TECHNIQUES["t8"]["name"],
                    title=f"Security header issue: {issue}",
                    description=f"Security header issue: {issue}",
                    severity=Severity.MEDIUM,
                    data_class=DataClass.INFRA,
                    url=self.config.url,
                    evidence=str(headers_result),
                    remediation="Implement proper security headers.",
                    impact="Missing or weak security headers can expose the application to various attacks."
                )
                self.store.add_finding(finding)
                if self.config.on_finding:
                    self.config.on_finding(finding)
        
        tls_result = self.fetcher.check_tls(self.config.url)
        
        if 'issues' in tls_result and tls_result['issues']:
            for issue in tls_result['issues']:
                finding = Finding(
                    technique="t8",
                    technique_name=TECHNIQUES["t8"]["name"],
                    title=f"TLS issue: {issue}",
                    description=f"TLS configuration issue: {issue}",
                    severity=Severity.HIGH,
                    data_class=DataClass.INFRA,
                    url=self.config.url,
                    evidence=str(tls_result),
                    remediation="Update TLS configuration.",
                    impact="Weak TLS configuration can allow traffic interception."
                )
                self.store.add_finding(finding)
                if self.config.on_finding:
                    self.config.on_finding(finding)
    
    def _scan_admin_surfaces(self):
        """Technique 9: Scan for admin/database/API surfaces"""
        if not self.config.url:
            return
        
        admin_paths = [
            '/admin/', '/wp-admin/', '/phpmyadmin/', '/adminer/',
            '/swagger/', '/api-docs', '/graphql', '/elasticsearch/'
        ]
        
        for path in admin_paths:
            admin_url = self.fetcher._make_absolute(path, self.config.url)
            if admin_url:
                result = self.fetcher.fetch(admin_url)
                
                if result.is_success():
                    severity = Severity.MEDIUM
                    if any(admin in path for admin in ['/phpmyadmin', '/wp-admin']):
                        severity = Severity.CRITICAL
                    
                    finding = Finding(
                        technique="t9",
                        technique_name=TECHNIQUES["t9"]["name"],
                        title=f"Admin/API surface found: {path}",
                        description=f"Admin or API surface found at {admin_url}",
                        severity=severity,
                        data_class=DataClass.INFRA,
                        url=admin_url,
                        evidence=result.content[:200] + "...",
                        remediation=f"Restrict access to {path}",
                        impact="Exposed admin and API surfaces can be targeted for attacks."
                    )
                    self.store.add_finding(finding)
                    if self.config.on_finding:
                        self.config.on_finding(finding)
    
    def _scan_subdomains(self):
        """Technique 10: Scan for subdomains using Certificate Transparency logs"""
        if not self.config.url:
            return
        
        try:
            import requests
            
            parsed = urlparse(self.config.url)
            domain = parsed.netloc
            
            cdx_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(cdx_url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                subdomains = set()
                for entry in data:
                    if 'name_value' in entry:
                        name = entry['name_value']
                        if name and name != domain:
                            subdomains.add(name)
                
                non_prod_keywords = ['dev', 'staging', 'test', 'qa', 'admin']
                
                for subdomain in subdomains:
                    if any(keyword in subdomain.lower() for keyword in non_prod_keywords):
                        finding = Finding(
                            technique="t10",
                            technique_name=TECHNIQUES["t10"]["name"],
                            title=f"Non-production subdomain: {subdomain}",
                            description=f"Non-production subdomain found: {subdomain}",
                            severity=Severity.MEDIUM,
                            data_class=DataClass.INFRA,
                            url=f"https://{subdomain}",
                            remediation=f"Review security of {subdomain}",
                            impact="Non-production subdomains often have weaker security controls."
                        )
                        self.store.add_finding(finding)
                        if self.config.on_finding:
                            self.config.on_finding(finding)
        except Exception as e:
            self.errors.append(f"Subdomain scan failed: {str(e)}")
    
    def _scan_api_endpoints(self):
        """Technique 11: Discover and test API endpoints"""
        if not self.config.url:
            return
        
        result = self.fetcher.fetch(self.config.url)
        
        if result.is_success():
            api_endpoints = self.fetcher.extract_api_endpoints(result.content, self.config.url)
            
            for endpoint in api_endpoints:
                self._test_api_endpoint(endpoint)
    
    def _test_api_endpoint(self, endpoint: str):
        """Test a single API endpoint for vulnerabilities"""
        try:
            # Try GET request
            result = self.fetcher.fetch(endpoint, method='GET')
            
            if result.is_success():
                # Check for secrets in response
                secrets = find_secrets_in_text(result.content, endpoint)
                
                for secret in secrets:
                    finding = self._create_secret_finding(
                        technique="t11",
                        secret=secret,
                        url=endpoint,
                        content=result.content,
                        content_type=result.content_type
                    )
                    self.store.add_finding(finding)
                    if self.config.on_finding:
                        self.config.on_finding(finding)
                
                # Check for error info leaks
                if self._has_error_info_leak(result.content):
                    finding = Finding(
                        technique="t11",
                        technique_name="API endpoint discovery",
                        title=f"Information leak in API response at {endpoint}",
                        description=f"API endpoint returns error messages that may leak information",
                        severity=Severity.MEDIUM,
                        data_class=DataClass.INFRA,
                        url=endpoint,
                        evidence=result.content[:200] + "...",
                        remediation="Configure API to return generic error messages.",
                        impact="Error messages can help attackers understand the application structure."
                    )
                    self.store.add_finding(finding)
                    if self.config.on_finding:
                        self.config.on_finding(finding)
        except Exception as e:
            self.errors.append(f"API endpoint test failed for {endpoint}: {str(e)}")
    
    def _has_error_info_leak(self, content: str) -> bool:
        """Check if content contains information leaks"""
        import re
        leak_patterns = [
            r'at\s+', r'File\s+"', r'line\s+\d+', r'SQL\s+',
            r'Exception:', r'Error:', r'Traceback', r'stack\s+trace'
        ]
        
        for pattern in leak_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        return False
    
    def _validate_api_keys(self):
        """Technique 12: Validate discovered API keys"""
        validatable_findings = [
            f for f in self.store.findings 
            if f.secret_value and f.provider and not f.allowlist
        ]
        
        for finding in validatable_findings:
            try:
                is_live = self._validate_key(finding.secret_value, finding.provider)
                finding.confirmed_live = is_live
                
                if is_live and finding.severity != Severity.CRITICAL:
                    finding.severity = Severity.CRITICAL
                    finding.attack_chain.append("Live key validation")
                    
                    if self.config.on_finding:
                        self.config.on_finding(finding)
                
            except Exception as e:
                self.errors.append(f"Key validation failed for {finding.provider}: {str(e)}")
    
    def _validate_key(self, key: str, provider: str) -> bool:
        """Validate an API key with its provider"""
        validation_functions = {
            'openai': self._validate_openai_key,
            'anthropic': self._validate_anthropic_key,
            'razorpay': self._validate_razorpay_key,
            'google': self._validate_google_key,
            'slack': self._validate_slack_token,
            'sendgrid': self._validate_sendgrid_key,
            'huggingface': self._validate_huggingface_token,
        }
        
        if provider in validation_functions:
            return validation_functions[provider](key)
        return False
    
    def _validate_openai_key(self, key: str) -> bool:
        try:
            import requests
            url = "https://api.openai.com/v1/models"
            headers = {"Authorization": f"Bearer {key}"}
            response = requests.get(url, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    

    def _validate_razorpay_key(self, key: str) -> bool:
        """Validate Razorpay key by checking if it's a valid key ID format
        For secrets, we check if it's a 32-character hex string (Razorpay secret format)
        """
        try:
            import requests
            # If it's a key ID (rzp_live_ or rzp_test_), validate it
            if key.startswith('rzp_live_') or key.startswith('rzp_test_'):
                # Extract the key ID part
                key_id = key
                # Try to validate with Razorpay API
                url = "https://api.razorpay.com/v1/payments"
                auth = (key_id, "")
                response = requests.get(url, auth=auth, timeout=15)
                # If we get 401, the key format is valid but might be invalid
                # If we get 403 or other errors, it might still be valid
                # We consider it valid if we don't get a connection error
                return response.status_code in [200, 401, 403]
            # For secret keys (32-char hex), we can't validate without the key ID
            # But we can check the format is correct
            elif len(key) == 32 and all(c in '0123456789abcdefABCDEF' for c in key):
                # This is a valid hex string of the right length
                # We'll consider it potentially valid but need more context
                return True
            return False
        except Exception:
            return False
    
    def _validate_google_key(self, key: str) -> bool:
        try:
            import requests
            url = "https://www.googleapis.com/oauth2/v3/tokeninfo"
            params = {"access_token": key}
            response = requests.get(url, params=params, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def _validate_slack_token(self, token: str) -> bool:
        try:
            import requests
            url = "https://slack.com/api/auth.test"
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(url, headers=headers, timeout=10)
            data = response.json()
            return data.get('ok', False)
        except Exception:
            return False
    
    def _validate_sendgrid_key(self, key: str) -> bool:
        try:
            import requests
            url = "https://api.sendgrid.com/v3/scopes"
            headers = {"Authorization": f"Bearer {key}"}
            response = requests.get(url, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def _validate_huggingface_token(self, token: str) -> bool:
        try:
            import requests
            url = "https://huggingface.co/api/whoami-v2"
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(url, headers=headers, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def _scan_cors(self):
        """Technique 13: Scan for CORS misconfigurations"""
        if not self.config.url:
            return
        
        cors_result = self.fetcher.check_cors(self.config.url)
        
        if cors_result.get('vulnerable', False):
            for issue in cors_result.get('issues', []):
                finding = Finding(
                    technique="t13",
                    technique_name=TECHNIQUES["t13"]["name"],
                    title=f"CORS misconfiguration: {issue}",
                    description=f"CORS misconfiguration: {issue}",
                    severity=Severity.HIGH,
                    data_class=DataClass.INFRA,
                    url=self.config.url,
                    evidence=str(cors_result),
                    remediation="Configure CORS properly to restrict origins.",
                    impact="CORS misconfigurations can allow cross-origin attacks."
                )
                self.store.add_finding(finding)
                if self.config.on_finding:
                    self.config.on_finding(finding)
    
    def _scan_rate_limits(self):
        """Technique 14: Test for missing rate limiting"""
        if not self.config.url:
            return
        
        try:
            import threading
            import time
            
            results = []
            
            def make_request():
                try:
                    start = time.time()
                    result = self.fetcher.fetch(self.config.url)
                    results.append({
                        'status': result.status_code,
                        'time': time.time() - start
                    })
                except Exception:
                    pass
            
            # Make 15 rapid requests
            threads = []
            for _ in range(15):
                thread = threading.Thread(target=make_request)
                threads.append(thread)
                thread.start()
            
            for thread in threads:
                thread.join(timeout=10)
            
            # Analyze results
            if len(results) >= 12:
                all_200 = all(r['status'] == 200 for r in results)
                avg_time = sum(r['time'] for r in results) / len(results)
                
                if all_200 and avg_time < 0.5:
                    finding = Finding(
                        technique="t14",
                        technique_name=TECHNIQUES["t14"]["name"],
                        title="Potential missing rate limiting",
                        description=f"Made 15 rapid requests to {self.config.url} with no rate limiting detected",
                        severity=Severity.MEDIUM,
                        data_class=DataClass.INFRA,
                        url=self.config.url,
                        evidence=f"15 requests completed in {sum(r['time'] for r in results):.2f} seconds",
                        remediation="Implement rate limiting to protect against brute force attacks.",
                        impact="Missing rate limiting can allow denial of service or brute force attacks."
                    )
                    self.store.add_finding(finding)
                    if self.config.on_finding:
                        self.config.on_finding(finding)
        except Exception as e:
            self.errors.append(f"Rate limit test failed: {str(e)}")
    
    def _scan_error_messages(self):
        """Technique 15: Analyze error messages for information leaks"""
        if not self.config.url:
            return
        
        test_paths = ['/nonexistent', '/api/nonexistent', '/test']
        
        for path in test_paths:
            test_url = self.fetcher._make_absolute(path, self.config.url)
            if test_url:
                result = self.fetcher.fetch(test_url)
                
                if result.status_code >= 400 and self._has_error_info_leak(result.content):
                    finding = Finding(
                        technique="t15",
                        technique_name=TECHNIQUES["t15"]["name"],
                        title=f"Information leak in error response for {path}",
                        description=f"Error response contains potentially sensitive information",
                        severity=Severity.MEDIUM,
                        data_class=DataClass.INFRA,
                        url=test_url,
                        evidence=result.content[:500] + "...",
                        remediation="Configure error pages to return generic messages.",
                        impact="Error messages can help attackers understand the application structure."
                    )
                    self.store.add_finding(finding)
                    if self.config.on_finding:
                        self.config.on_finding(finding)
                    break
    
    def _create_secret_finding(self, technique: str, secret: Dict, url: str, content: str, content_type: str) -> Finding:
        """Create a finding from a secret detection result"""
        return Finding(
            technique=technique,
            technique_name=TECHNIQUES[technique]["name"],
            title=f"{secret['type']} found in {url}",
            description=f"Found {secret['type']} in the content of {url}",
            severity=Severity(secret['severity']),
            data_class=DataClass(secret['data_class']),
            url=url,
            evidence=content[:500] + "..." if len(content) > 500 else content,
            secret_value=secret['value'],
            redacted_value=redact_secret(secret['value']),
            context=f"Found in {content_type} content",
            provider=secret.get('provider'),
            allowlist=secret.get('allowlist', False),
            remediation=f"Remove {secret['type']} from client-side code. Use environment variables or server-side configuration.",
            impact=f"Exposure of {secret['type']} could allow attackers to access {secret['data_class']} data or services."
        )


# Import urlparse for URL parsing
from urllib.parse import urlparse