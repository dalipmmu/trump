"""
Browser Automation Engine for SecretScout
NSA-GRADE scanning using real browser automation to bypass WAF protection
"""

import time
import json
import logging
from typing import Optional, List, Dict, Any, Set, Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from .storage import Finding, Severity, DataClass, FindingStore
from .patterns import (
    find_secrets_in_text, redact_secret, SOURCE_MAP_PATTERNS,
    CONFIG_FILE_PATTERNS, DEBUG_ENDPOINT_PATTERNS, GIT_PATTERNS,
    calculate_shannon_entropy, SecretPattern
)
from .stealth_fetcher import StealthFetcher, StealthFetchResult
from . import TECHNIQUES, ALL_TECHNIQUE_IDS

# Try to import browser fetcher, fall back to stealth
try:
    from .browser_fetcher import BrowserFetcher, BrowserFetchResult
    BROWSER_AVAILABLE = True
except Exception:
    BROWSER_AVAILABLE = False
    BrowserFetcher = None
    BrowserFetchResult = StealthFetchResult

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class BrowserScanConfig:
    """Configuration for browser-based scanning"""
    
    # Target
    url: Optional[str] = None
    
    # Scan options
    techniques: List[str] = field(default_factory=lambda: ["t1", "t2", "t3", "t4", "t5"])
    crawl: bool = True
    max_pages: int = 20
    max_depth: int = 3
    same_host_only: bool = True
    
    # Browser options
    headless: bool = True
    slow_mo: int = 50
    timeout: int = 30000
    user_agent: Optional[str] = None
    proxy: Optional[str] = None
    take_screenshots: bool = False
    
    # Output options
    reveal_secrets: bool = False
    output_format: str = "json"
    output_file: Optional[str] = None
    
    # Validation options
    validate_keys: bool = True
    
    # Rate limiting
    delay: float = 1.0
    
    # Callbacks
    on_progress: Optional[Callable] = None
    on_finding: Optional[Callable] = None


@dataclass
class BrowserScanResult:
    """Result of a browser-based scan"""
    
    scan_id: str
    config: BrowserScanConfig
    store: FindingStore = field(default_factory=FindingStore)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    
    # Statistics
    pages_scanned: int = 0
    pages_blocked: int = 0
    api_endpoints_found: int = 0
    links_extracted: int = 0
    
    # Browser-specific stats
    screenshots_taken: int = 0
    waf_bypasses: int = 0
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0
    
    @property
    def findings(self) -> List[Finding]:
        return self.store.findings if hasattr(self.store, 'findings') else []
    
    @property
    def high_confidence_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.confidence >= 0.8]
    
    @property
    def confirmed_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.confirmed_live]


class BrowserEngine:
    """
    NSA-GRADE Browser Automation Engine
    Uses Playwright to scan websites that block standard HTTP requests
    """
    
    def __init__(self, config: Optional[BrowserScanConfig] = None):
        self.config = config or BrowserScanConfig()
        self.store = FindingStore()
        self.errors: List[str] = []
        self.stats = {
            'pages_scanned': 0,
            'pages_blocked': 0,
            'api_endpoints_found': 0,
            'links_extracted': 0,
            'screenshots_taken': 0,
            'waf_bypasses': 0,
        }
        
        # Browser fetcher - try browser first, fall back to stealth
        self.fetcher = self._create_fetcher()
        
        # Visited URLs
        self._visited: Set[str] = set()
        
        # API endpoints found
        self._api_endpoints: Set[str] = set()
        
        logger.info("Browser Engine initialized")
    
    def _create_fetcher(self):
        """Create the appropriate fetcher based on availability"""
        # Try browser automation if requested and available
        if BROWSER_AVAILABLE and self.config.headless:
            try:
                return BrowserFetcher(
                    headless=self.config.headless,
                    slow_mo=self.config.slow_mo,
                    timeout=self.config.timeout,
                    user_agent=self.config.user_agent,
                    proxy=self.config.proxy,
                )
            except Exception as e:
                logger.warning(f"Browser automation failed: {e}. Falling back to stealth mode.")
        
        # Fall back to stealth fetcher
        logger.info("Using stealth HTTP fetcher (browser automation not available)")
        return StealthFetcher(
            delay=1.0,
            max_retries=3,
            user_agent=self.config.user_agent,
            proxy=self.config.proxy,
            timeout=self.config.timeout // 1000,  # Convert ms to seconds
        )
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def _is_same_host(self, url: str, base_url: str) -> bool:
        """Check if URL is on the same host"""
        if not self.config.same_host_only:
            return True
        
        url_domain = self._get_domain(url)
        base_domain = self._get_domain(base_url)
        return url_domain == base_domain
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.split('#')[0].split('?')[0].rstrip('/')
    
    def _should_scan_url(self, url: str, base_url: str) -> bool:
        """Determine if a URL should be scanned"""
        # Skip if already visited
        if url in self._visited:
            return False
        
        # Skip if not same host (if configured)
        if not self._is_same_host(url, base_url):
            logger.debug(f"Skipping external URL: {url}")
            return False
        
        # Skip non-HTTP URLs
        if not url.startswith(('http://', 'https://')):
            return False
        
        # Skip common non-content URLs
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot']
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return False
        
        return True
    
    def _scan_page_content(self, html: str, url: str, page_title: str = "") -> List[Finding]:
        """Scan page content for secrets"""
        findings = []
        
        # Find secrets in text
        text_findings = find_secrets_in_text(html, url)
        findings.extend(text_findings)
        
        # Check for source map patterns
        for pattern in SOURCE_MAP_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                if pattern['validator'] and not pattern['validator'](secret):
                    continue
                
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.MEDIUM),
                    confidence=pattern.get('confidence', 0.7),
                    technique_id="t1",
                    timestamp=time.time(),
                    metadata={'page_title': page_title, 'source': 'browser_html'}
                )
                findings.append(finding)
        
        # Check for config file patterns
        for pattern in CONFIG_FILE_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.HIGH),
                    confidence=pattern.get('confidence', 0.8),
                    technique_id="t2",
                    timestamp=time.time(),
                    metadata={'page_title': page_title, 'source': 'browser_html'}
                )
                findings.append(finding)
        
        # Check for debug endpoint patterns
        for pattern in DEBUG_ENDPOINT_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.CRITICAL),
                    confidence=pattern.get('confidence', 0.9),
                    technique_id="t3",
                    timestamp=time.time(),
                    metadata={'page_title': page_title, 'source': 'browser_html'}
                )
                findings.append(finding)
        
        # Check for Git patterns
        for pattern in GIT_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.HIGH),
                    confidence=pattern.get('confidence', 0.85),
                    technique_id="t4",
                    timestamp=time.time(),
                    metadata={'page_title': page_title, 'source': 'browser_html'}
                )
                findings.append(finding)
        
        return findings
    
    def _scan_api_endpoints(self, html: str, base_url: str) -> List[str]:
        """Extract and scan API endpoints from page"""
        endpoints = self.fetcher.extract_api_endpoints(html, base_url)
        
        # Filter and normalize
        unique_endpoints = set()
        for endpoint in endpoints:
            endpoint = self._normalize_url(endpoint)
            if endpoint not in self._api_endpoints:
                unique_endpoints.add(endpoint)
                self._api_endpoints.add(endpoint)
        
        self.stats['api_endpoints_found'] += len(unique_endpoints)
        return list(unique_endpoints)
    
    def _scan_technique_t1(self, html: str, url: str) -> List[Finding]:
        """Technique 1: Basic secret scanning in HTML"""
        return self._scan_page_content(html, url)
    
    def _scan_technique_t2(self, html: str, url: str) -> List[Finding]:
        """Technique 2: Config file scanning"""
        findings = []
        for pattern in CONFIG_FILE_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.HIGH),
                    confidence=pattern.get('confidence', 0.8),
                    technique_id="t2",
                    timestamp=time.time(),
                    metadata={'source': 'browser_t2'}
                )
                findings.append(finding)
        return findings
    
    def _scan_technique_t3(self, html: str, url: str) -> List[Finding]:
        """Technique 3: Debug endpoint scanning"""
        findings = []
        for pattern in DEBUG_ENDPOINT_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.CRITICAL),
                    confidence=pattern.get('confidence', 0.9),
                    technique_id="t3",
                    timestamp=time.time(),
                    metadata={'source': 'browser_t3'}
                )
                findings.append(finding)
        return findings
    
    def _scan_technique_t4(self, html: str, url: str) -> List[Finding]:
        """Technique 4: Git repository scanning"""
        findings = []
        for pattern in GIT_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.HIGH),
                    confidence=pattern.get('confidence', 0.85),
                    technique_id="t4",
                    timestamp=time.time(),
                    metadata={'source': 'browser_t4'}
                )
                findings.append(finding)
        return findings
    
    def _scan_technique_t5(self, html: str, url: str) -> List[Finding]:
        """Technique 5: Source map scanning"""
        findings = []
        for pattern in SOURCE_MAP_PATTERNS:
            matches = pattern['pattern'].findall(html)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                if pattern['validator'] and not pattern['validator'](secret):
                    continue
                
                finding = Finding(
                    secret_type=pattern['name'],
                    secret_value=secret,
                    redacted_secret=redact_secret(secret),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(secret) - 100):html.find(secret) + len(secret) + 100],
                    severity=pattern.get('severity', Severity.MEDIUM),
                    confidence=pattern.get('confidence', 0.7),
                    technique_id="t5",
                    timestamp=time.time(),
                    metadata={'source': 'browser_t5'}
                )
                findings.append(finding)
        return findings
    
    def _scan_technique_t16(self, html: str, url: str) -> List[Finding]:
        """Technique 16: JavaScript Variable Tracing (Browser Edition)"""
        findings = []
        
        # Look for JavaScript variables that might contain secrets
        import re
        
        # Patterns for JavaScript variable assignments
        js_var_patterns = [
            (r'const\s+(\w+)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'JS_CONST'),
            (r'let\s+(\w+)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'JS_LET'),
            (r'var\s+(\w+)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'JS_VAR'),
            (r'(\w+)\s*=\s*["\']([a-zA-Z0-9_\-]{20,})["\']', 'JS_ASSIGN'),
        ]
        
        for pattern, var_type in js_var_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for var_name, value in matches:
                # Check if value looks like a secret
                if len(value) >= 20 and calculate_shannon_entropy(value) > 3.5:
                    # Check for common secret keywords in variable name
                    secret_keywords = ['key', 'token', 'secret', 'api', 'password', 'auth', 'credential']
                    if any(kw in var_name.lower() for kw in secret_keywords):
                        finding = Finding(
                            secret_type=f"JavaScript {var_type} Variable",
                            secret_value=value,
                            redacted_secret=redact_secret(value),
                            source=url,
                            line_number=0,
                            context=f"{var_name}={value}",
                            severity=Severity.HIGH,
                            confidence=0.85,
                            technique_id="t16",
                            timestamp=time.time(),
                            metadata={'var_name': var_name, 'source': 'browser_t16'}
                        )
                        findings.append(finding)
        
        return findings
    
    def _scan_technique_t17(self, html: str, url: str) -> List[Finding]:
        """Technique 17: GitHub Token Deep Scan (Browser Edition)"""
        findings = []
        
        # Look for GitHub tokens in various formats
        github_patterns = [
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub Personal Access Token
            r'gho_[a-zA-Z0-9]{36}',  # GitHub OAuth Token
            r'ghu_[a-zA-Z0-9]{36}',  # GitHub User Token
            r'ghs_[a-zA-Z0-9]{36}',  # GitHub Server Token
            r'ghr_[a-zA-Z0-9]{36}',  # GitHub Refresh Token
        ]
        
        for pattern in github_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for token in matches:
                finding = Finding(
                    secret_type="GitHub Token",
                    secret_value=token,
                    redacted_secret=redact_secret(token),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(token) - 100):html.find(token) + len(token) + 100],
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    technique_id="t17",
                    timestamp=time.time(),
                    metadata={'source': 'browser_t17'}
                )
                findings.append(finding)
        
        return findings
    
    def _scan_technique_t18(self, html: str, url: str) -> List[Finding]:
        """Technique 18: Database Connection String Scan (Browser Edition)"""
        findings = []
        
        # Look for database connection strings
        db_patterns = [
            (r'mongodb:\/\/[^\s]+', 'MongoDB Connection String'),
            (r'mysql:\/\/[^\s]+', 'MySQL Connection String'),
            (r'postgresql:\/\/[^\s]+', 'PostgreSQL Connection String'),
            (r'redis:\/\/[^\s]+', 'Redis Connection String'),
            (r'amqp:\/\/[^\s]+', 'AMQP Connection String'),
            (r'Server=[^;]+;Database=[^;]+;Uid=[^;]+;Pwd=[^;]+', 'SQL Server Connection String'),
            (r'host=[^&]+&dbname=[^&]+&user=[^&]+&password=[^&]+', 'Generic DB Connection'),
        ]
        
        for pattern, db_type in db_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for conn_str in matches:
                finding = Finding(
                    secret_type=db_type,
                    secret_value=conn_str,
                    redacted_secret=redact_secret(conn_str),
                    source=url,
                    line_number=0,
                    context=html[max(0, html.find(conn_str) - 100):html.find(conn_str) + len(conn_str) + 100],
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    technique_id="t18",
                    timestamp=time.time(),
                    metadata={'source': 'browser_t18'}
                )
                findings.append(finding)
        
        return findings
    
    def _run_technique(self, technique_id: str, html: str, url: str) -> List[Finding]:
        """Run a specific technique on page content"""
        technique_map = {
            't1': self._scan_technique_t1,
            't2': self._scan_technique_t2,
            't3': self._scan_technique_t3,
            't4': self._scan_technique_t4,
            't5': self._scan_technique_t5,
            't16': self._scan_technique_t16,
            't17': self._scan_technique_t17,
            't18': self._scan_technique_t18,
        }
        
        if technique_id in technique_map:
            return technique_map[technique_id](html, url)
        else:
            logger.warning(f"Unknown technique: {technique_id}")
            return []
    
    def scan_page(self, url: str) -> BrowserFetchResult:
        """
        Scan a single page using browser automation
        
        Args:
            url: URL to scan
        
        Returns:
            BrowserFetchResult with scan results
        """
        url = self._normalize_url(url)
        
        # Check if should scan
        if not self._should_scan_url(url, self.config.url):
            logger.info(f"Skipping URL: {url}")
            return BrowserFetchResult(
                url=url,
                status_code=304,
                html="",
                error="Skipped"
            )
        
        # Mark as visited
        self._visited.add(url)
        
        # Fetch page using browser
        result = self.fetcher.fetch(
            url,
            wait_until='networkidle',
            take_screenshot=self.config.take_screenshots
        )
        
        # Update stats
        self.stats['pages_scanned'] += 1
        
        if result.error and 'WAF' in result.error:
            self.stats['pages_blocked'] += 1
        elif result.success:
            self.stats['waf_bypasses'] += 1
        
        if result.screenshot_path:
            self.stats['screenshots_taken'] += 1
        
        # Check if blocked
        if result.error or not result.success:
            logger.warning(f"Failed to fetch {url}: {result.error}")
            self.errors.append(f"Failed to fetch {url}: {result.error}")
            return result
        
        # Scan content with all techniques
        all_findings = []
        for technique_id in self.config.techniques:
            try:
                findings = self._run_technique(technique_id, result.html, result.page_url)
                all_findings.extend(findings)
                
                # Add to store
                for finding in findings:
                    # Update with page info
                    finding.metadata['page_title'] = result.page_title
                    finding.metadata['page_url'] = result.page_url
                    finding.metadata['browser_mode'] = True
                    
                    self.store.add_finding(finding)
                    
                    # Call callback if provided
                    if self.config.on_finding:
                        self.config.on_finding(finding)
                
                logger.info(f"Technique {technique_id} found {len(findings)} findings on {url}")
            except Exception as e:
                logger.error(f"Error running technique {technique_id} on {url}: {e}")
                self.errors.append(f"Error running technique {technique_id} on {url}: {e}")
        
        # Extract API endpoints
        api_endpoints = self._scan_api_endpoints(result.html, result.page_url)
        logger.info(f"Found {len(api_endpoints)} API endpoints on {url}")
        
        # Extract links for crawling
        links = self.fetcher.extract_links(result.html, result.page_url)
        self.stats['links_extracted'] += len(links)
        
        return result
    
    def crawl_and_scan(self, start_url: str):
        """
        Crawl a website starting from a URL and scan all pages
        
        Args:
            start_url: Starting URL for crawling
        """
        start_url = self._normalize_url(start_url)
        
        # Queue for BFS crawling
        from collections import deque
        queue = deque()
        queue.append((start_url, 0))  # (url, depth)
        
        # Track visited
        self._visited.add(start_url)
        
        # Track pages at each depth
        pages_at_depth = {0: [start_url]}
        
        while queue and len(self._visited) < self.config.max_pages:
            url, depth = queue.popleft()
            
            # Check depth limit
            if depth > self.config.max_depth:
                continue
            
            logger.info(f"Scanning {url} (depth {depth})")
            
            # Scan page
            result = self.scan_page(url)
            
            # Report progress
            if self.config.on_progress:
                self.config.on_progress({
                    'url': url,
                    'depth': depth,
                    'pages_scanned': len(self._visited),
                    'findings': len(self.store.get_all()),
                    'current_page': url
                })
            
            # If successful, extract links and add to queue
            if result.success:
                links = self.fetcher.extract_links(result.html, result.page_url)
                
                for link in links:
                    link = self._normalize_url(link)
                    
                    # Check if should scan
                    if not self._should_scan_url(link, start_url):
                        continue
                    
                    # Check if already visited or in queue
                    if link not in self._visited:
                        new_depth = depth + 1
                        
                        # Check if we've reached max pages at this depth
                        if new_depth not in pages_at_depth:
                            pages_at_depth[new_depth] = []
                        
                        if len(pages_at_depth[new_depth]) < self.config.max_pages:
                            pages_at_depth[new_depth].append(link)
                            queue.append((link, new_depth))
                            self._visited.add(link)
        
        logger.info(f"Crawling complete. Visited {len(self._visited)} pages")
    
    def scan(self, config: Optional[BrowserScanConfig] = None) -> BrowserScanResult:
        """
        Perform a complete browser-based scan
        
        Args:
            config: Scan configuration (overrides instance config)
        
        Returns:
            BrowserScanResult with all findings
        """
        if config:
            self.config = config
        
        # Generate scan ID
        import uuid
        scan_id = str(uuid.uuid4())
        
        # Fetcher is already initialized in __init__
        # Just ensure it's ready
        if self.fetcher is None:
            self.fetcher = self._create_fetcher()
        
        result = BrowserScanResult(
            scan_id=scan_id,
            config=self.config,
            store=self.store,
            start_time=time.time()
        )
        
        try:
            # Start scanning
            if self.config.crawl and self.config.url:
                self.crawl_and_scan(self.config.url)
            elif self.config.url:
                # Just scan the single URL
                self.scan_page(self.config.url)
            
            # Update result stats
            result.pages_scanned = self.stats['pages_scanned']
            result.pages_blocked = self.stats['pages_blocked']
            result.api_endpoints_found = self.stats['api_endpoints_found']
            result.links_extracted = self.stats['links_extracted']
            result.screenshots_taken = self.stats['screenshots_taken']
            result.waf_bypasses = self.stats['waf_bypasses']
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.errors.append(f"Scan failed: {e}")
        finally:
            # Close browser
            if self.fetcher:
                self.fetcher.close()
            
            result.end_time = time.time()
        
        return result
    
    def close(self):
        """Close the engine and cleanup"""
        if self.fetcher:
            self.fetcher.close()
        logger.info("Browser Engine closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def scan_with_browser(
    url: str,
    techniques: List[str] = None,
    crawl: bool = True,
    max_pages: int = 20,
    max_depth: int = 3,
    headless: bool = True,
    take_screenshots: bool = False,
    validate_keys: bool = True,
    reveal_secrets: bool = False,
    output_format: str = "json",
    output_file: Optional[str] = None,
    on_progress: Optional[Callable] = None,
    on_finding: Optional[Callable] = None,
) -> BrowserScanResult:
    """
    Convenience function to scan a URL with browser automation
    
    Args:
        url: Target URL to scan
        techniques: List of technique IDs to use
        crawl: Whether to crawl the site
        max_pages: Maximum pages to crawl
        max_depth: Maximum crawl depth
        headless: Run browser in headless mode
        take_screenshots: Take screenshots of pages
        validate_keys: Validate found API keys
        reveal_secrets: Reveal full secret values in output
        output_format: Output format ('json', 'html', 'pdf', 'nsa')
        output_file: Path to save output
        on_progress: Callback for progress updates
        on_finding: Callback for each finding
    
    Returns:
        BrowserScanResult with scan results
    """
    config = BrowserScanConfig(
        url=url,
        techniques=techniques or ["t1", "t2", "t3", "t4", "t5", "t16", "t17", "t18"],
        crawl=crawl,
        max_pages=max_pages,
        max_depth=max_depth,
        headless=headless,
        take_screenshots=take_screenshots,
        validate_keys=validate_keys,
        reveal_secrets=reveal_secrets,
        output_format=output_format,
        output_file=output_file,
        on_progress=on_progress,
        on_finding=on_finding,
    )
    
    engine = BrowserEngine(config)
    return engine.scan(config)
