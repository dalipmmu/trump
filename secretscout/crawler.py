"""
Web Crawler Module for SecretScout
Performs whole-site crawling to find all pages and assets
"""

import re
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Set, Optional, Callable
from dataclasses import dataclass, field

from .fetcher import Fetcher, FetchResult
from .storage import Finding, Severity, DataClass, FindingStore
from .patterns import find_secrets_in_text, redact_secret


@dataclass
class CrawlResult:
    """Result of a crawl operation"""
    base_url: str
    pages_visited: int = 0
    pages_failed: int = 0
    assets_found: Set[str] = field(default_factory=set)
    api_endpoints: Set[str] = field(default_factory=set)
    external_links: Set[str] = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0.0


class Crawler:
    """Web crawler for discovering pages and assets"""
    
    def __init__(self, 
                 fetcher: Optional[Fetcher] = None,
                 max_pages: int = 50,
                 max_depth: int = 5,
                 same_host_only: bool = True,
                 delay: float = 0.1):
        
        self.fetcher = fetcher or Fetcher()
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.same_host_only = same_host_only
        self.delay = delay
        
        self.visited_urls: Set[str] = set()
        self.to_visit: List[tuple] = []  # (url, depth)
        self.base_host: Optional[str] = None
        self.store = FindingStore()
    
    def crawl(self, start_url: str, 
              scan_technique: str = "t1",
              on_progress: Optional[Callable] = None) -> CrawlResult:
        """
        Crawl a website starting from the given URL
        
        Args:
            start_url: URL to start crawling from
            scan_technique: Technique ID to use for findings
            on_progress: Callback for progress updates
        
        Returns:
            CrawlResult with all discovered information
        """
        result = CrawlResult(base_url=start_url)
        
        # Parse base URL
        parsed = urlparse(start_url)
        self.base_host = parsed.netloc
        
        # Initialize queue
        self.to_visit = [(start_url, 0)]
        self.visited_urls = set()
        
        # Start crawling
        while self.to_visit and len(self.visited_urls) < self.max_pages:
            url, depth = self.to_visit.pop(0)
            
            # Skip if already visited
            if url in self.visited_urls:
                continue
            
            # Check depth limit
            if depth > self.max_depth:
                continue
            
            # Fetch the page
            fetch_result = self.fetcher.fetch(url)
            
            if fetch_result.is_success():
                result.pages_visited += 1
                self.visited_urls.add(url)
                
                # Extract secrets from content
                if scan_technique == "t1":  # Hardcoded secrets
                    secrets = find_secrets_in_text(fetch_result.content, url)
                    for secret in secrets:
                        finding = Finding(
                            technique=scan_technique,
                            technique_name="Hardcoded client-side secrets",
                            title=f"{secret['type']} found in {url}",
                            description=f"Found {secret['type']} in the content of {url}",
                            severity=Severity(secret['severity']),
                            data_class=DataClass(secret['data_class']),
                            url=url,
                            evidence=fetch_result.content[:500] + "..." if len(fetch_result.content) > 500 else fetch_result.content,
                            secret_value=secret['value'],
                            redacted_value=redact_secret(secret['value']),
                            context=f"Found in {fetch_result.content_type} content",
                            provider=secret.get('provider'),
                            allowlist=secret.get('allowlist', False),
                            remediation=f"Remove {secret['type']} from client-side code. Use environment variables or server-side configuration.",
                            impact=f"Exposure of {secret['type']} could allow attackers to access {secret['data_class']} data or services."
                        )
                        result.findings.append(finding)
                        self.store.add_finding(finding)
                
                # Extract links
                if fetch_result.is_html():
                    links = self.fetcher.extract_links(fetch_result.content, url)
                    api_endpoints = self.fetcher.extract_api_endpoints(fetch_result.content, url)
                    
                    result.api_endpoints.update(api_endpoints)
                    
                    for link in links:
                        if self._should_visit(link):
                            if link not in self.visited_urls:
                                self.to_visit.append((link, depth + 1))
                            result.assets_found.add(link)
                
                # Extract assets from HTML
                if fetch_result.is_html():
                    assets = self._extract_assets(fetch_result.content, url)
                    result.assets_found.update(assets)
                
            else:
                result.pages_failed += 1
            
            # Rate limiting
            time.sleep(self.delay)
            
            # Call progress callback
            if on_progress:
                on_progress({
                    'visited': len(self.visited_urls),
                    'queue': len(self.to_visit),
                    'current': url
                })
        
        result.end_time = time.time()
        return result
    
    def _should_visit(self, url: str) -> bool:
        """Determine if a URL should be visited"""
        if not url:
            return False
        
        # Skip non-HTTP URLs
        if not url.startswith('http://') and not url.startswith('https://'):
            return False
        
        # Skip external links if same_host_only
        if self.same_host_only:
            parsed = urlparse(url)
            if parsed.netloc != self.base_host:
                return False
        
        # Skip common non-content URLs
        skip_patterns = [
            r'\.(jpg|jpeg|png|gif|svg|ico|webp)$',
            r'\.(css|js)$',
            r'\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz)$',
            r'\.(mp3|mp4|avi|mov|wmv|flv)$',
            r'/feed/',
            r'/rss/',
            r'/atom/',
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False
        
        return True
    
    def _extract_assets(self, html: str, base_url: str) -> Set[str]:
        """Extract all assets from HTML"""
        assets = set()
        
        # JavaScript files
        js_files = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for js in js_files:
            absolute = self._make_absolute(js, base_url)
            if absolute:
                assets.add(absolute)
        
        # CSS files
        css_files = re.findall(r'<link[^>]+rel=["\']stylesheet["\'][^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE)
        css_files += re.findall(r'@import\s+["\']([^"\']+)["\']', html, re.IGNORECASE)
        for css in css_files:
            absolute = self._make_absolute(css, base_url)
            if absolute:
                assets.add(absolute)
        
        # Images
        img_files = re.findall(r'<img[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for img in img_files:
            absolute = self._make_absolute(img, base_url)
            if absolute:
                assets.add(absolute)
        
        # Source maps
        source_maps = re.findall(r'//#\s*sourceMappingURL=([^\s]+)', html, re.IGNORECASE)
        source_maps += re.findall(r'\.map$', html, re.IGNORECASE)
        for sm in source_maps:
            absolute = self._make_absolute(sm, base_url)
            if absolute:
                assets.add(absolute)
        
        return assets
    
    def _make_absolute(self, url: str, base_url: str) -> Optional[str]:
        """Convert relative URL to absolute"""
        if not url:
            return None
        
        if url.startswith('http://') or url.startswith('https://'):
            return url
        
        try:
            return urljoin(base_url, url)
        except Exception:
            return None
    
    def scan_assets(self, urls: List[str], scan_technique: str = "t1") -> List[Finding]:
        """Scan a list of asset URLs for secrets"""
        findings = []
        
        for url in urls:
            if url in self.visited_urls:
                continue
            
            fetch_result = self.fetcher.fetch(url)
            
            if fetch_result.is_success():
                self.visited_urls.add(url)
                
                # Scan for secrets based on technique
                if scan_technique == "t1":  # Hardcoded secrets
                    secrets = find_secrets_in_text(fetch_result.content, url)
                    for secret in secrets:
                        finding = Finding(
                            technique=scan_technique,
                            technique_name="Hardcoded client-side secrets",
                            title=f"{secret['type']} found in {url}",
                            description=f"Found {secret['type']} in {fetch_result.content_type} file at {url}",
                            severity=Severity(secret['severity']),
                            data_class=DataClass(secret['data_class']),
                            url=url,
                            evidence=fetch_result.content[:200] + "..." if len(fetch_result.content) > 200 else fetch_result.content,
                            secret_value=secret['value'],
                            redacted_value=redact_secret(secret['value']),
                            context=f"Found in {fetch_result.content_type} file",
                            provider=secret.get('provider'),
                            allowlist=secret.get('allowlist', False),
                            remediation=f"Remove {secret['type']} from static assets. Use server-side configuration.",
                            impact=f"Exposure of {secret['type']} in static files could allow attackers to access sensitive data."
                        )
                        findings.append(finding)
                        self.store.add_finding(finding)
                
                # Check for source maps
                if scan_technique == "t2" and any(url.endswith(ext) for ext in ['.js.map', '.css.map', '.map']):
                    finding = Finding(
                        technique=scan_technique,
                        technique_name="Exposed source maps",
                        title=f"Source map exposed at {url}",
                        description=f"Source map file found at {url}, which can reveal original source code and hidden secrets",
                        severity=Severity.HIGH,
                        data_class=DataClass.SOURCE,
                        url=url,
                        evidence=fetch_result.content[:200] + "..." if len(fetch_result.content) > 200 else fetch_result.content,
                        remediation="Remove source maps from production or configure build tools to not generate them.",
                        impact="Source maps can be used to reconstruct original source code, potentially revealing hidden secrets and sensitive logic."
                    )
                    findings.append(finding)
                    self.store.add_finding(finding)
            
            time.sleep(self.delay)
        
        return findings
