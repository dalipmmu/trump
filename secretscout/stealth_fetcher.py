"""
Stealth Fetcher Module for SecretScout
Uses advanced HTTP headers and techniques to bypass basic WAF protection
Falls back to requests when Playwright is not available
"""

import time
import random
import requests
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import logging

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class StealthFetchResult:
    """Result of a stealth fetch operation"""
    url: str
    status_code: int
    html: str
    page_title: str = ""
    page_url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    
    @property
    def success(self) -> bool:
        return self.status_code == 200 and not self.error


class StealthFetcher:
    """
    NSA-GRADE Stealth Fetcher
    Uses advanced HTTP headers and request patterns to bypass basic WAF protection
    """
    
    def __init__(
        self,
        delay: float = 1.0,
        max_retries: int = 3,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        headless: bool = True,
        slow_mo: int = 50,
    ):
        self.delay = delay
        self.max_retries = max_retries
        self.user_agent = user_agent or self._get_random_user_agent()
        self.proxy = proxy
        self.timeout = timeout
        
        # Session
        self.session = requests.Session()
        
        # Configure session
        self._configure_session()
        
        # Visited URLs
        self._visited_urls: Set[str] = set()
        
        logger.info(f"Stealth Fetcher initialized: user_agent={self.user_agent[:50]}...")
    
    def _get_random_user_agent(self) -> str:
        """Get a random modern browser user agent"""
        user_agents = [
            # Chrome on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            
            # Chrome on Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            
            # Firefox on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            
            # Safari on Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/604.1',
            
            # Edge on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            
            # Mobile - iPhone
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
            
            # Mobile - Android
            'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        ]
        return random.choice(user_agents)
    
    def _configure_session(self):
        """Configure the requests session with stealth headers"""
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        })
        
        # Set proxy if configured
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy,
            }
    
    def _human_like_delay(self):
        """Add human-like random delay"""
        time.sleep(random.uniform(0.5, 2.5))
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def _decode_content(self, response) -> str:
        """Decode response content handling gzip, deflate, and brotli"""
        content = response.content
        content_encoding = response.headers.get('content-encoding', '').lower()
        
        # Try to decode based on content encoding
        if content_encoding == 'br' or content.startswith(b'\x0b\x77'):
            # Brotli encoding
            try:
                import brotli
                return brotli.decompress(content).decode('utf-8')
            except:
                pass
        elif content_encoding == 'gzip' or content.startswith(b'\x1f\x8b'):
            # Gzip encoding
            try:
                import gzip
                return gzip.decompress(content).decode('utf-8')
            except:
                pass
        elif content_encoding == 'deflate':
            # Deflate encoding
            try:
                import zlib
                return zlib.decompress(content, -15).decode('utf-8')
            except:
                pass
        
        # Fall back to response.text
        return response.text
    
    def fetch(self, url: str, **kwargs) -> StealthFetchResult:
        """
        Fetch a URL using stealth techniques
        
        Args:
            url: URL to fetch
            **kwargs: Additional options
        
        Returns:
            StealthFetchResult with page content and metadata
        """
        url = self._normalize_url(url)
        
        # Check if already visited
        if url in self._visited_urls:
            logger.info(f"Skipping already visited URL: {url}")
            return StealthFetchResult(
                url=url,
                status_code=304,
                html="",
                error="Already visited"
            )
        
        max_attempts = self.max_retries + 1
        last_error = None
        
        for attempt in range(max_attempts):
            try:
                # Add human-like delay
                self._human_like_delay()
                
                # Change user agent for each attempt
                if attempt > 0:
                    self.user_agent = self._get_random_user_agent()
                    self.session.headers['User-Agent'] = self.user_agent
                
                # Make request
                logger.info(f"Fetching URL (attempt {attempt + 1}/{max_attempts}): {url}")
                
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Decode content (handle gzip, deflate, brotli)
                html = self._decode_content(response)
                
                # Get page title
                page_title = ""
                if response.status_code == 200:
                    # Try to extract title from HTML
                    if '<title>' in html.lower():
                        start = html.lower().find('<title>') + 7
                        end = html.lower().find('</title>', start)
                        if end > start:
                            page_title = html[start:end].strip()
                
                # Mark as visited
                self._visited_urls.add(url)
                
                logger.info(f"Successfully fetched: {url} ({response.status_code})")
                
                return StealthFetchResult(
                    url=url,
                    status_code=response.status_code,
                    html=html,
                    page_title=page_title,
                    page_url=response.url,
                    headers=dict(response.headers),
                    cookies=dict(response.cookies),
                )
                
            except requests.exceptions.RequestException as e:
                last_error = str(e)
                logger.warning(f"Error fetching {url} (attempt {attempt + 1}): {e}")
                
                if attempt < max_attempts - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                    continue
                else:
                    return StealthFetchResult(
                        url=url,
                        status_code=500,
                        html="",
                        error=last_error
                    )
        
        return StealthFetchResult(
            url=url,
            status_code=500,
            html="",
            error=last_error
        )
    
    def fetch_multiple(self, urls: List[str], **kwargs) -> List[StealthFetchResult]:
        """Fetch multiple URLs sequentially"""
        results = []
        for url in urls:
            result = self.fetch(url, **kwargs)
            results.append(result)
            # Add delay between requests
            time.sleep(1)
        return results
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Extract href attributes
        for tag in soup.find_all(['a', 'link'], href=True):
            href = tag['href']
            if href and not href.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                absolute_url = urljoin(base_url, href)
                links.add(absolute_url)
        
        # Extract src attributes
        for tag in soup.find_all(['script', 'img', 'iframe'], src=True):
            src = tag['src']
            if src and not src.startswith(('javascript:', 'data:')):
                absolute_url = urljoin(base_url, src)
                links.add(absolute_url)
        
        # Filter and normalize
        filtered_links = []
        for link in links:
            if not link.startswith(('http://', 'https://')):
                continue
            link = link.split('#')[0].split('?')[0].rstrip('/')
            filtered_links.append(link)
        
        return list(set(filtered_links))
    
    def extract_api_endpoints(self, html: str, base_url: str) -> List[str]:
        """Extract potential API endpoints from HTML and JavaScript"""
        import re
        endpoints = set()
        
        # Look for API URLs in JavaScript
        js_patterns = [
            r'https?://[^/]+/api[^/]*',
            r'https?://[^/]+/v[0-9]+[^/]*',
            r'https?://[^/]+/graphql[^/]*',
            r'https?://[^/]+/rest[^/]*',
            r'https?://[^/]+/wp-json[^/]*',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                endpoints.add(match)
        
        # Look for fetch/XHR calls
        fetch_patterns = [
            r'fetch\([\"\'](https?://[^\"\']+)[\"\']',
            r'axios\.(get|post|put|delete)\([\"\'](https?://[^\"\']+)[\"\']',
            r'\.ajax\([^)]*url:\s*[\"\'](https?://[^\"\']+)[\"\']',
        ]
        
        for pattern in fetch_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[-1]
                else:
                    endpoint = match
                endpoint = endpoint.strip('"\'')
                if endpoint.startswith(('http://', 'https://')):
                    endpoints.add(endpoint)
        
        return list(endpoints)
    
    def close(self):
        """Close the session"""
        self.session.close()
        logger.info("Stealth Fetcher closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def __del__(self):
        self.close()


def create_fetcher(
    use_browser: bool = True,
    **kwargs
) -> StealthFetcher:
    """
    Factory function to create the appropriate fetcher
    
    Args:
        use_browser: Try to use browser automation if available
        **kwargs: Arguments to pass to the fetcher
    
    Returns:
        Fetcher instance (BrowserFetcher or StealthFetcher)
    """
    # Try to use browser automation if requested
    if use_browser:
        try:
            from .browser_fetcher import BrowserFetcher
            return BrowserFetcher(**kwargs)
        except Exception as e:
            logger.warning(f"Browser automation not available: {e}")
            logger.info("Falling back to stealth HTTP fetcher")
    
    # Fall back to stealth fetcher
    return StealthFetcher(**kwargs)
