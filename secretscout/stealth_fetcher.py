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
        mobile_mode: bool = False,
    ):
        self.delay = delay
        self.max_retries = max_retries
        self.user_agent = user_agent or self._get_random_user_agent(mobile=mobile_mode)
        self.proxy = proxy
        self.timeout = timeout
        self.mobile_mode = mobile_mode
        
        # Session
        self.session = requests.Session()
        
        # Configure session
        self._configure_session()
        
        # Visited URLs
        self._visited_urls: Set[str] = set()
        
        # WAF bypass state
        self._waf_detected: Optional[str] = None
        self._request_count = 0
        
        logger.info(f"Stealth Fetcher initialized: user_agent={self.user_agent[:50]}..., mobile_mode={mobile_mode}")
    
    def _get_random_user_agent(self, mobile: bool = False) -> str:
        """Get a random modern browser user agent"""
        if mobile:
            user_agents = [
                # Mobile - iPhone (iOS 17)
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7 Mobile/15E148 Safari/604.1',
                
                # Mobile - Android (Chrome)
                'Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
                'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
                'Mozilla/5.0 (Linux; Android 12; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36',
                
                # Mobile - Android (Firefox)
                'Mozilla/5.0 (Android 13; Mobile; rv:115.0) Gecko/115.0 Firefox/115.0',
                'Mozilla/5.0 (Android 12; Mobile; rv:109.0) Gecko/109.0 Firefox/115.0',
                
                # Mobile - Samsung
                'Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
                
                # Mobile - Xiaomi
                'Mozilla/5.0 (Linux; Android 13; 2210132SG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            ]
        else:
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
            ]
        return random.choice(user_agents)
    
    def _get_mobile_headers(self) -> Dict[str, str]:
        """Get headers optimized for mobile devices (less WAF aggressive)"""
        return {
            'User-Agent': self._get_random_user_agent(mobile=True),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'X-Requested-With': 'XMLHttpRequest',
            'Save-Data': 'on',  # Mobile optimization
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }
    
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
        
        # Configure session for WAF bypass
        self._configure_waf_bypass()
    
    def _configure_waf_bypass(self):
        """Configure advanced WAF bypass settings"""
        # Remove default headers that might trigger WAF
        self.session.headers.pop('Accept-Encoding', None)
        
        # Add realistic browser headers that bypass common WAFs
        self.session.headers.update({
            'Accept-Encoding': 'gzip, deflate',  # Remove br to avoid some WAFs
            'X-Requested-With': 'XMLHttpRequest',
            'DNT': '1',  # Do Not Track
            'Sec-GPC': '1',  # Global Privacy Control
        })
    
    def _get_akamai_bypass_headers(self) -> Dict[str, str]:
        """Get headers specifically for bypassing Akamai WAF"""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
        }
    
    def _get_akamai_cookies(self, domain: str) -> Dict[str, str]:
        """Generate realistic cookies for Akamai bypass"""
        import hashlib
        import time
        
        timestamp = str(int(time.time() * 1000))
        
        # Generate realistic cookie values
        cookies = {
            'bm_sz': f'{random.randint(1000000, 9999999)}__{random.randint(1000000, 9999999)}',
            'bm_sv': f'{random.randint(1000000, 9999999)}__{random.randint(1000000, 9999999)}',
            '_abck': f'{hashlib.md5(f"{timestamp}{random.random()}".encode()).hexdigest()}_{timestamp}_-1__UTC',
            'X-BM-GB': f'{random.randint(1000000, 9999999)}.{random.randint(1000000, 9999999)}.{random.randint(1000000, 9999999)}.{random.randint(1000000, 9999999)}',
        }
        
        return cookies
    
    def _get_realistic_referer(self, url: str) -> str:
        """Generate a realistic referer for the request"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Common referers that look legitimate
        referers = [
            f'https://www.google.com/search?q=site:{domain}',
            f'https://www.google.com/',
            f'https://{domain}/',
            f'https://www.bing.com/search?q={domain}',
            f'https://duckduckgo.com/?q={domain}',
        ]
        
        return random.choice(referers)
    
    def _apply_akamai_bypass(self, url: str):
        """Apply advanced Akamai bypass techniques"""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Set Akamai-specific headers
        akamai_headers = self._get_akamai_bypass_headers()
        for key, value in akamai_headers.items():
            self.session.headers[key] = value
        
        # Add realistic referer
        self.session.headers['Referer'] = self._get_realistic_referer(url)
        
        # Add cookies
        cookies = self._get_akamai_cookies(domain)
        self.session.cookies.update(cookies)
        
        # Remove suspicious headers
        self.session.headers.pop('X-Requested-With', None)
        self.session.headers.pop('DNT', None)
        self.session.headers.pop('Sec-GPC', None)
        
        logger.info(f"Applied Akamai bypass for {domain}")
    
    def _get_cloudflare_bypass_headers(self) -> Dict[str, str]:
        """Get headers specifically for bypassing Cloudflare WAF"""
        return {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }
    
    def _get_aws_waf_bypass_headers(self) -> Dict[str, str]:
        """Get headers specifically for bypassing AWS WAF"""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0',
        }
    
    def _detect_waf(self, response) -> Optional[str]:
        """Detect which WAF is blocking the request"""
        headers = dict(response.headers)
        content = response.text if hasattr(response, 'text') else ''
        
        # Check headers
        server = headers.get('Server', '').lower()
        x_powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'akamai' in server or 'akamaighost' in server.lower():
            return 'akamai'
        if 'cloudflare' in server or 'cloudflare' in x_powered_by:
            return 'cloudflare'
        if 'aws' in server or 'awselb' in server:
            return 'aws'
        if 'incapsula' in server:
            return 'incapsula'
        if 'sucuri' in server:
            return 'sucuri'
        
        # Check content
        content_lower = content.lower()
        if 'akamai' in content_lower or 'edgesuite' in content_lower:
            return 'akamai'
        if 'cloudflare' in content_lower:
            return 'cloudflare'
        if 'aws waf' in content_lower:
            return 'aws'
        if 'incapsula' in content_lower:
            return 'incapsula'
        if 'sucuri' in content_lower:
            return 'sucuri'
        
        # Check status codes
        if response.status_code == 403:
            return 'unknown'
        
        return None
    
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
        detected_waf = None
        
        # Different header strategies for each attempt
        header_strategies = [
            'default',
            'akamai',
            'cloudflare',
            'aws',
        ]
        
        for attempt in range(max_attempts):
            try:
                # Add human-like delay
                self._human_like_delay()
                
                # Use different header strategy for each attempt
                if attempt > 0:
                    strategy = header_strategies[min(attempt, len(header_strategies) - 1)]
                    
                    if strategy == 'akamai':
                        headers = self._get_akamai_bypass_headers()
                        self.user_agent = headers['User-Agent']
                    elif strategy == 'cloudflare':
                        headers = self._get_cloudflare_bypass_headers()
                        self.user_agent = headers['User-Agent']
                    elif strategy == 'aws':
                        headers = self._get_aws_waf_bypass_headers()
                        self.user_agent = headers['User-Agent']
                    else:
                        self.user_agent = self._get_random_user_agent()
                        headers = None
                    
                    if headers:
                        # Update session headers with WAF-specific headers
                        for key, value in headers.items():
                            self.session.headers[key] = value
                
                # Make request
                logger.info(f"Fetching URL (attempt {attempt + 1}/{max_attempts}, strategy={header_strategies[min(attempt, len(header_strategies) - 1)]}): {url}")
                
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Check if we're being blocked by a WAF
                if response.status_code == 403:
                    detected_waf = self._detect_waf(response)
                    logger.warning(f"WAF detected: {detected_waf} - Status: {response.status_code}")
                    
                    # If we detected a specific WAF, use appropriate bypass for next attempt
                    if detected_waf == 'akamai' and attempt < max_attempts - 1:
                        # Try mobile mode first (Akamai is less aggressive with mobile)
                        if not self.mobile_mode and attempt == 0:
                            self.mobile_mode = True
                            self.user_agent = self._get_random_user_agent(mobile=True)
                            mobile_headers = self._get_mobile_headers()
                            for key, value in mobile_headers.items():
                                self.session.headers[key] = value
                            logger.info("Switching to mobile mode for Akamai bypass")
                            continue
                        else:
                            self._apply_akamai_bypass(url)
                            continue
                    elif detected_waf == 'cloudflare' and attempt < max_attempts - 1:
                        cf_headers = self._get_cloudflare_bypass_headers()
                        for key, value in cf_headers.items():
                            self.session.headers[key] = value
                        continue
                    elif detected_waf == 'aws' and attempt < max_attempts - 1:
                        aws_headers = self._get_aws_waf_bypass_headers()
                        for key, value in aws_headers.items():
                            self.session.headers[key] = value
                        continue
                
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
