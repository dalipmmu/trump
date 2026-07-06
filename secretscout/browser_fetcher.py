"""
Browser-based Fetcher Module for SecretScout
Uses Playwright to bypass WAF protection and fetch pages like a real browser
"""

import asyncio
import time
import re
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import logging

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class BrowserFetchResult:
    """Result of a browser fetch operation"""
    url: str
    status_code: int
    html: str
    page_title: str = ""
    page_url: str = ""  # Final URL after redirects
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    screenshot_path: Optional[str] = None
    har_log: Optional[Dict] = None
    
    @property
    def success(self) -> bool:
        return self.status_code == 200 and not self.error


class BrowserFetcher:
    """
    NSA-GRADE Browser-based Fetcher
    Uses Playwright to bypass WAF and fetch pages with real browser behavior
    """
    
    def __init__(
        self,
        headless: bool = True,
        slow_mo: int = 50,  # Milliseconds to slow down operations
        timeout: int = 30000,  # 30 seconds
        max_retries: int = 3,
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        viewport_width: int = 1920,
        viewport_height: int = 1080,
        device_scale_factor: int = 1,
        locale: str = 'en-US',
        timezone_id: str = 'America/New_York',
    ):
        self.headless = headless
        self.slow_mo = slow_mo
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or self._get_random_user_agent()
        self.proxy = proxy
        self.viewport = {'width': viewport_width, 'height': viewport_height}
        self.device_scale_factor = device_scale_factor
        self.locale = locale
        self.timezone_id = timezone_id
        
        # Browser instance
        self.browser = None
        self.browser_context = None
        self.page = None
        
        # Session state
        self._visited_urls: Set[str] = set()
        self._cookies: Dict[str, str] = {}
        self._rate_limit_delay: float = 0.0
        
        # HAR logging
        self.har_log: Optional[Dict] = None
        
        # Initialize browser
        self._initialize_browser()
    
    def _get_random_user_agent(self) -> str:
        """Get a random modern browser user agent"""
        user_agents = [
            # Chrome on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            
            # Chrome on Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            
            # Firefox on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            
            # Firefox on Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
            
            # Safari on Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15',
            
            # Edge on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            
            # Mobile - iPhone
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
            
            # Mobile - Android
            'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (Linux; Android 12; SM-A525F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        ]
        return user_agents[0]  # Use Chrome Windows as default
    
    def _initialize_browser(self):
        """Initialize Playwright browser"""
        try:
            from playwright.sync_api import sync_playwright
            self.playwright_instance = sync_playwright().start()
        except ImportError:
            raise ImportError(
                "Playwright is not installed. Please install it with: "
                "pip install playwright && playwright install"
            )
        
        # Start browser - try with system chromium first, then fallback to bundled
        try:
            self.browser = self.playwright_instance.chromium.launch(
                headless=self.headless,
                slow_mo=self.slow_mo,
                proxy=self.proxy,
                channel='chrome',  # Try system chrome/chromium
            )
        except:
            try:
                self.browser = self.playwright_instance.chromium.launch(
                    headless=self.headless,
                    slow_mo=self.slow_mo,
                    proxy=self.proxy,
                )
            except Exception as e:
                logger.error(f"Failed to launch browser: {e}")
                raise
        
        # Create context with realistic settings
        context_options = {
            'viewport': self.viewport,
            'device_scale_factor': self.device_scale_factor,
            'locale': self.locale,
            'timezone_id': self.timezone_id,
            'user_agent': self.user_agent,
            'java_script_enabled': True,
            'ignore_https_errors': True,
        }
        
        # Add permissions
        context_options['permissions'] = ['geolocation', 'notifications', 'camera', 'microphone']
        
        # Create context
        self.browser_context = self.browser.new_context(**context_options)
        
        # Add realistic headers
        self.browser_context.set_extra_http_headers({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        })
        
        # Create page
        self.page = self.browser_context.new_page()
        
        # Set default timeout
        self.page.set_default_timeout(self.timeout)
        
        logger.info(f"Browser initialized: headless={self.headless}, user_agent={self.user_agent[:50]}...")
    
    def _human_like_delay(self):
        """Add human-like random delay"""
        import random
        time.sleep(random.uniform(0.5, 2.5))
    
    def _simulate_human_behavior(self, page):
        """Simulate human-like mouse movements and scrolling"""
        import random
        
        # Random mouse movement
        if random.random() > 0.7:
            x = random.randint(100, self.viewport['width'] - 100)
            y = random.randint(100, self.viewport['height'] - 100)
            page.mouse.move(x, y)
            
        # Random scroll
        if random.random() > 0.5:
            scroll_amount = random.randint(100, 500)
            page.mouse.wheel(0, scroll_amount)
            
        # Random small delay
        time.sleep(random.uniform(0.1, 0.5))
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _get_domain(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc
    
    def fetch(self, url: str, **kwargs) -> BrowserFetchResult:
        """
        Fetch a URL using browser automation
        
        Args:
            url: URL to fetch
            **kwargs: Additional options
                - wait_until: 'domcontentloaded', 'load', 'networkidle'
                - take_screenshot: bool
                - extract_links: bool
                - click_element: CSS selector to click
                - fill_form: dict of {selector: value}
        
        Returns:
            BrowserFetchResult with page content and metadata
        """
        url = self._normalize_url(url)
        
        # Check if already visited
        if url in self._visited_urls:
            logger.info(f"Skipping already visited URL: {url}")
            return BrowserFetchResult(
                url=url,
                status_code=304,
                html="",
                error="Already visited"
            )
        
        wait_until = kwargs.get('wait_until', 'networkidle')
        take_screenshot = kwargs.get('take_screenshot', False)
        extract_links = kwargs.get('extract_links', False)
        click_element = kwargs.get('click_element')
        fill_form = kwargs.get('fill_form')
        
        max_attempts = self.max_retries + 1
        last_error = None
        
        for attempt in range(max_attempts):
            try:
                # Navigate to page
                logger.info(f"Fetching URL (attempt {attempt + 1}/{max_attempts}): {url}")
                
                # Add human-like delay before navigation
                self._human_like_delay()
                
                # Navigate
                response = self.page.goto(url, wait_until=wait_until, timeout=self.timeout)
                
                # Check if navigation was successful
                if response is None or not response.ok:
                    status_code = 404 if response is None else response.status
                    last_error = f"Navigation failed with status {status_code}"
                    logger.warning(f"Navigation failed: {url} - {last_error}")
                    
                    # Try to get current page content anyway
                    html = self.page.content()
                    if 'Access Denied' in html or '403' in html:
                        logger.warning(f"WAF blocked request to {url}")
                        last_error = "WAF blocked request"
                    
                    if attempt < max_attempts - 1:
                        # Wait and retry
                        time.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    else:
                        return BrowserFetchResult(
                            url=url,
                            status_code=status_code,
                            html=html,
                            error=last_error
                        )
                
                # Simulate human behavior
                self._simulate_human_behavior(self.page)
                
                # Wait for page to fully load
                time.sleep(1)
                
                # Handle form filling if requested
                if fill_form:
                    for selector, value in fill_form.items():
                        try:
                            self.page.fill(selector, value)
                            time.sleep(0.5)
                        except Exception as e:
                            logger.warning(f"Failed to fill form field {selector}: {e}")
                
                # Handle element clicking if requested
                if click_element:
                    try:
                        self.page.click(click_element)
                        time.sleep(1)
                        # Wait for navigation if click triggered it
                        try:
                            self.page.wait_for_load_state('networkidle', timeout=10000)
                        except:
                            pass
                    except Exception as e:
                        logger.warning(f"Failed to click element {click_element}: {e}")
                
                # Get final page state
                html = self.page.content()
                page_title = self.page.title()
                page_url = self.page.url
                status_code = response.status
                
                # Get cookies
                cookies = self.page.context.cookies()
                cookies_dict = {c['name']: c['value'] for c in cookies}
                
                # Get response headers
                headers = dict(response.headers) if response else {}
                
                # Take screenshot if requested
                screenshot_path = None
                if take_screenshot:
                    import os
                    screenshot_dir = '/tmp/secretscout_screenshots'
                    os.makedirs(screenshot_dir, exist_ok=True)
                    screenshot_path = f'{screenshot_dir}/{int(time.time())}_{urlparse(url).netloc}.png'
                    self.page.screenshot(path=screenshot_path)
                    logger.info(f"Screenshot saved: {screenshot_path}")
                
                # Mark as visited
                self._visited_urls.add(url)
                self._visited_urls.add(page_url)
                
                # Update cookies
                self._cookies.update(cookies_dict)
                
                logger.info(f"Successfully fetched: {url} -> {page_url} ({status_code})")
                
                return BrowserFetchResult(
                    url=url,
                    status_code=status_code,
                    html=html,
                    page_title=page_title,
                    page_url=page_url,
                    headers=headers,
                    cookies=cookies_dict,
                    screenshot_path=screenshot_path
                )
                
            except Exception as e:
                last_error = str(e)
                logger.error(f"Error fetching {url} (attempt {attempt + 1}): {e}")
                
                if attempt < max_attempts - 1:
                    time.sleep(2 ** attempt)
                    continue
                else:
                    return BrowserFetchResult(
                        url=url,
                        status_code=500,
                        html="",
                        error=last_error
                    )
        
        return BrowserFetchResult(
            url=url,
            status_code=500,
            html="",
            error=last_error
        )
    
    def fetch_multiple(self, urls: List[str], **kwargs) -> List[BrowserFetchResult]:
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
        for tag in soup.find_all(['script', 'img', 'iframe', 'video', 'audio'], src=True):
            src = tag['src']
            if src and not src.startswith(('javascript:', 'data:')):
                absolute_url = urljoin(base_url, src)
                links.add(absolute_url)
        
        # Extract form actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            if action:
                absolute_url = urljoin(base_url, action)
                links.add(absolute_url)
        
        # Filter and normalize
        filtered_links = []
        for link in links:
            # Skip non-HTTP links
            if not link.startswith(('http://', 'https://')):
                continue
            # Normalize
            link = link.split('#')[0].split('?')[0].rstrip('/')
            filtered_links.append(link)
        
        return list(set(filtered_links))
    
    def extract_api_endpoints(self, html: str, base_url: str) -> List[str]:
        """Extract potential API endpoints from HTML and JavaScript"""
        endpoints = set()
        
        # Look for API URLs in JavaScript
        js_patterns = [
            r'https?://[^/]+/api[^/]*',
            r'https?://[^/]+/v[0-9]+[^/]*',
            r'https?://[^/]+/graphql[^/]*',
            r'https?://[^/]+/rest[^/]*',
            r'https?://[^/]+/wp-json[^/]*',
            r'\"https?://[^\"]+\"',
            r"'https?://[^']+'",
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                # Clean up the match
                endpoint = match.strip('"\'')
                if any(x in endpoint.lower() for x in ['api', 'graphql', 'rest', 'json', 'endpoint']):
                    endpoints.add(endpoint)
        
        # Look for fetch/XHR calls
        fetch_patterns = [
            r'fetch\([\"\'](https?://[^\"\']+)[\"\']',
            r'axios\.(get|post|put|delete)\([\"\'](https?://[^\"\']+)[\"\']',
            r'\.ajax\([^)]*url:\s*[\"\'](https?://[^\"\']+)[\"\']',
            r'XMLHttpRequest.*?open\([^)]*[\"\'](GET|POST|PUT|DELETE)[\"\']\s*,\s*[\"\'](https?://[^\"\']+)[\"\']',
        ]
        
        for pattern in fetch_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[-1]  # Last element is usually the URL
                else:
                    endpoint = match
                endpoint = endpoint.strip('"\'')
                if endpoint.startswith(('http://', 'https://')):
                    endpoints.add(endpoint)
        
        return list(endpoints)
    
    def extract_secrets_from_page(self, html: str, url: str):
        """Extract secrets from a page using existing pattern matching"""
        from .patterns import find_secrets_in_text
        from .storage import Finding
        
        findings = find_secrets_in_text(html, url)
        return findings
    
    def close(self):
        """Close the browser"""
        try:
            if self.page:
                self.page.close()
        except:
            pass
        try:
            if self.browser_context:
                self.browser_context.close()
        except:
            pass
        try:
            if self.browser:
                self.browser.close()
        except:
            pass
        try:
            if hasattr(self, 'playwright_instance') and self.playwright_instance:
                self.playwright_instance.stop()
        except:
            pass
        logger.info("Browser closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def __del__(self):
        self.close()


class AsyncBrowserFetcher:
    """
    Async version of BrowserFetcher for concurrent requests
    """
    
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.browser = None
        self._lock = asyncio.Lock()
    
    async def __aenter__(self):
        self.browser = BrowserFetcher(**self.kwargs)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.browser:
            self.browser.close()
    
    async def fetch(self, url: str, **kwargs) -> BrowserFetchResult:
        """Async fetch using browser"""
        async with self._lock:
            # For now, use sync version (Playwright has async API but we need to handle it properly)
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self.browser.fetch, url, **kwargs)
