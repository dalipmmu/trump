"""
HTTP Fetcher Module for SecretScout
Handles all HTTP requests, session management, and asset discovery
"""

import re
import time
import requests
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
import threading


@dataclass
class FetchResult:
    """Result of a fetch operation"""
    url: str
    status_code: int
    content: str
    headers: Dict[str, str]
    content_type: str
    encoding: str
    error: Optional[str] = None
    redirect_url: Optional[str] = None
    request_time: float = 0.0
    
    def is_success(self) -> bool:
        return 200 <= self.status_code < 400 and self.error is None
    
    def is_html(self) -> bool:
        return 'text/html' in self.content_type
    
    def is_json(self) -> bool:
        return 'application/json' in self.content_type
    
    def is_javascript(self) -> bool:
        return 'javascript' in self.content_type or 'application/x-javascript' in self.content_type
    
    def is_css(self) -> bool:
        return 'css' in self.content_type


class Fetcher:
    """HTTP fetcher with session management and rate limiting"""
    
    def __init__(self, 
                 user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecretScout/2.0",
                 timeout: int = 30,
                 max_retries: int = 3,
                 delay: float = 0.1,
                 max_concurrent: int = 10):
        
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.max_concurrent = max_concurrent
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        self._lock = threading.Semaphore(max_concurrent)
        self._visited_urls: Set[str] = set()
        self._rate_limit_delay = 0.0
    
    def fetch(self, url: str, method: str = 'GET', **kwargs) -> FetchResult:
        """Fetch a URL with retries and rate limiting"""
        with self._lock:
            time.sleep(self._rate_limit_delay)
        
        # Normalize URL
        url = self._normalize_url(url)
        
        # Check if already visited
        if url in self._visited_urls:
            return FetchResult(
                url=url,
                status_code=304,
                content="",
                headers={},
                content_type="",
                encoding="utf-8",
                error="Already visited"
            )
        
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                # Prepare request
                headers = kwargs.get('headers', {}).copy()
                headers.update(self.session.headers)
                
                # Make request
                response = self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=True,
                    **{k: v for k, v in kwargs.items() if k not in ['headers']}
                )
                
                # Parse response
                content_type = response.headers.get('Content-Type', '')
                encoding = response.encoding or 'utf-8'
                
                try:
                    content = response.text
                except Exception:
                    content = response.content.decode(encoding, errors='replace')
                
                result = FetchResult(
                    url=url,
                    status_code=response.status_code,
                    content=content,
                    headers=dict(response.headers),
                    content_type=content_type,
                    encoding=encoding,
                    redirect_url=response.url if response.url != url else None,
                    request_time=time.time() - start_time
                )
                
                # Mark as visited
                self._visited_urls.add(url)
                
                # Apply rate limiting based on response
                self._apply_rate_limiting(response)
                
                return result
                
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    self._visited_urls.add(url)
                    return FetchResult(
                        url=url,
                        status_code=0,
                        content="",
                        headers={},
                        content_type="",
                        encoding="utf-8",
                        error=str(e)
                    )
                time.sleep(self.delay * (attempt + 1))
        
        return FetchResult(
            url=url,
            status_code=0,
            content="",
            headers={},
            content_type="",
            encoding="utf-8",
            error="Max retries exceeded"
        )
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for consistent comparison"""
        parsed = urlparse(url)
        
        # Remove fragment
        parsed = parsed._replace(fragment='')
        
        # Normalize path
        if parsed.path and not parsed.path.endswith('/'):
            # Keep trailing slash for directories
            pass
        
        # Rebuild URL
        return urlunparse(parsed)
    
    def _apply_rate_limiting(self, response: requests.Response):
        """Apply rate limiting based on response headers"""
        # Check for rate limit headers
        rate_limit_reset = response.headers.get('X-RateLimit-Reset')
        if rate_limit_reset:
            try:
                reset_time = int(rate_limit_reset)
                current_time = int(time.time())
                delay = max(0, reset_time - current_time)
                self._rate_limit_delay = max(self._rate_limit_delay, delay)
            except ValueError:
                pass
        
        # Check for retry-after
        retry_after = response.headers.get('Retry-After')
        if retry_after:
            try:
                self._rate_limit_delay = max(self._rate_limit_delay, float(retry_after))
            except ValueError:
                pass
        
        # If we got a 429, increase delay
        if response.status_code == 429:
            self._rate_limit_delay = min(5.0, self._rate_limit_delay * 2)
    
    def fetch_async(self, url: str, **kwargs) -> Tuple[str, FetchResult]:
        """Fetch URL asynchronously (returns immediately with future)"""
        import concurrent.futures
        
        def fetch_wrapper():
            return self.fetch(url, **kwargs)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            future = executor.submit(fetch_wrapper)
            return url, future
    
    def fetch_multiple(self, urls: List[str], **kwargs) -> Dict[str, FetchResult]:
        """Fetch multiple URLs concurrently"""
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            future_to_url = {executor.submit(self.fetch, url, **kwargs): url for url in urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results[url] = future.result()
                except Exception as e:
                    results[url] = FetchResult(
                        url=url,
                        status_code=0,
                        content="",
                        headers={},
                        content_type="",
                        encoding="utf-8",
                        error=str(e)
                    )
        
        return results
    
    def extract_links(self, html: str, base_url: str) -> Set[str]:
        """Extract all links from HTML"""
        links = set()
        
        # Extract href attributes
        for match in re.finditer(r'href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1)
            absolute_url = self._make_absolute(url, base_url)
            if absolute_url:
                links.add(absolute_url)
        
        # Extract src attributes
        for match in re.finditer(r'src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1)
            absolute_url = self._make_absolute(url, base_url)
            if absolute_url:
                links.add(absolute_url)
        
        # Extract script src
        for match in re.finditer(r'<script\s+[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1)
            absolute_url = self._make_absolute(url, base_url)
            if absolute_url:
                links.add(absolute_url)
        
        # Extract link rel
        for match in re.finditer(r'<link\s+[^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1)
            absolute_url = self._make_absolute(url, base_url)
            if absolute_url:
                links.add(absolute_url)
        
        # Extract import statements (CSS/JS)
        for match in re.finditer(r'@import\s+["\']([^"\']+)["\']', html, re.IGNORECASE):
            url = match.group(1)
            absolute_url = self._make_absolute(url, base_url)
            if absolute_url:
                links.add(absolute_url)
        
        return links
    
    def extract_api_endpoints(self, content: str, base_url: str) -> Set[str]:
        """Extract API endpoints from content"""
        endpoints = set()
        
        # Look for URLs in JavaScript
        js_urls = re.findall(r'fetch\(["\']([^"\']+)["\']', content)
        js_urls += re.findall(r'axios\.get\(["\']([^"\']+)["\']', content)
        js_urls += re.findall(r'axios\.post\(["\']([^"\']+)["\']', content)
        js_urls += re.findall(r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']', content)
        js_urls += re.findall(r'XMLHttpRequest.*?open\([^)]*["\']([^"\']+)["\']', content)
        
        # Look for API endpoints in JSON
        json_urls = re.findall(r'"(https?://[^"]+/api/[^"]+)"', content)
        json_urls += re.findall(r'"(/api/[^"]+)"', content)
        
        # Look for endpoints in comments or strings
        all_urls = re.findall(r'(https?://[^\s"\']+/[^\s"\']+)', content)
        
        # Combine and normalize
        all_endpoints = js_urls + json_urls + all_urls
        
        for endpoint in all_endpoints:
            absolute_url = self._make_absolute(endpoint, base_url)
            if absolute_url and self._is_api_endpoint(absolute_url):
                endpoints.add(absolute_url)
        
        return endpoints
    
    def _make_absolute(self, url: str, base_url: str) -> Optional[str]:
        """Convert relative URL to absolute"""
        if not url or url.startswith('javascript:') or url.startswith('mailto:') or url.startswith('tel:'):
            return None
        
        if url.startswith('http://') or url.startswith('https://'):
            return url
        
        try:
            return urljoin(base_url, url)
        except Exception:
            return None
    
    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL looks like an API endpoint"""
        api_patterns = [
            r'/api/',
            r'/graphql',
            r'/rest/',
            r'/v[0-9]+/',
            r'\.json$',
            r'\.xml$',
            r'/endpoint/',
            r'/service/',
        ]
        
        for pattern in api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def check_cors(self, url: str) -> Dict[str, Any]:
        """Check CORS configuration for a URL"""
        try:
            # Send OPTIONS request
            result = self.fetch(url, method='OPTIONS')
            
            headers = result.headers
            cors_info = {
                'url': url,
                'access_control_allow_origin': headers.get('Access-Control-Allow-Origin', '*'),
                'access_control_allow_credentials': headers.get('Access-Control-Allow-Credentials', 'false'),
                'access_control_allow_methods': headers.get('Access-Control-Allow-Methods', ''),
                'access_control_allow_headers': headers.get('Access-Control-Allow-Headers', ''),
                'vulnerable': False,
                'issues': []
            }
            
            # Check for dangerous CORS configurations
            allow_origin = cors_info['access_control_allow_origin']
            allow_credentials = cors_info['access_control_allow_credentials'].lower()
            
            if allow_origin == '*' and allow_credentials == 'true':
                cors_info['vulnerable'] = True
                cors_info['issues'].append('Wildcard origin with credentials allows any site to make authenticated requests')
            
            if allow_origin == '*':
                cors_info['issues'].append('Wildcard origin allows any site to access this resource')
            
            if 'delete' in allow_origin.lower():
                cors_info['vulnerable'] = True
                cors_info['issues'].append('Potential CORS misconfiguration with dangerous methods')
            
            return cors_info
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'vulnerable': False,
                'issues': []
            }
    
    def check_security_headers(self, url: str) -> Dict[str, Any]:
        """Check security headers for a URL"""
        try:
            result = self.fetch(url)
            headers = result.headers
            
            security_headers = {
                'url': url,
                'csp': headers.get('Content-Security-Policy', ''),
                'hsts': headers.get('Strict-Transport-Security', ''),
                'x_frame_options': headers.get('X-Frame-Options', ''),
                'x_content_type_options': headers.get('X-Content-Type-Options', ''),
                'referrer_policy': headers.get('Referrer-Policy', ''),
                'permissions_policy': headers.get('Permissions-Policy', ''),
                'issues': []
            }
            
            # Check for missing or weak headers
            if not security_headers['csp']:
                security_headers['issues'].append('Missing Content-Security-Policy header')
            elif 'unsafe-inline' in security_headers['csp'] or 'unsafe-eval' in security_headers['csp']:
                security_headers['issues'].append('CSP contains unsafe directives (unsafe-inline, unsafe-eval)')
            
            if not security_headers['hsts']:
                security_headers['issues'].append('Missing Strict-Transport-Security header')
            elif 'includeSubDomains' not in security_headers['hsts']:
                security_headers['issues'].append('HSTS missing includeSubDomains directive')
            
            if not security_headers['x_frame_options']:
                security_headers['issues'].append('Missing X-Frame-Options header')
            elif security_headers['x_frame_options'] != 'DENY' and security_headers['x_frame_options'] != 'SAMEORIGIN':
                security_headers['issues'].append('X-Frame-Options not set to DENY or SAMEORIGIN')
            
            if not security_headers['x_content_type_options']:
                security_headers['issues'].append('Missing X-Content-Type-Options header')
            elif security_headers['x_content_type_options'] != 'nosniff':
                security_headers['issues'].append('X-Content-Type-Options not set to nosniff')
            
            if not security_headers['referrer_policy']:
                security_headers['issues'].append('Missing Referrer-Policy header')
            
            return security_headers
            
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'issues': []
            }
    
    def check_tls(self, url: str) -> Dict[str, Any]:
        """Check TLS configuration for a URL"""
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                return {
                    'url': url,
                    'uses_https': False,
                    'issues': ['Site does not use HTTPS']
                }
            
            # Try to get SSL info
            import ssl
            import socket
            
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=hostname
            )
            
            try:
                conn.connect((hostname, port))
                ssl_info = conn.getpeercert()
                
                tls_info = {
                    'url': url,
                    'uses_https': True,
                    'certificate': {
                        'subject': dict(x[0] for x in ssl_info.get('subject', [])),
                        'issuer': dict(x[0] for x in ssl_info.get('issuer', [])),
                        'version': ssl_info.get('version'),
                        'serialNumber': ssl_info.get('serialNumber'),
                        'notBefore': ssl_info.get('notBefore'),
                        'notAfter': ssl_info.get('notAfter'),
                    },
                    'protocol': conn.version(),
                    'cipher': conn.cipher(),
                    'issues': []
                }
                
                # Check for issues
                import datetime
                not_after = ssl_info.get('notAfter')
                if not_after:
                    expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.datetime.now()).days
                    if days_until_expiry < 30:
                        tls_info['issues'].append(f'Certificate expires in {days_until_expiry} days')
                    elif days_until_expiry < 90:
                        tls_info['issues'].append(f'Certificate expires in {days_until_expiry} days (consider renewal)')
                
                # Check protocol
                if 'TLSv1' in tls_info['protocol']:
                    tls_info['issues'].append('Using outdated TLS protocol (TLSv1)')
                elif 'TLSv1.1' in tls_info['protocol']:
                    tls_info['issues'].append('Using outdated TLS protocol (TLSv1.1)')
                
                return tls_info
                
            finally:
                conn.close()
                
        except Exception as e:
            return {
                'url': url,
                'error': str(e),
                'issues': []
            }
