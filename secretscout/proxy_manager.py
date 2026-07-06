"""
Proxy Manager for SecretScout
Manages residential and datacenter proxies for WAF bypass
"""

import random
import requests
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import logging

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    protocol: str = "http"
    proxy_type: str = "datacenter"  # datacenter, residential, mobile
    country: Optional[str] = None
    
    @property
    def url(self) -> str:
        """Get proxy URL"""
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.protocol}://{auth}{self.host}:{self.port}"


class ProxyManager:
    """
    Manages proxy rotation for WAF bypass
    Supports residential, datacenter, and mobile proxies
    """
    
    def __init__(self):
        self.proxies: List[ProxyConfig] = []
        self.current_index = 0
        self.failed_proxies: List[str] = []
    
    def add_proxy(self, host: str, port: int, username: str = None, password: str = None, 
                  protocol: str = "http", proxy_type: str = "datacenter", country: str = None):
        """Add a proxy to the pool"""
        proxy = ProxyConfig(
            host=host,
            port=port,
            username=username,
            password=password,
            protocol=protocol,
            proxy_type=proxy_type,
            country=country
        )
        self.proxies.append(proxy)
        logger.info(f"Added proxy: {proxy.url} ({proxy_type})")
    
    def add_proxies_from_list(self, proxy_list: List[str], proxy_type: str = "datacenter"):
        """Add multiple proxies from a list"""
        for proxy_str in proxy_list:
            proxy_str = proxy_str.strip()
            if not proxy_str:
                continue
            
            # Parse proxy string (host:port or protocol://host:port)
            if '://' in proxy_str:
                protocol, rest = proxy_str.split('://', 1)
            else:
                protocol = 'http'
                rest = proxy_str
            
            if '@' in rest:
                auth, host_port = rest.split('@', 1)
                if ':' in auth:
                    username, password = auth.split(':', 1)
                else:
                    username = auth
                    password = None
            else:
                username = None
                password = None
                host_port = rest
            
            if ':' in host_port:
                host, port = host_port.split(':', 1)
                try:
                    port = int(port)
                except ValueError:
                    continue
            else:
                host = host_port
                port = 80 if protocol == 'http' else 443
            
            self.add_proxy(host, port, username, password, protocol, proxy_type)
    
    def get_next_proxy(self) -> Optional[ProxyConfig]:
        """Get the next proxy in rotation"""
        if not self.proxies:
            return None
        
        # Rotate proxies
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def get_random_proxy(self) -> Optional[ProxyConfig]:
        """Get a random proxy"""
        if not self.proxies:
            return None
        return random.choice(self.proxies)
    
    def get_working_proxy(self, test_url: str = "https://httpbin.org/ip") -> Optional[ProxyConfig]:
        """Get a working proxy (tests proxies until one works)"""
        tested = set()
        
        while self.proxies:
            proxy = self.get_next_proxy()
            if proxy.url in tested:
                continue
            
            tested.add(proxy.url)
            
            try:
                response = requests.get(
                    test_url,
                    proxies={"http": proxy.url, "https": proxy.url},
                    timeout=10
                )
                if response.status_code == 200:
                    logger.info(f"Found working proxy: {proxy.url}")
                    return proxy
                else:
                    logger.warning(f"Proxy {proxy.url} returned {response.status_code}")
            except Exception as e:
                logger.warning(f"Proxy {proxy.url} failed: {e}")
                self.failed_proxies.append(proxy.url)
        
        return None
    
    def mark_failed(self, proxy_url: str):
        """Mark a proxy as failed"""
        if proxy_url not in self.failed_proxies:
            self.failed_proxies.append(proxy_url)
            logger.warning(f"Marked proxy as failed: {proxy_url}")
    
    def get_proxy_count(self) -> int:
        """Get total proxy count"""
        return len(self.proxies)
    
    def get_working_count(self) -> int:
        """Get count of working proxies"""
        return len(self.proxies) - len(self.failed_proxies)


# Global proxy manager instance
proxy_manager = ProxyManager()


def get_session_with_proxy() -> requests.Session:
    """Get a requests session with a working proxy"""
    session = requests.Session()
    
    proxy = proxy_manager.get_working_proxy()
    if proxy:
        session.proxies = {"http": proxy.url, "https": proxy.url}
        logger.info(f"Using proxy: {proxy.url}")
    
    return session


# Free proxy lists (for testing - residential proxies require paid services)
FREE_PROXY_LISTS = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]


def load_free_proxies(count: int = 20):
    """Load free proxies from public lists"""
    proxies_added = 0
    
    for proxy_list_url in FREE_PROXY_LISTS:
        if proxies_added >= count:
            break
        
        try:
            response = requests.get(proxy_list_url, timeout=30)
            if response.status_code == 200:
                proxy_lines = response.text.strip().split('\n')
                for line in proxy_lines:
                    if proxies_added >= count:
                        break
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxy_manager.add_proxy(line, proxy_type="free")
                        proxies_added += 1
        except Exception as e:
            logger.warning(f"Failed to load proxy list {proxy_list_url}: {e}")
    
    logger.info(f"Loaded {proxies_added} free proxies")
    return proxies_added
