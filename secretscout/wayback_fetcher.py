"""
WayBack Machine Fetcher for SecretScout
Bypasses WAF by scanning archived versions of websites
"""

import requests
import time
import random
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import logging

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class WayBackResult:
    """Result from WayBack Machine fetch"""
    url: str
    timestamp: str
    status_code: int
    html: str
    success: bool = False
    error: Optional[str] = None


class WayBackFetcher:
    """
    Fetches archived versions of websites from WayBack Machine
    Useful for bypassing WAF protection on live sites
    """
    
    def __init__(self, delay: float = 1.0, max_snapshots: int = 10):
        self.delay = delay
        self.max_snapshots = max_snapshots
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
    
    def get_snapshots(self, url: str, from_year: int = 2020, to_year: int = 2026) -> List[Dict[str, str]]:
        """
        Get list of snapshots for a URL from WayBack Machine
        
        Args:
            url: URL to search for
            from_year: Start year
            to_year: End year
        
        Returns:
            List of snapshot metadata
        """
        # Normalize URL
        url = url.rstrip('/').replace('https://', 'http://')
        
        # Build CDX API URL
        cdx_url = f'http://web.archive.org/cdx/search/cdx?url={url}/*&output=json&limit={self.max_snapshots}&from={from_year}&to={to_year}'
        
        try:
            response = self.session.get(cdx_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if len(data) > 1:  # Skip header row
                    snapshots = []
                    for row in data[1:]:  # Skip header
                        if len(row) >= 5:
                            snapshots.append({
                                'timestamp': row[1],
                                'url': row[2],
                                'original': row[3],
                                'status': row[4],
                                'digest': row[5] if len(row) > 5 else None
                            })
                    return snapshots
            return []
        except Exception as e:
            logger.error(f"Error fetching snapshots: {e}")
            return []
    
    def fetch_snapshot(self, snapshot_url: str) -> WayBackResult:
        """
        Fetch a specific snapshot from WayBack Machine
        
        Args:
            snapshot_url: Full WayBack Machine URL
        
        Returns:
            WayBackResult with snapshot content
        """
        try:
            # Add delay to be polite
            time.sleep(self.delay)
            
            response = self.session.get(snapshot_url, timeout=60, allow_redirects=True)
            
            # Extract timestamp from URL
            timestamp = snapshot_url.split('/')[4] if '/' in snapshot_url else 'unknown'
            
            return WayBackResult(
                url=snapshot_url,
                timestamp=timestamp,
                status_code=response.status_code,
                html=response.text,
                success=response.status_code == 200,
                error=None if response.status_code == 200 else f"HTTP {response.status_code}"
            )
        except Exception as e:
            return WayBackResult(
                url=snapshot_url,
                timestamp='unknown',
                status_code=500,
                html='',
                success=False,
                error=str(e)
            )
    
    def fetch_recent_snapshots(self, url: str, count: int = 5) -> List[WayBackResult]:
        """
        Fetch recent snapshots for a URL
        
        Args:
            url: URL to fetch snapshots for
            count: Number of recent snapshots to fetch
        
        Returns:
            List of WayBackResult objects
        """
        snapshots = self.get_snapshots(url)
        results = []
        
        for snapshot in snapshots[:count]:
            snapshot_url = f"http://web.archive.org/web/{snapshot['timestamp']}/{snapshot['url']}"
            result = self.fetch_snapshot(snapshot_url)
            results.append(result)
            
            # Respect WayBack Machine rate limits
            time.sleep(2)
        
        return results
    
    def scan_with_wayback(self, url: str, scan_function, count: int = 5):
        """
        Scan a URL using WayBack Machine snapshots
        
        Args:
            url: URL to scan
            scan_function: Function to scan HTML content
            count: Number of snapshots to scan
        
        Returns:
            List of findings from all snapshots
        """
        snapshots = self.get_snapshots(url)
        all_findings = []
        
        print(f"[WAYBACK] Found {len(snapshots)} snapshots for {url}")
        
        for i, snapshot in enumerate(snapshots[:count], 1):
            snapshot_url = f"http://web.archive.org/web/{snapshot['timestamp']}/{snapshot['url']}"
            print(f"[WAYBACK] Scanning snapshot {i}/{min(count, len(snapshots))}: {snapshot['timestamp']}")
            
            result = self.fetch_snapshot(snapshot_url)
            
            if result.success:
                findings = scan_function(result.html, snapshot_url)
                all_findings.extend(findings)
                print(f"[WAYBACK] Found {len(findings)} findings in snapshot {snapshot['timestamp']}")
            else:
                print(f"[WAYBACK] Failed to fetch snapshot: {result.error}")
            
            time.sleep(2)  # Rate limiting
        
        return all_findings
    
    def close(self):
        """Close the session"""
        self.session.close()


def scan_wayback_for_secrets(url: str, count: int = 5):
    """
    Convenience function to scan WayBack Machine snapshots for secrets
    
    Args:
        url: URL to scan
        count: Number of snapshots to check
    
    Returns:
        List of findings
    """
    from .patterns import find_secrets_in_text
    
    fetcher = WayBackFetcher()
    findings = fetcher.scan_with_wayback(url, find_secrets_in_text, count)
    fetcher.close()
    return findings
