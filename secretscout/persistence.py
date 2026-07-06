"""
NSA-Grade Persistence Module for SecretScout
SQLite-based storage with proper indexing and querying
"""

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from dataclasses import asdict

from .storage import Finding, Severity, DataClass


class NSAFindingStore:
    """
    NSA-Grade SQLite-based finding storage
    Provides efficient querying, indexing, and persistence
    """
    
    def __init__(self, db_path: str = 'findings.db'):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database with proper schema"""
        with self._get_connection() as conn:
            # Create findings table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    title TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    technique_name TEXT,
                    url TEXT,
                    secret_value TEXT,
                    redacted_value TEXT,
                    severity TEXT NOT NULL,
                    data_class TEXT,
                    provider TEXT,
                    impact TEXT,
                    remediation TEXT,
                    confirmed_live BOOLEAN DEFAULT FALSE,
                    allowlist BOOLEAN DEFAULT FALSE,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_false_positive BOOLEAN DEFAULT FALSE,
                    UNIQUE(scan_id, target, technique, secret_value)
                )
            ''')
            
            # Create scans table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    start_time TIMESTAMP NOT NULL,
                    end_time TIMESTAMP,
                    finding_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    techniques_used TEXT,
                    classification TEXT DEFAULT 'UNKNOWN'
                )
            ''')
            
            # Create false positives table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS false_positives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    secret_hash TEXT NOT NULL UNIQUE,
                    secret_value TEXT,
                    reason TEXT,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_id ON findings(scan_id)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_target ON findings(target)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_provider ON findings(provider)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_data_class ON findings(data_class)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_confirmed_live ON findings(confirmed_live)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_false_positive ON findings(is_false_positive)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_scan_start ON scans(start_time)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_fp_hash ON false_positives(secret_hash)')
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def add_finding(self, finding: Finding, scan_id: str):
        """Add a finding to the database"""
        severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
        data_class = finding.data_class.value if hasattr(finding.data_class, 'value') else str(finding.data_class)
        
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR IGNORE INTO findings 
                (scan_id, target, title, technique, technique_name, url, secret_value,
                 redacted_value, severity, data_class, provider, impact, remediation,
                 confirmed_live, allowlist, is_false_positive)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                finding.url,
                finding.title,
                finding.technique,
                finding.technique_name,
                finding.url,
                finding.secret_value,
                finding.redacted_value,
                severity,
                data_class,
                finding.provider,
                finding.impact,
                finding.remediation,
                finding.confirmed_live,
                finding.allowlist,
                finding.is_false_positive
            ))
    
    def get_findings(self, scan_id: str = None, target: str = None, 
                    severity: str = None, provider: str = None,
                    limit: int = None) -> List[Finding]:
        """Get findings with filtering"""
        query = 'SELECT * FROM findings'
        params = []
        
        conditions = []
        if scan_id:
            conditions.append('scan_id = ?')
            params.append(scan_id)
        if target:
            conditions.append('target = ?')
            params.append(target)
        if severity:
            conditions.append('severity = ?')
            params.append(severity)
        if provider:
            conditions.append('provider = ?')
            params.append(provider)
        
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        
        query += ' ORDER BY last_seen DESC'
        
        if limit:
            query += f' LIMIT {limit}'
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [self._row_to_finding(row) for row in cursor.fetchall()]
    
    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan metadata"""
        with self._get_connection() as conn:
            cursor = conn.execute('SELECT * FROM scans WHERE scan_id = ?', (scan_id,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    def get_scans(self, limit: int = None, severity: str = None) -> List[Dict]:
        """Get list of scans"""
        query = 'SELECT * FROM scans'
        params = []
        
        if severity:
            # Filter by severity count
            if severity == 'critical':
                query += ' WHERE critical_count > 0'
            elif severity == 'high':
                query += ' WHERE high_count > 0'
            elif severity == 'medium':
                query += ' WHERE medium_count > 0'
            elif severity == 'low':
                query += ' WHERE low_count > 0'
        
        query += ' ORDER BY start_time DESC'
        
        if limit:
            query += f' LIMIT {limit}'
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def save_scan_metadata(self, scan_id: str, target: str, start_time: datetime,
                          end_time: datetime, finding_count: int,
                          critical_count: int, high_count: int, 
                          medium_count: int, low_count: int,
                          techniques_used: List[str], classification: str):
        """Save scan metadata"""
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR REPLACE INTO scans 
                (scan_id, target, start_time, end_time, finding_count,
                 critical_count, high_count, medium_count, low_count,
                 techniques_used, classification)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                target,
                start_time.isoformat() if isinstance(start_time, datetime) else start_time,
                end_time.isoformat() if isinstance(end_time, datetime) else end_time,
                finding_count,
                critical_count,
                high_count,
                medium_count,
                low_count,
                ','.join(techniques_used),
                classification
            ))
    
    def mark_false_positive(self, finding_id: int, reason: str = None):
        """Mark a finding as false positive"""
        with self._get_connection() as conn:
            # Get the finding first
            cursor = conn.execute('SELECT secret_value FROM findings WHERE id = ?', (finding_id,))
            row = cursor.fetchone()
            if row:
                secret_value = row['secret_value']
                # Add to false positives table
                conn.execute('''
                    INSERT OR IGNORE INTO false_positives (secret_hash, secret_value, reason)
                    VALUES (?, ?, ?)
                ''', (self._hash_secret(secret_value), secret_value, reason))
                
                # Mark as false positive in findings
                conn.execute('''
                    UPDATE findings SET is_false_positive = TRUE WHERE id = ?
                ''', (finding_id,))
    
    def is_known_false_positive(self, secret_value: str) -> bool:
        """Check if a secret is a known false positive"""
        secret_hash = self._hash_secret(secret_value)
        with self._get_connection() as conn:
            cursor = conn.execute('SELECT 1 FROM false_positives WHERE secret_hash = ?', (secret_hash,))
            return cursor.fetchone() is not None
    
    def add_false_positive(self, secret_value: str, reason: str = None):
        """Add a secret to the false positives list"""
        secret_hash = self._hash_secret(secret_value)
        with self._get_connection() as conn:
            conn.execute('''
                INSERT OR IGNORE INTO false_positives (secret_hash, secret_value, reason)
                VALUES (?, ?, ?)
            ''', (secret_hash, secret_value, reason))
    
    def get_stats(self) -> Dict:
        """Get statistics"""
        with self._get_connection() as conn:
            # Get counts by severity
            cursor = conn.execute('''
                SELECT 
                    severity,
                    COUNT(*) as count,
                    SUM(CASE WHEN confirmed_live THEN 1 ELSE 0 END) as live_count,
                    SUM(CASE WHEN is_false_positive THEN 1 ELSE 0 END) as fp_count
                FROM findings
                GROUP BY severity
            ''')
            
            by_severity = {}
            for row in cursor.fetchall():
                by_severity[row['severity']] = {
                    'total': row['count'],
                    'live': row['live_count'],
                    'false_positives': row['fp_count']
                }
            
            # Get total counts
            cursor = conn.execute('SELECT COUNT(*) FROM findings')
            total = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM findings WHERE confirmed_live = TRUE')
            live_total = cursor.fetchone()[0]
            
            cursor = conn.execute('SELECT COUNT(*) FROM false_positives')
            fp_total = cursor.fetchone()[0]
            
            return {
                'total_findings': total,
                'live_findings': live_total,
                'false_positives': fp_total,
                'by_severity': by_severity
            }
    
    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        """Convert database row to Finding object"""
        return Finding(
            title=row['title'],
            technique=row['technique'],
            technique_name=row['technique_name'],
            url=row['url'],
            secret_value=row['secret_value'],
            redacted_value=row['redacted_value'],
            severity=Severity(row['severity']),
            data_class=DataClass(row['data_class']) if row['data_class'] else None,
            provider=row['provider'],
            impact=row['impact'],
            remediation=row['remediation'],
            confirmed_live=bool(row['confirmed_live']),
            allowlist=bool(row['allowlist']),
            is_false_positive=bool(row['is_false_positive'])
        )
    
    def _hash_secret(self, secret: str) -> str:
        """Create a hash of a secret for storage"""
        import hashlib
        return hashlib.sha256(secret.encode()).hexdigest()
    
    def generate_summary(self, target_url: str = "", target_project: str = "", 
                       techniques_used: List[str] = None):
        """Generate scan summary (compatible with existing code)"""
        findings = self.get_findings()
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Classify scan
        classification = 'CLEAN'
        if severity_counts['critical'] > 0:
            classification = 'CRITICAL'
        elif severity_counts['high'] > 0:
            classification = 'HIGH_RISK'
        elif any(severity_counts.values()):
            classification = 'MEDIUM_RISK'
        
        # Save scan metadata
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.save_scan_metadata(
            scan_id=scan_id,
            target=target_url or target_project or 'unknown',
            start_time=datetime.now(),
            end_time=datetime.now(),
            finding_count=len(findings),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
            techniques_used=techniques_used or [],
            classification=classification
        )
        
        return {
            'scan_id': scan_id,
            'target': target_url or target_project or 'unknown',
            'total_findings': len(findings),
            'by_severity': severity_counts,
            'classification': classification,
            'techniques_used': techniques_used or []
        }


# Create a global instance for easy access
nsa_store = NSAFindingStore()
