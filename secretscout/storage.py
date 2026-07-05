"""
Storage Module for SecretScout
Handles finding storage, severity management, and summary generation
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    """Severity levels for findings"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DataClass(Enum):
    """Data classification for findings"""
    CREDENTIAL = "Credential"
    FINANCIAL = "Financial"
    PII = "PII"
    SOURCE = "Source"
    INFRA = "Infra"


@dataclass
class Finding:
    """Represents a single vulnerability finding"""
    
    # Unique identifier
    id: str = field(default_factory=lambda: hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:12])
    
    # Finding details
    technique: str = ""
    technique_name: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    data_class: DataClass = DataClass.CREDENTIAL
    
    # Evidence
    url: str = ""
    evidence: str = ""
    secret_value: Optional[str] = None
    redacted_value: str = ""
    
    # Context
    context: str = ""
    provider: Optional[str] = None
    allowlist: bool = False
    
    # Status
    confirmed_live: bool = False
    is_false_positive: bool = False
    
    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.now)
    
    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Attack chain information
    attack_chain: List[str] = field(default_factory=list)
    
    # Remediation
    remediation: str = ""
    impact: str = ""
    
    def to_dict(self, reveal_secrets: bool = False) -> Dict[str, Any]:
        """Convert finding to dictionary, optionally revealing secrets"""
        result = asdict(self)
        
        # Convert enums to strings
        result['severity'] = self.severity.value
        result['data_class'] = self.data_class.value
        
        # Handle datetime
        result['discovered_at'] = self.discovered_at.isoformat()
        
        # Redact secrets if not revealing
        if not reveal_secrets and self.secret_value:
            result['secret_value'] = self.redacted_value
        
        return result
    
    def get_severity_weight(self) -> int:
        """Get numeric weight for severity"""
        weights = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5
        }
        return weights.get(self.severity, 0)


@dataclass
class ScanSummary:
    """Summary of a scan"""
    
    scan_id: str
    target_url: str
    target_project: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Technique usage
    techniques_used: List[str] = field(default_factory=list)
    
    # Finding counts
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_technique: Dict[str, int] = field(default_factory=dict)
    findings_by_data_class: Dict[str, int] = field(default_factory=dict)
    
    # Live validation
    live_keys_confirmed: int = 0
    live_keys_revoked: int = 0
    
    # Attack chains
    attack_chains: List[Dict] = field(default_factory=list)
    
    # Risk score
    risk_score: float = 0.0
    risk_level: str = "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert summary to dictionary"""
        result = asdict(self)
        result['started_at'] = self.started_at.isoformat()
        if self.completed_at:
            result['completed_at'] = self.completed_at.isoformat()
        return result


class FindingStore:
    """Central storage for all findings"""
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.summary: Optional[ScanSummary] = None
        self.scan_id: str = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
    
    def add_finding(self, finding: Finding) -> Finding:
        """Add a finding to the store"""
        # Check for duplicates
        for existing in self.findings:
            if (existing.url == finding.url and 
                existing.title == finding.title and
                existing.secret_value == finding.secret_value):
                return existing
        
        self.findings.append(finding)
        return finding
    
    def add_findings(self, findings: List[Finding]) -> List[Finding]:
        """Add multiple findings"""
        added = []
        for finding in findings:
            added.append(self.add_finding(finding))
        return added
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings by severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_technique(self, technique: str) -> List[Finding]:
        """Get findings by technique"""
        return [f for f in self.findings if f.technique == technique]
    
    def get_findings_by_data_class(self, data_class: DataClass) -> List[Finding]:
        """Get findings by data class"""
        return [f for f in self.findings if f.data_class == data_class]
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical findings"""
        return self.get_findings_by_severity(Severity.CRITICAL)
    
    def get_live_confirmed_findings(self) -> List[Finding]:
        """Get findings that have been confirmed live"""
        return [f for f in self.findings if f.confirmed_live]
    
    def get_attack_chains(self) -> List[List[Finding]]:
        """Group findings into attack chains"""
        chains = {}
        
        for finding in self.findings:
            if finding.attack_chain:
                chain_key = tuple(finding.attack_chain)
                if chain_key not in chains:
                    chains[chain_key] = []
                chains[chain_key].append(finding)
        
        return list(chains.values())
    
    def generate_summary(self, target_url: str, target_project: Optional[str] = None, 
                        techniques_used: List[str] = None) -> ScanSummary:
        """Generate a summary of the scan"""
        
        if techniques_used is None:
            techniques_used = []
        
        # Count by severity
        severity_counts = {}
        for severity in Severity:
            count = len(self.get_findings_by_severity(severity))
            if count > 0:
                severity_counts[severity.value] = count
        
        # Count by technique
        technique_counts = {}
        for finding in self.findings:
            if finding.technique:
                technique_counts[finding.technique] = technique_counts.get(finding.technique, 0) + 1
        
        # Count by data class
        data_class_counts = {}
        for finding in self.findings:
            data_class_counts[finding.data_class.value] = data_class_counts.get(finding.data_class.value, 0) + 1
        
        # Count live keys
        live_confirmed = len(self.get_live_confirmed_findings())
        
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        risk_level = self._get_risk_level(risk_score)
        
        # Generate attack chains
        attack_chains = []
        for chain in self.get_attack_chains():
            attack_chains.append({
                'steps': [f.title for f in chain],
                'severity': max(f.severity.value for f in chain),
                'findings': [f.id for f in chain]
            })
        
        self.summary = ScanSummary(
            scan_id=self.scan_id,
            target_url=target_url,
            target_project=target_project,
            started_at=self.summary.started_at if self.summary else datetime.now(),
            completed_at=datetime.now(),
            techniques_used=techniques_used,
            total_findings=len(self.findings),
            findings_by_severity=severity_counts,
            findings_by_technique=technique_counts,
            findings_by_data_class=data_class_counts,
            live_keys_confirmed=live_confirmed,
            attack_chains=attack_chains,
            risk_score=risk_score,
            risk_level=risk_level
        )
        
        return self.summary
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score (0-100)"""
        if not self.findings:
            return 0.0
        
        score = 0.0
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.5
        }
        
        for finding in self.findings:
            score += weights.get(finding.severity, 0)
            if finding.confirmed_live:
                score += 5.0  # Bonus for live keys
        
        # Normalize to 0-100
        max_possible = len(self.findings) * 10.0 + 5.0 * len([f for f in self.findings if f.confirmed_live])
        if max_possible > 0:
            score = (score / max_possible) * 100
        
        return min(score, 100.0)
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level based on score"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "info"
    
    def to_dict(self, reveal_secrets: bool = False) -> Dict[str, Any]:
        """Convert entire store to dictionary"""
        return {
            'scan_id': self.scan_id,
            'findings': [f.to_dict(reveal_secrets) for f in self.findings],
            'summary': self.summary.to_dict() if self.summary else None
        }
    
    def to_json(self, reveal_secrets: bool = False, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(reveal_secrets), indent=indent, default=str)
    
    def save_to_file(self, filename: str, reveal_secrets: bool = False):
        """Save findings to a JSON file"""
        with open(filename, 'w') as f:
            f.write(self.to_json(reveal_secrets))
    
    def load_from_file(self, filename: str):
        """Load findings from a JSON file"""
        with open(filename, 'r') as f:
            data = json.load(f)
        
        self.scan_id = data.get('scan_id', self.scan_id)
        self.findings = []
        
        for finding_data in data.get('findings', []):
            finding = Finding(
                id=finding_data.get('id', ''),
                technique=finding_data.get('technique', ''),
                technique_name=finding_data.get('technique_name', ''),
                title=finding_data.get('title', ''),
                description=finding_data.get('description', ''),
                severity=Severity(finding_data.get('severity', 'medium')),
                data_class=DataClass(finding_data.get('data_class', 'Credential')),
                url=finding_data.get('url', ''),
                evidence=finding_data.get('evidence', ''),
                secret_value=finding_data.get('secret_value'),
                redacted_value=finding_data.get('redacted_value', ''),
                context=finding_data.get('context', ''),
                provider=finding_data.get('provider'),
                allowlist=finding_data.get('allowlist', False),
                confirmed_live=finding_data.get('confirmed_live', False),
                is_false_positive=finding_data.get('is_false_positive', False),
                metadata=finding_data.get('metadata', {}),
                attack_chain=finding_data.get('attack_chain', []),
                remediation=finding_data.get('remediation', ''),
                impact=finding_data.get('impact', '')
            )
            self.findings.append(finding)
        
        if 'summary' in data:
            summary_data = data['summary']
            self.summary = ScanSummary(
                scan_id=summary_data.get('scan_id', ''),
                target_url=summary_data.get('target_url', ''),
                target_project=summary_data.get('target_project'),
                started_at=datetime.fromisoformat(summary_data.get('started_at', datetime.now().isoformat())),
                completed_at=datetime.fromisoformat(summary_data.get('completed_at', datetime.now().isoformat())) if summary_data.get('completed_at') else None,
                duration_seconds=summary_data.get('duration_seconds', 0.0),
                techniques_used=summary_data.get('techniques_used', []),
                total_findings=summary_data.get('total_findings', 0),
                findings_by_severity=summary_data.get('findings_by_severity', {}),
                findings_by_technique=summary_data.get('findings_by_technique', {}),
                findings_by_data_class=summary_data.get('findings_by_data_class', {}),
                live_keys_confirmed=summary_data.get('live_keys_confirmed', 0),
                live_keys_revoked=summary_data.get('live_keys_revoked', 0),
                attack_chains=summary_data.get('attack_chains', []),
                risk_score=summary_data.get('risk_score', 0.0),
                risk_level=summary_data.get('risk_level', 'low')
            )
