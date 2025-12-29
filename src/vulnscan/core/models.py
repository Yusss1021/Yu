"""
Data models for VulnScan.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class ScanStatus(Enum):
    """Scan job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class PortState(Enum):
    """Port state."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class RiskLevel(Enum):
    """Risk level classification."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Severity(Enum):
    """Vulnerability severity based on CVSS."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Host:
    """Represents a discovered host."""
    ip: str
    id: Optional[int] = None
    scan_id: Optional[int] = None
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    is_alive: bool = True

    def __hash__(self):
        return hash(self.ip)

    def __eq__(self, other):
        if isinstance(other, Host):
            return self.ip == other.ip
        return False


@dataclass
class Service:
    """Represents a service running on a host."""
    host_ip: str
    port: int
    proto: str = "tcp"
    id: Optional[int] = None
    host_id: Optional[int] = None
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: Optional[str] = None
    state: PortState = PortState.OPEN
    banner: Optional[str] = None

    @property
    def full_version(self) -> str:
        """Return formatted product and version string."""
        parts = []
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts) if parts else "unknown"


@dataclass
class Vulnerability:
    """Represents a known vulnerability."""
    cve_id: str
    id: Optional[int] = None
    description: Optional[str] = None
    cvss_base: float = 0.0
    cvss_vector: Optional[str] = None
    severity: Severity = Severity.LOW
    published_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    affected_cpe: Optional[str] = None
    solution: Optional[str] = None

    @classmethod
    def severity_from_cvss(cls, cvss: float) -> Severity:
        """Determine severity from CVSS score."""
        if cvss >= 9.0:
            return Severity.CRITICAL
        elif cvss >= 7.0:
            return Severity.HIGH
        elif cvss >= 4.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW


@dataclass
class ServiceVuln:
    """Association between a service and a vulnerability."""
    service_id: int
    vuln_id: int
    id: Optional[int] = None
    match_type: str = "cpe_exact"  # cpe_exact, cpe_partial, version_range
    confidence: float = 1.0


@dataclass
class Scan:
    """Represents a scan job."""
    target_range: str
    id: Optional[int] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: ScanStatus = ScanStatus.PENDING
    notes: Optional[str] = None

    @property
    def duration(self) -> Optional[float]:
        """Return scan duration in seconds."""
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None


@dataclass
class HostRiskResult:
    """Risk assessment result for a single host."""
    host_id: int
    scan_id: int
    id: Optional[int] = None
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.LOW
    summary: Optional[str] = None
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0


@dataclass
class VerificationResult:
    """Result from active vulnerability verification."""
    scan_id: int
    host_id: int
    service_id: Optional[int] = None
    id: Optional[int] = None
    verifier: str = ""
    name: str = ""
    severity: Severity = Severity.LOW
    cve_id: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    detected_at: Optional[datetime] = None

    @property
    def is_confirmed(self) -> bool:
        return self.severity in (Severity.CRITICAL, Severity.HIGH)


@dataclass
class ScanResult:
    """Aggregated result from a scan or scan stage."""
    hosts: List[Host] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    service_vulns: List[ServiceVuln] = field(default_factory=list)
    risk_results: List[HostRiskResult] = field(default_factory=list)
    verification_results: List[VerificationResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def merge(self, other: "ScanResult") -> None:
        """Merge another ScanResult into this one."""
        # Deduplicate hosts by IP
        existing_ips = {h.ip for h in self.hosts}
        for host in other.hosts:
            if host.ip not in existing_ips:
                self.hosts.append(host)
                existing_ips.add(host.ip)

        # Add services (allow duplicates for different ports)
        self.services.extend(other.services)

        # Deduplicate vulnerabilities by CVE ID
        existing_cves = {v.cve_id for v in self.vulnerabilities}
        for vuln in other.vulnerabilities:
            if vuln.cve_id not in existing_cves:
                self.vulnerabilities.append(vuln)
                existing_cves.add(vuln.cve_id)

        self.service_vulns.extend(other.service_vulns)
        self.risk_results.extend(other.risk_results)
        self.verification_results.extend(other.verification_results)
        self.errors.extend(other.errors)

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def service_count(self) -> int:
        return len(self.services)

    @property
    def vuln_count(self) -> int:
        return len(self.vulnerabilities)

    def summary(self) -> dict:
        """Return a summary of the scan results."""
        return {
            "hosts": self.host_count,
            "services": self.service_count,
            "vulnerabilities": self.vuln_count,
            "errors": len(self.errors),
        }
