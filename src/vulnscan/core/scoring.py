"""
Risk scoring module - Calculate risk scores for hosts and services.
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from .models import (
    Host,
    HostRiskResult,
    RiskLevel,
    Service,
    Severity,
    Vulnerability,
)
from ..nvd.matcher import MatchResult

logger = logging.getLogger(__name__)


# High-risk ports that increase exposure
HIGH_RISK_PORTS = {
    21: 1.2,    # FTP
    22: 1.3,    # SSH
    23: 1.5,    # Telnet
    25: 1.1,    # SMTP
    53: 1.2,    # DNS
    110: 1.1,   # POP3
    135: 1.4,   # MS RPC
    139: 1.4,   # NetBIOS
    143: 1.1,   # IMAP
    445: 1.5,   # SMB
    1433: 1.4,  # MSSQL
    1521: 1.3,  # Oracle
    3306: 1.3,  # MySQL
    3389: 1.5,  # RDP
    5432: 1.3,  # PostgreSQL
    5900: 1.4,  # VNC
    6379: 1.3,  # Redis
    27017: 1.3, # MongoDB
}

# Severity weights
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 4.0,
    Severity.HIGH: 3.0,
    Severity.MEDIUM: 1.5,
    Severity.LOW: 0.5,
}


@dataclass
class RiskConfig:
    """Configuration for risk scoring."""
    # Base CVSS weight
    cvss_weight: float = 1.0

    # Port exposure factor
    port_exposure_enabled: bool = True

    # Multiple vulnerability accumulation factor
    accumulation_factor: float = 0.8

    # Maximum risk score
    max_score: float = 100.0

    # Risk level thresholds (adjusted for realistic single-vuln scenarios)
    critical_threshold: float = 25.0  # 1 critical vuln (CVSS 9+) triggers critical
    high_threshold: float = 12.0      # 1 high vuln (CVSS 7+) triggers high
    medium_threshold: float = 5.0     # 1 medium vuln (CVSS 4+) triggers medium


class RiskScorer:
    """
    Calculate risk scores for hosts based on discovered vulnerabilities.

    Uses a simplified CVSS-based model that considers:
    - Base CVSS score of each vulnerability
    - Severity classification
    - Port exposure (high-risk services)
    - Vulnerability accumulation
    """

    def __init__(self, config: RiskConfig = None):
        """
        Initialize risk scorer.

        Args:
            config: Risk scoring configuration
        """
        self.config = config or RiskConfig()

    def score_host(
        self,
        host: Host,
        services: List[Service],
        matches: List[MatchResult],
    ) -> HostRiskResult:
        """
        Calculate risk score for a single host.

        Args:
            host: Host to score
            services: Services on the host
            matches: Vulnerability matches for host services

        Returns:
            HostRiskResult with calculated scores
        """
        if not host.id:
            raise ValueError("Host must have an ID")

        # Filter matches for this host
        host_matches = [
            m for m in matches
            if m.service.host_ip == host.ip
        ]

        # Calculate base score from vulnerabilities
        vuln_scores = []
        severity_counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }

        for match in host_matches:
            vuln = match.vulnerability
            base_score = self._calculate_vuln_score(vuln, match)

            # Apply port exposure factor
            if self.config.port_exposure_enabled:
                port_factor = HIGH_RISK_PORTS.get(match.service.port, 1.0)
                base_score *= port_factor

            vuln_scores.append(base_score)

            # Count severities
            if vuln.severity in severity_counts:
                severity_counts[vuln.severity] += 1

        # Aggregate scores with diminishing returns
        total_score = self._aggregate_scores(vuln_scores)

        # Determine risk level
        risk_level = self._determine_risk_level(total_score)

        # Generate summary
        summary = self._generate_summary(
            host, len(host_matches), severity_counts, total_score
        )

        return HostRiskResult(
            host_id=host.id,
            scan_id=host.scan_id or 0,
            risk_score=round(total_score, 2),
            risk_level=risk_level,
            summary=summary,
            vuln_count=len(host_matches),
            critical_count=severity_counts[Severity.CRITICAL],
            high_count=severity_counts[Severity.HIGH],
            medium_count=severity_counts[Severity.MEDIUM],
            low_count=severity_counts[Severity.LOW],
        )

    def score_hosts(
        self,
        hosts: List[Host],
        services: List[Service],
        matches: List[MatchResult],
    ) -> List[HostRiskResult]:
        """
        Calculate risk scores for multiple hosts.

        Args:
            hosts: List of hosts
            services: All discovered services
            matches: All vulnerability matches

        Returns:
            List of HostRiskResult objects
        """
        results = []

        for host in hosts:
            host_services = [s for s in services if s.host_ip == host.ip]
            result = self.score_host(host, host_services, matches)
            results.append(result)

        # Sort by risk score descending
        results.sort(key=lambda r: r.risk_score, reverse=True)

        return results

    def _calculate_vuln_score(
        self,
        vuln: Vulnerability,
        match: MatchResult,
    ) -> float:
        """
        Calculate score contribution from a single vulnerability.

        Args:
            vuln: Vulnerability
            match: Match result with confidence

        Returns:
            Score contribution
        """
        # Base CVSS score (0-10)
        cvss = vuln.cvss_base or 0.0

        # Apply CVSS weight
        score = cvss * self.config.cvss_weight

        # Apply severity weight
        severity_weight = SEVERITY_WEIGHTS.get(vuln.severity, 1.0)
        score *= severity_weight

        # Apply match confidence with reduced penalty for uncertainty
        # Use quadratic easing: confidence * (2 - confidence)
        # e.g., 0.5 confidence -> 0.75 factor, 0.8 -> 0.96 factor
        confidence_factor = match.confidence * (2.0 - match.confidence)
        score *= confidence_factor

        return score

    def _aggregate_scores(self, scores: List[float]) -> float:
        """
        Aggregate multiple vulnerability scores.

        Uses diminishing returns to avoid unrealistic totals.

        Args:
            scores: List of individual vulnerability scores

        Returns:
            Aggregated score
        """
        if not scores:
            return 0.0

        # Sort descending
        sorted_scores = sorted(scores, reverse=True)

        total = 0.0
        factor = 1.0

        for score in sorted_scores:
            total += score * factor
            factor *= self.config.accumulation_factor

        # Cap at max score
        return min(total, self.config.max_score)

    def _determine_risk_level(self, score: float) -> RiskLevel:
        """
        Determine risk level from score.

        Args:
            score: Calculated risk score

        Returns:
            RiskLevel enum value
        """
        if score >= self.config.critical_threshold:
            return RiskLevel.CRITICAL
        elif score >= self.config.high_threshold:
            return RiskLevel.HIGH
        elif score >= self.config.medium_threshold:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def _generate_summary(
        self,
        host: Host,
        vuln_count: int,
        severity_counts: Dict[Severity, int],
        score: float,
    ) -> str:
        """
        Generate human-readable risk summary.

        Args:
            host: Host being summarized
            vuln_count: Total vulnerability count
            severity_counts: Counts by severity
            score: Calculated score

        Returns:
            Summary string
        """
        if vuln_count == 0:
            return f"No known vulnerabilities detected on {host.ip}"

        parts = [f"Host {host.ip}:"]

        if severity_counts[Severity.CRITICAL] > 0:
            parts.append(f"{severity_counts[Severity.CRITICAL]} critical")
        if severity_counts[Severity.HIGH] > 0:
            parts.append(f"{severity_counts[Severity.HIGH]} high")
        if severity_counts[Severity.MEDIUM] > 0:
            parts.append(f"{severity_counts[Severity.MEDIUM]} medium")
        if severity_counts[Severity.LOW] > 0:
            parts.append(f"{severity_counts[Severity.LOW]} low")

        parts.append(f"vulnerabilities found (Score: {score:.1f})")

        return " ".join(parts)


def calculate_scan_risk_summary(results: List[HostRiskResult]) -> Dict:
    """
    Calculate overall scan risk summary.

    Args:
        results: List of host risk results

    Returns:
        Summary dictionary
    """
    if not results:
        return {
            "total_hosts": 0,
            "total_vulnerabilities": 0,
            "average_score": 0.0,
            "max_score": 0.0,
            "critical_hosts": 0,
            "high_hosts": 0,
            "medium_hosts": 0,
            "low_hosts": 0,
            "info_hosts": 0,
        }

    total_vulns = sum(r.vuln_count for r in results)
    avg_score = sum(r.risk_score for r in results) / len(results)
    max_score = max(r.risk_score for r in results)

    critical = sum(1 for r in results if r.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for r in results if r.risk_level == RiskLevel.HIGH)
    medium = sum(1 for r in results if r.risk_level == RiskLevel.MEDIUM)
    low = sum(1 for r in results if r.risk_level == RiskLevel.LOW)
    info = sum(1 for r in results if r.risk_level == RiskLevel.INFO)

    return {
        "total_hosts": len(results),
        "total_vulnerabilities": total_vulns,
        "average_score": round(avg_score, 2),
        "max_score": round(max_score, 2),
        "critical_hosts": critical,
        "high_hosts": high,
        "medium_hosts": medium,
        "low_hosts": low,
        "info_hosts": info,
    }
