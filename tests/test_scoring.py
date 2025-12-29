"""
Tests for risk scoring module.
"""

import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vulnscan.core.models import Host, Service, Vulnerability, PortState, Severity, RiskLevel
from vulnscan.core.scoring import RiskScorer, RiskConfig, calculate_scan_risk_summary
from vulnscan.nvd.matcher import MatchResult


class TestRiskScorer:
    def test_score_host_no_vulns(self):
        scorer = RiskScorer()
        host = Host(id=1, ip="192.168.1.1")
        services = []
        matches = []

        result = scorer.score_host(host, services, matches)

        assert result.risk_score == 0.0
        assert result.risk_level == RiskLevel.INFO
        assert result.vuln_count == 0

    def test_score_host_with_vulns(self):
        scorer = RiskScorer()
        host = Host(id=1, ip="192.168.1.1")

        service = Service(
            id=1,
            host_ip="192.168.1.1",
            port=80,
            proto="tcp",
            state=PortState.OPEN,
        )

        vuln = Vulnerability(
            id=1,
            cve_id="CVE-2021-12345",
            cvss_base=9.8,
            severity=Severity.CRITICAL,
        )

        match = MatchResult(
            vulnerability=vuln,
            service=service,
            match_type="cpe_exact",
            confidence=0.95,
        )

        result = scorer.score_host(host, [service], [match])

        assert result.risk_score > 0
        assert result.vuln_count == 1
        assert result.critical_count == 1

    def test_high_risk_port_factor(self):
        scorer = RiskScorer()
        host = Host(id=1, ip="192.168.1.1")

        # Service on high-risk port (RDP)
        service_rdp = Service(
            id=1,
            host_ip="192.168.1.1",
            port=3389,
            proto="tcp",
            state=PortState.OPEN,
        )

        # Service on regular port
        service_http = Service(
            id=2,
            host_ip="192.168.1.1",
            port=8080,
            proto="tcp",
            state=PortState.OPEN,
        )

        vuln = Vulnerability(
            id=1,
            cve_id="CVE-2021-12345",
            cvss_base=7.5,
            severity=Severity.HIGH,
        )

        match_rdp = MatchResult(
            vulnerability=vuln,
            service=service_rdp,
            match_type="cpe_exact",
            confidence=0.95,
        )

        match_http = MatchResult(
            vulnerability=vuln,
            service=service_http,
            match_type="cpe_exact",
            confidence=0.95,
        )

        result_rdp = scorer.score_host(host, [service_rdp], [match_rdp])
        result_http = scorer.score_host(host, [service_http], [match_http])

        # RDP port should have higher risk due to port factor
        assert result_rdp.risk_score > result_http.risk_score


class TestCalculateScanRiskSummary:
    def test_empty_results(self):
        summary = calculate_scan_risk_summary([])

        assert summary["total_hosts"] == 0
        assert summary["total_vulnerabilities"] == 0
        assert summary["average_score"] == 0.0

    def test_with_results(self):
        from vulnscan.core.models import HostRiskResult

        results = [
            HostRiskResult(
                host_id=1,
                scan_id=1,
                risk_score=75.0,
                risk_level=RiskLevel.CRITICAL,
                vuln_count=5,
            ),
            HostRiskResult(
                host_id=2,
                scan_id=1,
                risk_score=25.0,
                risk_level=RiskLevel.MEDIUM,
                vuln_count=2,
            ),
        ]

        summary = calculate_scan_risk_summary(results)

        assert summary["total_hosts"] == 2
        assert summary["total_vulnerabilities"] == 7
        assert summary["average_score"] == 50.0
        assert summary["max_score"] == 75.0
        assert summary["critical_hosts"] == 1
        assert summary["medium_hosts"] == 1
