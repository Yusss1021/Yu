"""
Tests for core models.
"""

import pytest
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vulnscan.core.models import (
    Host,
    Service,
    Scan,
    Vulnerability,
    HostRiskResult,
    ScanStatus,
    PortState,
    RiskLevel,
    Severity,
    ScanResult,
)


class TestHost:
    def test_create_host(self):
        host = Host(ip="192.168.1.1", hostname="test-host", is_alive=True)
        assert host.ip == "192.168.1.1"
        assert host.hostname == "test-host"
        assert host.is_alive is True

    def test_host_with_mac(self):
        host = Host(ip="192.168.1.1", mac="00:11:22:33:44:55")
        assert host.mac == "00:11:22:33:44:55"


class TestService:
    def test_create_service(self):
        service = Service(
            host_ip="192.168.1.1",
            port=22,
            proto="tcp",
            service_name="ssh",
            state=PortState.OPEN,
        )
        assert service.port == 22
        assert service.proto == "tcp"
        assert service.state == PortState.OPEN

    def test_service_with_version(self):
        service = Service(
            host_ip="192.168.1.1",
            port=80,
            proto="tcp",
            service_name="http",
            product="nginx",
            version="1.18.0",
            state=PortState.OPEN,
        )
        assert service.product == "nginx"
        assert service.version == "1.18.0"


class TestVulnerability:
    def test_create_vulnerability(self):
        vuln = Vulnerability(
            cve_id="CVE-2021-44228",
            cvss_base=10.0,
            severity=Severity.CRITICAL,
            description="Log4j RCE vulnerability",
        )
        assert vuln.cve_id == "CVE-2021-44228"
        assert vuln.cvss_base == 10.0
        assert vuln.severity == Severity.CRITICAL


class TestScan:
    def test_create_scan(self):
        scan = Scan(target_range="192.168.1.0/24", status=ScanStatus.PENDING)
        assert scan.target_range == "192.168.1.0/24"
        assert scan.status == ScanStatus.PENDING

    def test_scan_with_timestamps(self):
        now = datetime.now()
        scan = Scan(
            target_range="192.168.1.0/24",
            started_at=now,
            status=ScanStatus.RUNNING,
        )
        assert scan.started_at == now


class TestScanResult:
    def test_empty_scan_result(self):
        result = ScanResult()
        assert len(result.hosts) == 0
        assert len(result.services) == 0

    def test_merge_results(self):
        result1 = ScanResult(hosts=[Host(ip="192.168.1.1")])
        result2 = ScanResult(hosts=[Host(ip="192.168.1.2")])

        result1.merge(result2)

        assert len(result1.hosts) == 2


class TestHostRiskResult:
    def test_create_risk_result(self):
        result = HostRiskResult(
            host_id=1,
            scan_id=1,
            risk_score=75.5,
            risk_level=RiskLevel.CRITICAL,
            vuln_count=10,
            critical_count=2,
            high_count=3,
            medium_count=3,
            low_count=2,
        )
        assert result.risk_score == 75.5
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.vuln_count == 10
