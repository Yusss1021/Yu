# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vuln_assessor.models import HostAsset, RiskFinding, ServiceFingerprint, VulnerabilityFinding
from vuln_assessor.orchestrator import ScanOrchestrator
from vuln_assessor.storage import ScanRepository


class _StubServiceEngine:
    def fingerprint(
        self,
        assets: list[HostAsset],
        fallback_ports: list[int],
        nmap_arguments: list[str] | None = None,
        require_nmap: bool = False,
    ) -> list[ServiceFingerprint]:
        _ = (fallback_ports, nmap_arguments, require_nmap)
        return [
            ServiceFingerprint(
                host_ip=assets[0].ip,
                port=23,
                protocol="tcp",
                service_name="telnet",
                product="mock-telnet",
                version="1.0",
            )
        ]


class _StubMatcher:
    def match(self, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        return [
            VulnerabilityFinding(
                host_ip=services[0].host_ip,
                port=services[0].port,
                service_name=services[0].service_name,
                product=services[0].product,
                version=services[0].version,
                cve_id="CVE-2020-0001",
                severity="HIGH",
                cvss=8.8,
                description="demo matcher finding",
                remediation="upgrade",
            )
        ]


class _StubActiveCheckEngine:
    def run(
        self,
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        fallback_ports: list[int],
        enable_auth_checks: bool = False,
    ) -> list[VulnerabilityFinding]:
        _ = (assets, services, fallback_ports, enable_auth_checks)
        return [
            VulnerabilityFinding(
                host_ip="192.168.56.10",
                port=23,
                service_name="telnet",
                product="mock-telnet",
                version="1.0",
                cve_id="CFG-TELNET-OPEN-0001",
                severity="MEDIUM",
                cvss=6.5,
                description="telnet open",
                remediation="disable telnet",
                match_confidence=9.0,
                confidence_tier="HIGH",
            )
        ]


class _StubRiskEvaluator:
    def evaluate(self, vulnerabilities: list[VulnerabilityFinding]) -> list[RiskFinding]:
        results: list[RiskFinding] = []
        for item in vulnerabilities:
            results.append(
                RiskFinding(
                    host_ip=item.host_ip,
                    port=item.port,
                    service_name=item.service_name,
                    product=item.product,
                    version=item.version,
                    cve_id=item.cve_id,
                    severity=item.severity,
                    cvss=item.cvss,
                    description=item.description,
                    remediation=item.remediation,
                    match_confidence=item.match_confidence,
                    confidence_tier=item.confidence_tier,
                    manual_confirmation_needed=item.manual_confirmation_needed,
                    confidence_reason=item.confidence_reason,
                    asset_criticality=item.asset_criticality,
                    risk_score=7.2,
                    risk_level="MEDIUM",
                )
            )
        return results


class _StubReportGenerator:
    def generate(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        risks: list[RiskFinding],
        output_dir: Path,
        scan_name: str = "",
        asset_profile_label: str = "未使用",
        report_type: str = "analysis",
    ) -> str:
        _ = (target, methods, ports, assets, services, risks, asset_profile_label)
        report_dir = output_dir / f"{report_type}_{scan_name or 'active_check_demo'}"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.html"
        report_path.write_text("<html><body>demo</body></html>", encoding="utf-8")
        return str(report_path)


class TestOrchestratorActiveChecks(unittest.TestCase):
    def test_analyze_assets_merges_active_findings_into_repository(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            repository = ScanRepository(db_path)
            repository.initialize()

            orchestrator = ScanOrchestrator(repository)
            orchestrator.service_engine = _StubServiceEngine()
            orchestrator.matcher = _StubMatcher()
            orchestrator.active_check_engine = _StubActiveCheckEngine()
            orchestrator.risk_evaluator = _StubRiskEvaluator()
            orchestrator.report_generator = _StubReportGenerator()

            result = orchestrator.analyze_assets(
                target_cidr="192.168.56.0/24",
                methods=["icmp"],
                ports=[23],
                assets=[HostAsset(ip="192.168.56.10", discovered_by=["icmp"])],
                output_dir=Path(tmp_dir) / "reports",
                scan_name="active_merge_demo",
            )

            stored = repository.get_vulnerabilities(int(result["scan_id"]))
            stored_ids = {item["cve_id"] for item in stored}
            self.assertEqual(stored_ids, {"CVE-2020-0001", "CFG-TELNET-OPEN-0001"})
