# pyright: reportMissingImports=false, reportUnknownVariableType=false

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vuln_assessor.models import HostAsset, RiskFinding, ServiceFingerprint, VulnerabilityFinding
from vuln_assessor.orchestrator import ScanOrchestrator
from vuln_assessor.storage import ScanRepository
from vuln_assessor.webapp import create_app
from vuln_assessor.workbench import ScanWorkbench


class _StubDiscoveryEngine:
    def __init__(self) -> None:
        self.called = False

    def discover(self, cidr: str, ports: list[int], methods: list[str]) -> list[HostAsset]:
        self.called = True
        return [
            HostAsset(
                ip="192.168.10.8",
                mac="00:11:22:33:44:55",
                discovered_by=list(methods),
                open_ports=[],
            )
        ]


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
                port=22,
                protocol="tcp",
                service_name="ssh",
                product="OpenSSH",
                version="7.4",
                fingerprint_method="nmap",
                fingerprint_confidence=8.0,
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
                description="demo vulnerability",
                remediation="upgrade",
                match_confidence=8.0,
                confidence_tier="HIGH",
                asset_criticality=6.0,
            )
        ]


class _StubRiskEvaluator:
    def evaluate(self, vulnerabilities: list[VulnerabilityFinding]) -> list[RiskFinding]:
        finding = vulnerabilities[0]
        return [
            RiskFinding(
                host_ip=finding.host_ip,
                port=finding.port,
                service_name=finding.service_name,
                product=finding.product,
                version=finding.version,
                cve_id=finding.cve_id,
                severity=finding.severity,
                cvss=finding.cvss,
                description=finding.description,
                remediation=finding.remediation,
                exploit_maturity=7.0,
                match_confidence=finding.match_confidence,
                confidence_tier=finding.confidence_tier,
                asset_criticality=finding.asset_criticality,
                risk_score=8.3,
                risk_level="HIGH",
            )
        ]


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
        report_dir = output_dir / f"{report_type}_{scan_name or 'demo_report'}"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.html"
        report_path.write_text("<html><body>demo</body></html>", encoding="utf-8")
        return str(report_path)


class _StubDiscoveryWorkbenchOrchestrator:
    def __init__(self, repository: ScanRepository) -> None:
        self.repository = repository

    def discover_assets(self, target_cidr: str, methods: list[str], ports: list[int]) -> list[HostAsset]:
        _ = (target_cidr, ports)
        return [
            HostAsset(
                ip="192.168.10.18",
                mac="00:AA:BB:CC:DD:EE",
                discovered_by=list(methods),
                open_ports=[80],
            )
        ]

    def generate_asset_report(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        assets: list[HostAsset],
        output_dir: Path,
        scan_name: str = "",
        asset_profile_label: str = "未使用",
    ) -> str:
        _ = (target, methods, ports, assets, asset_profile_label)
        report_dir = output_dir / (scan_name or "asset_report")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.html"
        report_path.write_text("<html><body>asset report</body></html>", encoding="utf-8")
        return str(report_path)


class TestWorkbenchFlow(unittest.TestCase):
    def test_orchestrator_supports_discovery_then_analysis(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            repository = ScanRepository(db_path)
            repository.initialize()

            orchestrator = ScanOrchestrator(repository)
            stub_discovery = _StubDiscoveryEngine()
            orchestrator.discovery_engine = stub_discovery
            orchestrator.service_engine = _StubServiceEngine()
            orchestrator.matcher = _StubMatcher()
            orchestrator.risk_evaluator = _StubRiskEvaluator()
            orchestrator.report_generator = _StubReportGenerator()

            assets = orchestrator.discover_assets("192.168.10.0/24", ["icmp"], [22])
            self.assertTrue(stub_discovery.called)
            self.assertEqual(len(assets), 1)
            self.assertEqual(assets[0].open_ports, [])

            stub_discovery.called = False
            result = orchestrator.analyze_assets(
                target_cidr="192.168.10.0/24",
                methods=["icmp"],
                ports=[22],
                assets=assets,
                output_dir=report_dir,
                scan_name="split_flow_demo",
            )

            self.assertFalse(stub_discovery.called)
            self.assertEqual(result["total_hosts"], 1)
            self.assertEqual(result["total_services"], 1)
            self.assertEqual(result["total_risks"], 1)

            stored_assets = repository.get_assets(int(result["scan_id"]))
            self.assertEqual(stored_assets[0]["ip"], "192.168.10.8")
            self.assertEqual(stored_assets[0]["open_ports"], "22")

            stored_services = repository.get_services(int(result["scan_id"]))
            self.assertEqual(stored_services[0]["service_name"], "ssh")

            stored_vulnerabilities = repository.get_vulnerabilities(int(result["scan_id"]))
            self.assertEqual(stored_vulnerabilities[0]["cve_id"], "CVE-2020-0001")

    def test_repository_filters_analysis_scans_by_type(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            repository = ScanRepository(db_path)
            repository.initialize()

            _ = repository.save_scan(
                target="192.168.10.0/24",
                methods=["icmp"],
                ports=[22],
                started_at="2026-04-11 10:00:00",
                finished_at="2026-04-11 10:00:03",
                duration_seconds=3.0,
                assets=[HostAsset(ip="192.168.10.8", discovered_by=["icmp"], open_ports=[22])],
                services=[],
                risks=[],
                report_path="reports/asset/report.html",
                scan_type="asset_discovery",
            )
            _ = repository.save_scan(
                target="192.168.10.0/24",
                methods=["icmp"],
                ports=[22],
                started_at="2026-04-11 10:10:00",
                finished_at="2026-04-11 10:10:05",
                duration_seconds=5.0,
                assets=[HostAsset(ip="192.168.10.9", discovered_by=["icmp"], open_ports=[22])],
                services=[],
                risks=[],
                report_path="reports/analysis/report.html",
                scan_type="analysis",
            )

            analysis_rows = repository.list_scans(limit=10, scan_type="analysis")

            self.assertEqual(len(analysis_rows), 1)
            self.assertEqual(analysis_rows[0]["scan_type"], "analysis")
            self.assertEqual(analysis_rows[0]["report_path"], "reports/analysis/report.html")

    def test_workbench_discovery_creates_asset_report_record(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            discovery_dir = Path(tmp_dir) / "discovery"
            workbench = ScanWorkbench(db_path=db_path, report_dir=report_dir, discovery_dir=discovery_dir)

            with patch("vuln_assessor.workbench.ScanOrchestrator", _StubDiscoveryWorkbenchOrchestrator):
                snapshot = workbench.discover_assets(
                    target="192.168.10.0/24",
                    methods=["icmp"],
                    ports=[80],
                    snapshot_name="asset_round",
                )

            self.assertEqual(snapshot.report_type, "asset_discovery")
            self.assertTrue(Path(snapshot.report_path).exists())
            self.assertIsInstance(snapshot.scan_id, int)

            repository = ScanRepository(db_path)
            repository.initialize()
            asset_rows = repository.list_scans(limit=10, scan_type="asset_discovery")
            self.assertEqual(len(asset_rows), 1)
            self.assertEqual(asset_rows[0]["scan_type"], "asset_discovery")

    def test_workbench_discovery_applies_asset_profile_to_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            discovery_dir = Path(tmp_dir) / "discovery"
            profile_path = Path(tmp_dir) / "profile.json"
            profile_path.write_text(
                '{"default_criticality": 4.0, "assets": {"192.168.10.18": 9.0}}',
                encoding="utf-8",
            )
            workbench = ScanWorkbench(db_path=db_path, report_dir=report_dir, discovery_dir=discovery_dir)

            with patch("vuln_assessor.workbench.ScanOrchestrator", _StubDiscoveryWorkbenchOrchestrator):
                snapshot = workbench.discover_assets(
                    target="192.168.10.0/24",
                    methods=["icmp"],
                    ports=[80],
                    snapshot_name="asset_profile_round",
                    asset_profile_path=profile_path,
                )

            self.assertEqual(snapshot.asset_profile_path, str(profile_path))
            self.assertEqual(snapshot.assets[0].asset_criticality, 9.0)
            loaded = workbench.load_discovery_snapshot(snapshot.file_path)
            self.assertEqual(loaded.asset_profile_path, str(profile_path))
            self.assertEqual(loaded.assets[0].asset_criticality, 9.0)

    def test_workbench_delete_scan_removes_report_bundle_and_records(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            discovery_dir = Path(tmp_dir) / "discovery"
            report_bundle = report_dir / "demo_delete"
            report_bundle.mkdir(parents=True, exist_ok=True)
            report_path = report_bundle / "report.html"
            report_path.write_text("<html><body>delete me</body></html>", encoding="utf-8")
            workbench = ScanWorkbench(db_path=db_path, report_dir=report_dir, discovery_dir=discovery_dir)
            repository = ScanRepository(db_path)
            repository.initialize()
            scan_id = repository.save_scan(
                target="127.0.0.1/32",
                methods=["icmp"],
                ports=[22],
                started_at="2026-04-12 15:20:00",
                finished_at="2026-04-12 15:20:03",
                duration_seconds=3.0,
                assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[22])],
                services=[],
                risks=[],
                report_path=str(report_path),
                scan_type="analysis",
            )

            result = workbench.delete_scan(scan_id)

            self.assertEqual(result["scan_id"], scan_id)
            self.assertFalse(report_bundle.exists())
            self.assertIsNone(repository.get_scan(scan_id))
            self.assertEqual(repository.list_scans(limit=10, scan_type="analysis"), [])

    def test_web_becomes_report_center_only(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            repository = ScanRepository(db_path)
            repository.initialize()
            _ = repository.save_scan(
                target="10.10.10.0/24",
                methods=["icmp", "arp", "syn"],
                ports=[80],
                started_at="2026-03-25 09:55:00",
                finished_at="2026-03-25 09:55:04",
                duration_seconds=4.0,
                assets=[HostAsset(ip="10.10.10.8", discovered_by=["icmp"], open_ports=[80])],
                services=[],
                risks=[],
                report_path="reports/assets/report.html",
                scan_type="asset_discovery",
            )
            _ = repository.save_scan(
                target="127.0.0.1/32",
                methods=["icmp"],
                ports=[22],
                started_at="2026-03-25 10:00:00",
                finished_at="2026-03-25 10:00:03",
                duration_seconds=3.0,
                assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[22])],
                services=[],
                risks=[],
                report_path="reports/demo/report.html",
                scan_type="analysis",
            )

            app = create_app(db_path=db_path)
            client = app.test_client()

            response = client.get("/")
            html = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200)
            self.assertIn("127.0.0.1/32", html)
            self.assertNotIn("10.10.10.0/24", html)
            self.assertIn("报告中心", html)
            self.assertNotIn("提交扫描任务", html)
            self.assertIn("--brand: #0f4c81", html)
            self.assertNotIn("/static/style.css", html)

            submit_response = client.post("/scan/submit", data={}, follow_redirects=True)
            submit_html = submit_response.get_data(as_text=True)
            self.assertEqual(submit_response.status_code, 200)
            self.assertIn("桌面端", submit_html)

            task_response = client.get("/task/demo-task")
            self.assertEqual(task_response.status_code, 410)

            compare_response = client.get("/compare")
            compare_html = compare_response.get_data(as_text=True)
            self.assertEqual(compare_response.status_code, 200)
            self.assertIn("127.0.0.1/32", compare_html)
            self.assertNotIn("10.10.10.0/24", compare_html)

    def test_web_can_delete_report_from_dashboard(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_root = Path(tmp_dir) / "reports"
            report_bundle = report_root / "web_delete_demo"
            report_bundle.mkdir(parents=True, exist_ok=True)
            report_path = report_bundle / "report.html"
            report_path.write_text("<html><body>delete</body></html>", encoding="utf-8")
            repository = ScanRepository(db_path)
            repository.initialize()
            scan_id = repository.save_scan(
                target="127.0.0.1/32",
                methods=["icmp"],
                ports=[22],
                started_at="2026-04-12 15:30:00",
                finished_at="2026-04-12 15:30:03",
                duration_seconds=3.0,
                assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[22])],
                services=[],
                risks=[],
                report_path=str(report_path),
                scan_type="analysis",
            )

            with patch("vuln_assessor.webapp.REPORT_ROOT", report_root.resolve()):
                app = create_app(db_path=db_path)
            client = app.test_client()

            response = client.post(f"/scan/{scan_id}/delete", follow_redirects=True)
            html = response.get_data(as_text=True)

            self.assertEqual(response.status_code, 200)
            self.assertIn("已删除", html)
            self.assertNotIn("127.0.0.1/32", html)
            self.assertFalse(report_bundle.exists())
            self.assertIsNone(repository.get_scan(scan_id))

    def test_web_serves_report_assets_for_embedded_charts(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_root = Path(tmp_dir) / "reports"
            report_bundle = report_root / "web_asset_demo"
            assets_dir = report_bundle / "assets"
            assets_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_bundle / "report.html"
            report_path.write_text(
                '<html><head><script src="assets/chart.umd.min.js"></script></head><body>demo</body></html>',
                encoding="utf-8",
            )
            (assets_dir / "chart.umd.min.js").write_text("window.Chart = {};", encoding="utf-8")
            repository = ScanRepository(db_path)
            repository.initialize()
            scan_id = repository.save_scan(
                target="127.0.0.1/32",
                methods=["icmp"],
                ports=[22],
                started_at="2026-04-12 16:10:00",
                finished_at="2026-04-12 16:10:03",
                duration_seconds=3.0,
                assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[22])],
                services=[],
                risks=[],
                report_path=str(report_path),
                scan_type="analysis",
            )

            with patch("vuln_assessor.webapp.REPORT_ROOT", report_root.resolve()):
                app = create_app(db_path=db_path)
            client = app.test_client()

            report_response = client.get(f"/report/{scan_id}")
            asset_response = client.get(f"/report/{scan_id}/assets/chart.umd.min.js")
            try:
                self.assertEqual(report_response.status_code, 200)
                self.assertIn(f"/report/{scan_id}/assets/chart.umd.min.js", report_response.get_data(as_text=True))
                self.assertEqual(asset_response.status_code, 200)
                self.assertIn("window.Chart", asset_response.get_data(as_text=True))
            finally:
                report_response.close()
                asset_response.close()
