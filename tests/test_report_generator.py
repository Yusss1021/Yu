# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vuln_assessor.models import HostAsset, RiskFinding, ServiceFingerprint
from vuln_assessor.report import HtmlReportGenerator


class TestReportGenerator(unittest.TestCase):
    def test_same_name_asset_and_analysis_reports_use_distinct_paths(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            output_dir = Path(tmp_dir)
            generator = HtmlReportGenerator()

            asset_path = Path(
                generator.generate(
                    target="127.0.0.0/29",
                    methods=["icmp"],
                    ports=[8080],
                    assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[8080])],
                    services=[],
                    risks=[],
                    output_dir=output_dir,
                    scan_name="same_name_case",
                    report_type="asset_discovery",
                )
            )
            analysis_path = Path(
                generator.generate(
                    target="127.0.0.0/29",
                    methods=["icmp"],
                    ports=[8080],
                    assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[8080])],
                    services=[
                        ServiceFingerprint(
                            host_ip="127.0.0.1",
                            port=8080,
                            protocol="tcp",
                            service_name="http",
                            product="nginx",
                            version="1.18.0",
                            fingerprint_method="nmap",
                            fingerprint_confidence=8.0,
                        )
                    ],
                    risks=[
                        RiskFinding(
                            host_ip="127.0.0.1",
                            port=8080,
                            service_name="http",
                            product="nginx",
                            version="1.18.0",
                            cve_id="LAB-DEMO-0001",
                            severity="MEDIUM",
                            cvss=6.5,
                            description="demo",
                            remediation="fix",
                            exploit_maturity=7.0,
                            match_confidence=8.0,
                            confidence_tier="HIGH",
                            manual_confirmation_needed=False,
                            confidence_reason="demo",
                            asset_criticality=5.0,
                            risk_score=6.8,
                            risk_level="MEDIUM",
                        )
                    ],
                    output_dir=output_dir,
                    scan_name="same_name_case",
                    report_type="analysis",
                )
            )

            self.assertNotEqual(asset_path, analysis_path)
            self.assertTrue(asset_path.exists())
            self.assertTrue(analysis_path.exists())

    def test_asset_discovery_report_omits_analysis_sections(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            output_dir = Path(tmp_dir)
            generator = HtmlReportGenerator()

            asset_path = Path(
                generator.generate(
                    target="127.0.0.0/29",
                    methods=["icmp"],
                    ports=[8080],
                    assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[8080])],
                    services=[],
                    risks=[],
                    output_dir=output_dir,
                    scan_name="asset_only_case",
                    report_type="asset_discovery",
                )
            )

            html = asset_path.read_text(encoding="utf-8")

            self.assertIn("discoveryChart", html)
            self.assertNotIn("riskPie", html)
            self.assertNotIn("confidenceChart", html)
            self.assertNotIn("Risk = 0.45*CVSS", html)
