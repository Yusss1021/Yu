# pyright: reportMissingImports=false, reportUnknownVariableType=false

import tempfile
import unittest
import gc
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch

from vuln_assessor.config import DEFAULT_PORTS
from vuln_assessor.desktop_gui import DesktopControlCenterGUI
from vuln_assessor.desktop_profiles import resolve_discovery_methods, resolve_nmap_arguments
from vuln_assessor.models import HostAsset
from vuln_assessor.storage import ScanRepository
from vuln_assessor.workbench import ScanWorkbench

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _destroy_gui(gui: DesktopControlCenterGUI) -> None:
    with suppress(Exception):
        gui.root.update_idletasks()
    with suppress(Exception):
        gui._handle_close()
    gc.collect()


class _StubAnalysisOrchestrator:
    def __init__(
        self,
        repository: ScanRepository,
        asset_criticality_map: dict[str, float] | None = None,
        default_asset_criticality: float = 5.0,
    ) -> None:
        _ = (asset_criticality_map, default_asset_criticality)
        self.repository = repository

    def run_scan(
        self,
        target_cidr: str,
        methods: list[str],
        ports: list[int],
        output_dir: Path,
        scan_name: str = "",
        nmap_profile: str = "standard",
        extra_nmap_args: list[str] | None = None,
        nmap_arguments: list[str] | None = None,
        require_nmap: bool = False,
        enable_active_checks: bool = True,
        enable_auth_checks: bool = False,
        asset_profile_label: str = "未使用",
    ) -> dict[str, object]:
        _ = (
            methods,
            nmap_profile,
            extra_nmap_args,
            nmap_arguments,
            require_nmap,
            enable_active_checks,
            enable_auth_checks,
            asset_profile_label,
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        report_dir = output_dir / (scan_name or "analysis_report")
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / "report.html"
        report_path.write_text("<html><body>analysis</body></html>", encoding="utf-8")
        scan_id = self.repository.save_scan(
            target=target_cidr,
            methods=["icmp", "arp", "syn"],
            ports=ports,
            started_at="2026-04-11 12:00:00",
            finished_at="2026-04-11 12:00:05",
            duration_seconds=5.0,
            assets=[HostAsset(ip="192.168.10.9", discovered_by=["icmp"], open_ports=ports)],
            services=[],
            risks=[],
            report_path=str(report_path),
            scan_type="analysis",
        )
        return {
            "scan_id": scan_id,
            "target": target_cidr,
            "total_hosts": 1,
            "total_services": 0,
            "total_risks": 0,
            "report_path": str(report_path),
            "scan_type": "analysis",
        }


class _StubRuleManager:
    def summary(self) -> dict[str, object]:
        return {"total": 0, "severity_count": {}}


class _StubDiscoveryGuiOrchestrator:
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


class _StubGuiWorkbench:
    def __init__(self) -> None:
        self.analyze_calls: list[dict[str, object]] = []

    def list_discovery_snapshots(self, limit: int = 30) -> list[dict[str, object]]:
        _ = limit
        return []

    def list_scans(self, limit: int = 50, scan_type: str | None = None) -> list[dict[str, object]]:
        _ = (limit, scan_type)
        return []

    def get_rule_manager(self) -> _StubRuleManager:
        return _StubRuleManager()

    def get_services(self, scan_id: int) -> list[dict[str, object]]:
        _ = scan_id
        return []

    def get_vulnerabilities(self, scan_id: int) -> list[dict[str, object]]:
        _ = scan_id
        return []

    def analyze_target(
        self,
        target: str,
        ports: list[int],
        nmap_profile: str = "standard",
        extra_nmap_args: list[str] | None = None,
        scan_name: str = "",
        output_dir: Path | None = None,
        asset_profile_path: Path | None = None,
        enable_active_checks: bool = True,
        enable_auth_checks: bool = False,
    ) -> dict[str, object]:
        self.analyze_calls.append(
            {
                "target": target,
                "ports": ports,
                "nmap_profile": nmap_profile,
                "extra_nmap_args": extra_nmap_args or [],
                "scan_name": scan_name,
                "output_dir": output_dir,
                "asset_profile_path": asset_profile_path,
                "enable_active_checks": enable_active_checks,
                "enable_auth_checks": enable_auth_checks,
            }
        )
        return {
            "scan_id": 7,
            "target": target,
            "total_hosts": 1,
            "total_services": 2,
            "total_risks": 1,
            "report_path": "reports/analysis/report.html",
            "scan_type": "analysis",
        }


class TestDesktopGuiWorkflows(unittest.TestCase):
    def test_progressive_discovery_preset_resolves_expected_methods(self) -> None:
        self.assertEqual(resolve_discovery_methods("progressive", "icmp"), ["icmp", "arp", "syn"])

    def test_standard_nmap_profile_resolves_expected_arguments(self) -> None:
        self.assertEqual(resolve_nmap_arguments("standard"), ["-sV", "-Pn", "--version-intensity", "5"])

    def test_workbench_analysis_target_runs_without_snapshot_dependency(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            workbench = ScanWorkbench(db_path=db_path, report_dir=report_dir)

            with patch("vuln_assessor.workbench.ScanOrchestrator", _StubAnalysisOrchestrator):
                result = workbench.analyze_target(
                    target="192.168.10.0/24",
                    ports=[22, 80],
                    nmap_profile="standard",
                    scan_name="analysis_round",
                )

            self.assertEqual(result["scan_type"], "analysis")
            self.assertTrue(Path(str(result["report_path"])).exists())

    def test_gui_exposes_five_tabs_with_independent_analysis_target(self) -> None:
        gui = DesktopControlCenterGUI(workbench=_StubGuiWorkbench())
        gui.root.withdraw()

        try:
            tab_texts = [gui.notebook.tab(tab_id, "text") for tab_id in gui.notebook.tabs()]
            self.assertEqual(
                tab_texts,
                ["资产发现", "漏洞匹配与服务识别", "规则库导入", "报告对比", "Web 报告中心"],
            )
            self.assertTrue(hasattr(gui, "analysis_target_var"))
            self.assertFalse(hasattr(gui, "analysis_snapshot_combo"))
        finally:
            _destroy_gui(gui)

    def test_gui_custom_discovery_preset_forces_advanced_controls(self) -> None:
        gui = DesktopControlCenterGUI(workbench=_StubGuiWorkbench())
        gui.root.withdraw()

        try:
            gui.discovery_preset_var.set("自定义扫描方式")
            gui._apply_discovery_preset()
            gui.root.update_idletasks()

            self.assertTrue(gui.discovery_advanced_var.get())
            self.assertIn("disabled", gui.discovery_advanced_toggle.state())
            self.assertEqual(gui.discovery_advanced_frame.winfo_manager(), "grid")

            gui.discovery_preset_var.set("递进式智能扫描（ICMP -> ARP -> SYN）")
            gui._apply_discovery_preset()
            gui.root.update_idletasks()

            self.assertFalse(gui.discovery_advanced_var.get())
            self.assertNotIn("disabled", gui.discovery_advanced_toggle.state())
        finally:
            _destroy_gui(gui)

    def test_gui_analysis_profile_hint_updates_with_selected_preset(self) -> None:
        gui = DesktopControlCenterGUI(workbench=_StubGuiWorkbench())
        gui.root.withdraw()

        try:
            self.assertIn("--version-intensity 5", gui.analysis_profile_hint_var.get())

            gui.analysis_nmap_profile_var.set("快速扫描")
            gui._update_analysis_profile_hint()
            self.assertIn("--version-light", gui.analysis_profile_hint_var.get())

            gui.analysis_nmap_profile_var.set("深度扫描")
            gui._update_analysis_profile_hint()
            self.assertIn("--version-all", gui.analysis_profile_hint_var.get())
        finally:
            _destroy_gui(gui)

    def test_gui_report_history_only_lists_analysis_scans(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            discovery_dir = Path(tmp_dir) / "discovery"
            repository = ScanRepository(db_path)
            repository.initialize()

            _ = repository.save_scan(
                target="10.10.10.0/24",
                methods=["icmp", "arp", "syn"],
                ports=[80],
                started_at="2026-04-11 10:00:00",
                finished_at="2026-04-11 10:00:03",
                duration_seconds=3.0,
                assets=[HostAsset(ip="10.10.10.8", discovered_by=["icmp"], open_ports=[80])],
                services=[],
                risks=[],
                report_path="reports/assets/report.html",
                scan_type="asset_discovery",
            )
            _ = repository.save_scan(
                target="192.168.10.0/24",
                methods=["icmp", "arp", "syn"],
                ports=[22, 80],
                started_at="2026-04-11 10:10:00",
                finished_at="2026-04-11 10:10:05",
                duration_seconds=5.0,
                assets=[HostAsset(ip="192.168.10.9", discovered_by=["icmp"], open_ports=[22, 80])],
                services=[],
                risks=[],
                report_path="reports/analysis/report.html",
                scan_type="analysis",
            )

            gui = DesktopControlCenterGUI(
                workbench=ScanWorkbench(
                    db_path=db_path,
                    report_dir=report_dir,
                    discovery_dir=discovery_dir,
                )
            )
            gui.root.withdraw()

            try:
                gui._refresh_scan_history(select_latest=True)
                rows = gui.reports_tree.get_children()

                self.assertEqual(len(rows), 1)
                values = gui.reports_tree.item(rows[0], "values")
                self.assertEqual(values[2], "192.168.10.0/24")
                self.assertEqual(tuple(gui.compare_new_combo.cget("values")), ("#2 | 2026-04-11 10:10:00 | 192.168.10.0/24",))
            finally:
                _destroy_gui(gui)

    def test_gui_analysis_action_calls_analyze_target(self) -> None:
        workbench = _StubGuiWorkbench()
        gui = DesktopControlCenterGUI(workbench=workbench)
        gui.root.withdraw()

        def run_now(_task_name: str, worker, on_success=None) -> None:
            result = worker()
            if on_success is not None:
                on_success(result)

        try:
            gui.analysis_target_var.set("192.168.56.0/24")
            gui.analysis_ports_var.set("22,80")
            gui.analysis_nmap_profile_var.set("standard")
            gui.analysis_name_var.set("analysis_round")

            with patch.object(gui, "_run_async_task", side_effect=run_now):
                with patch.object(gui, "_refresh_scan_history"):
                    with patch.object(gui, "_render_analysis_result"):
                        gui._start_analysis()

            self.assertEqual(len(workbench.analyze_calls), 1)
            self.assertEqual(workbench.analyze_calls[0]["target"], "192.168.56.0/24")
            self.assertEqual(workbench.analyze_calls[0]["ports"], [22, 80])
            self.assertEqual(workbench.analyze_calls[0]["nmap_profile"], "standard")
            self.assertTrue(workbench.analyze_calls[0]["enable_active_checks"])
            self.assertFalse(workbench.analyze_calls[0]["enable_auth_checks"])
        finally:
            _destroy_gui(gui)

    def test_gui_analysis_can_enable_auth_checks(self) -> None:
        workbench = _StubGuiWorkbench()
        gui = DesktopControlCenterGUI(workbench=workbench)
        gui.root.withdraw()

        def run_now(_task_name: str, worker, on_success=None) -> None:
            result = worker()
            if on_success is not None:
                on_success(result)

        try:
            gui.analysis_target_var.set("192.168.56.0/24")
            gui.analysis_ports_var.set("21,22,3306")
            gui.analysis_auth_checks_var.set(True)

            with patch.object(gui, "_run_async_task", side_effect=run_now):
                with patch.object(gui, "_refresh_scan_history"):
                    with patch.object(gui, "_render_analysis_result"):
                        gui._start_analysis()

            self.assertTrue(workbench.analyze_calls[0]["enable_active_checks"])
            self.assertTrue(workbench.analyze_calls[0]["enable_auth_checks"])
        finally:
            _destroy_gui(gui)

    def test_gui_can_clear_asset_profile_and_followup_scan_uses_default(self) -> None:
        workbench = _StubGuiWorkbench()
        gui = DesktopControlCenterGUI(workbench=workbench)
        gui.root.withdraw()

        def run_now(_task_name: str, worker, on_success=None) -> None:
            result = worker()
            if on_success is not None:
                on_success(result)

        try:
            gui.analysis_profile_var.set(str(PROJECT_ROOT / "asset_profiles" / "critical_access_path.json"))
            gui._clear_asset_profile(gui.analysis_profile_var, "漏洞匹配与服务识别")
            gui.analysis_target_var.set("192.168.56.0/24")

            with patch.object(gui, "_run_async_task", side_effect=run_now):
                with patch.object(gui, "_refresh_scan_history"):
                    with patch.object(gui, "_render_analysis_result"):
                        gui._start_analysis()

            self.assertEqual(gui.analysis_profile_var.get(), "")
            self.assertIsNone(workbench.analyze_calls[0]["asset_profile_path"])
        finally:
            _destroy_gui(gui)

    def test_gui_can_restore_default_discovery_ports(self) -> None:
        gui = DesktopControlCenterGUI(workbench=_StubGuiWorkbench())
        gui.root.withdraw()

        try:
            gui.discovery_ports_var.set("")
            gui._restore_discovery_default_ports()

            self.assertEqual(gui.discovery_ports_var.get(), ",".join(str(port) for port in DEFAULT_PORTS))
        finally:
            _destroy_gui(gui)

    def test_gui_can_replace_discovery_ports_with_range_expression(self) -> None:
        gui = DesktopControlCenterGUI(workbench=_StubGuiWorkbench())
        gui.root.withdraw()

        try:
            gui.discovery_port_range_start_var.set("1024")
            gui.discovery_port_range_end_var.set("1")
            gui._replace_discovery_port_range()

            self.assertEqual(gui.discovery_ports_var.get(), "1-1024")
        finally:
            _destroy_gui(gui)

    def test_gui_can_append_analysis_ports_with_range_expression(self) -> None:
        gui = DesktopControlCenterGUI(workbench=_StubGuiWorkbench())
        gui.root.withdraw()

        try:
            gui.analysis_ports_var.set("22,80")
            gui.analysis_port_range_start_var.set("3300")
            gui.analysis_port_range_end_var.set("3306")
            gui._append_analysis_port_range()

            self.assertEqual(gui.analysis_ports_var.get(), "22,80,3300-3306")
        finally:
            _destroy_gui(gui)

    def test_gui_can_set_full_port_range_for_analysis(self) -> None:
        gui = DesktopControlCenterGUI(workbench=_StubGuiWorkbench())
        gui.root.withdraw()

        try:
            gui._set_analysis_full_port_range()

            self.assertEqual(gui.analysis_ports_var.get(), "1-65535")
        finally:
            _destroy_gui(gui)

    def test_gui_restores_default_analysis_ports_when_blank(self) -> None:
        workbench = _StubGuiWorkbench()
        gui = DesktopControlCenterGUI(workbench=workbench)
        gui.root.withdraw()

        def run_now(_task_name: str, worker, on_success=None) -> None:
            result = worker()
            if on_success is not None:
                on_success(result)

        try:
            gui.analysis_target_var.set("192.168.56.0/24")
            gui.analysis_ports_var.set("")

            with patch.object(gui, "_run_async_task", side_effect=run_now):
                with patch.object(gui, "_refresh_scan_history"):
                    with patch.object(gui, "_render_analysis_result"):
                        gui._start_analysis()

            self.assertEqual(gui.analysis_ports_var.get(), ",".join(str(port) for port in DEFAULT_PORTS))
            self.assertEqual(workbench.analyze_calls[0]["ports"], DEFAULT_PORTS)
        finally:
            _destroy_gui(gui)

    def test_gui_can_delete_selected_asset_discovery_report(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            discovery_dir = Path(tmp_dir) / "discovery"
            workbench = ScanWorkbench(db_path=db_path, report_dir=report_dir, discovery_dir=discovery_dir)

            with patch("vuln_assessor.workbench.ScanOrchestrator", _StubDiscoveryGuiOrchestrator):
                snapshot = workbench.discover_assets(
                    target="192.168.10.0/24",
                    methods=["icmp"],
                    ports=[80],
                    snapshot_name="asset_delete_round",
                )

            gui = DesktopControlCenterGUI(workbench=workbench)
            gui.root.withdraw()

            def run_now(_task_name: str, worker, on_success=None) -> None:
                result = worker()
                if on_success is not None:
                    on_success(result)

            try:
                gui._refresh_discovery_snapshots(select_path=str(snapshot.file_path))
                gui.assets_tree.insert("", "end", values=("192.168.10.8", "-", "icmp", "80", 5.0))

                with patch("vuln_assessor.desktop_gui.messagebox.askyesno", return_value=True):
                    with patch.object(gui, "_run_async_task", side_effect=run_now):
                        gui._delete_selected_asset_report()

                repository = ScanRepository(db_path)
                repository.initialize()
                self.assertEqual(repository.list_scans(limit=10, scan_type="asset_discovery"), [])
                self.assertFalse(Path(snapshot.report_path).parent.exists())
                self.assertFalse(snapshot.file_path.exists())
                self.assertEqual(gui.snapshots_tree.get_children(), ())
                self.assertEqual(gui.assets_tree.get_children(), ())
            finally:
                _destroy_gui(gui)

    def test_gui_can_delete_selected_analysis_report(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
            db_path = Path(tmp_dir) / "scans.db"
            report_dir = Path(tmp_dir) / "reports"
            discovery_dir = Path(tmp_dir) / "discovery"
            report_bundle = report_dir / "gui_delete_demo"
            report_bundle.mkdir(parents=True, exist_ok=True)
            report_path = report_bundle / "report.html"
            report_path.write_text("<html><body>delete from gui</body></html>", encoding="utf-8")
            repository = ScanRepository(db_path)
            repository.initialize()
            scan_id = repository.save_scan(
                target="127.0.0.1/32",
                methods=["icmp"],
                ports=[22],
                started_at="2026-04-12 15:40:00",
                finished_at="2026-04-12 15:40:03",
                duration_seconds=3.0,
                assets=[HostAsset(ip="127.0.0.1", discovered_by=["icmp"], open_ports=[22])],
                services=[],
                risks=[],
                report_path=str(report_path),
                scan_type="analysis",
            )
            gui = DesktopControlCenterGUI(
                workbench=ScanWorkbench(
                    db_path=db_path,
                    report_dir=report_dir,
                    discovery_dir=discovery_dir,
                )
            )
            gui.root.withdraw()

            def run_now(_task_name: str, worker, on_success=None) -> None:
                result = worker()
                if on_success is not None:
                    on_success(result)

            try:
                gui._refresh_scan_history(select_latest=True)
                gui.reports_tree.selection_set(str(scan_id))
                gui.reports_tree.focus(str(scan_id))
                gui.services_tree.insert("", "end", values=("127.0.0.1", 22, "ssh", "-", "-", "-", 0))
                gui.vulnerabilities_tree.insert("", "end", values=("127.0.0.1", 22, "CVE-TEST", "LOW", 1.0, "LOW", "是"))

                with patch("vuln_assessor.desktop_gui.messagebox.askyesno", return_value=True):
                    with patch.object(gui, "_run_async_task", side_effect=run_now):
                        gui._delete_selected_report()

                self.assertIsNone(repository.get_scan(scan_id))
                self.assertFalse(report_bundle.exists())
                self.assertEqual(gui.reports_tree.get_children(), ())
                self.assertEqual(tuple(gui.compare_new_combo.cget("values")), ())
                self.assertEqual(gui.services_tree.get_children(), ())
                self.assertEqual(gui.vulnerabilities_tree.get_children(), ())
                self.assertIsNone(gui._latest_scan_id)
            finally:
                _destroy_gui(gui)

    def test_windows_requirements_split_optional_scapy(self) -> None:
        requirements = (PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8")
        advanced = (PROJECT_ROOT / "requirements-advanced.txt").read_text(encoding="utf-8")

        self.assertNotIn("scapy", requirements)
        self.assertIn("scapy", advanced)
        self.assertIn("paramiko", advanced)
        self.assertIn("pymysql", advanced)
