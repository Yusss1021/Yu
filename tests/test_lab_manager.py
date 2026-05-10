# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import socket
import time
import unittest
import warnings
from pathlib import Path

from lab.lab_manager import (
    DEMO_TARGET_CIDR,
    DEFAULT_SCAN_PORTS,
    DemoService,
    _read_pid,
    _start_service,
    _terminate_process,
    build_demo_services,
    build_scan_command,
)

warnings.filterwarnings("ignore", message=r"subprocess \d+ is still running", category=ResourceWarning)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestLabManager(unittest.TestCase):
    def test_windows_delivery_batch_files_exist(self) -> None:
        self.assertTrue((PROJECT_ROOT / "start_gui.bat").exists())
        self.assertTrue((PROJECT_ROOT / "lab" / "start_demo_lab.bat").exists())
        self.assertTrue((PROJECT_ROOT / "lab" / "stop_demo_lab.bat").exists())
        self.assertTrue((PROJECT_ROOT / "lab" / "run_demo_scan.bat").exists())

    def test_demo_services_use_multi_host_loopback_layout(self) -> None:
        services = build_demo_services()

        self.assertEqual([item.name for item in services], ["mock_ssh", "mock_http_nginx", "mock_ftp", "mock_redis"])
        self.assertEqual([item.host for item in services], ["127.0.0.2", "127.0.0.1", "127.0.0.3", "127.0.0.4"])
        self.assertEqual([item.port for item in services], [2222, 8080, 2121, 6379])

    def test_demo_http_service_uses_reachable_windows_loopback_host(self) -> None:
        template = build_demo_services()[1]
        service = DemoService("mock_http_nginx_probe", template.host, 18081, template.script_path)
        service.pid_path.unlink(missing_ok=True)
        service.log_path.unlink(missing_ok=True)

        try:
            _start_service(service)
            time.sleep(1.0)
            with socket.create_connection((service.host, service.port), timeout=2.0):
                self.assertEqual(service.host, "127.0.0.1")
        finally:
            pid = _read_pid(service.pid_path)
            if pid is not None:
                _terminate_process(pid)
            time.sleep(0.4)
            service.pid_path.unlink(missing_ok=True)
            for _ in range(5):
                try:
                    service.log_path.unlink(missing_ok=True)
                except PermissionError:
                    time.sleep(0.2)
                    continue
                break

    def test_scan_command_targets_fixed_loopback_lab(self) -> None:
        command = build_scan_command(scan_name="demo_round")

        self.assertIn("main.py", command[1])
        self.assertEqual(DEMO_TARGET_CIDR, "127.0.0.0/29")
        self.assertEqual(DEFAULT_SCAN_PORTS, [2121, 2222, 6379, 8080])
        self.assertIn("--target", command)
        self.assertIn(DEMO_TARGET_CIDR, command)
        self.assertIn("--ports", command)
        self.assertIn("2121,2222,6379,8080", command)
        self.assertIn("--name", command)
        self.assertIn("demo_round", command)
