# pyright: reportMissingImports=false, reportUnknownVariableType=false

import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from vuln_assessor.gui_launcher import LauncherConfig, ManagedWebServer, PROJECT_ROOT


class TestGuiLauncher(unittest.TestCase):
    def test_validate_resolves_relative_db_path(self) -> None:
        config = LauncherConfig(
            host="127.0.0.1",
            port=5000,
            db_path=Path("data/gui_test.db"),
            max_concurrent=2,
            auto_open_browser=False,
        )

        validated = config.validate()

        self.assertTrue(validated.db_path.is_absolute())
        self.assertTrue(str(validated.db_path).startswith(str(PROJECT_ROOT)))

    def test_managed_web_server_start_and_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "gui_test.db"
            logs: list[str] = []
            server = ManagedWebServer()
            url = server.start(
                LauncherConfig(
                    host="127.0.0.1",
                    port=0,
                    db_path=db_path,
                    max_concurrent=1,
                    auto_open_browser=False,
                ),
                log_callback=logs.append,
            )

            try:
                for _ in range(20):
                    try:
                        with urllib.request.urlopen(url, timeout=1) as response:
                            self.assertEqual(response.status, 200)
                            break
                    except Exception:
                        time.sleep(0.1)
                else:
                    self.fail("Web 服务启动后未能正常响应 HTTP 请求")

                self.assertTrue(server.is_running())
                self.assertTrue(any("Web 服务已启动" in item for item in logs))
            finally:
                server.stop(log_callback=logs.append)

            self.assertFalse(server.is_running())
            self.assertIsNone(server.current_url())
            self.assertTrue(any("Web 服务已停止" in item for item in logs))
