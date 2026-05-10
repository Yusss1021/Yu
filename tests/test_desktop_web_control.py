# pyright: reportMissingImports=false, reportUnknownVariableType=false

import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
START_SCRIPT = PROJECT_ROOT / "desktop_start_web.py"
STOP_SCRIPT = PROJECT_ROOT / "desktop_stop_web.py"


class TestDesktopWebControl(unittest.TestCase):
    def test_start_and_stop_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            runtime_dir = Path(tmp_dir) / "runtime"
            db_path = Path(tmp_dir) / "scans.db"
            port = "5017"
            env = os.environ.copy()
            env["INTRA_VULN_RUNTIME_DIR"] = str(runtime_dir)
            env["INTRA_VULN_DB_PATH"] = str(db_path)
            env["INTRA_VULN_WEB_PORT"] = port
            env["INTRA_VULN_NO_BROWSER"] = "1"

            try:
                start = subprocess.run(
                    [sys.executable, str(START_SCRIPT)],
                    cwd=str(PROJECT_ROOT),
                    env=env,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(start.returncode, 0, msg=start.stderr or start.stdout)

                url = f"http://127.0.0.1:{port}"
                for _ in range(30):
                    try:
                        with urllib.request.urlopen(url, timeout=1) as response:
                            self.assertEqual(response.status, 200)
                            break
                    except Exception:
                        time.sleep(0.3)
                else:
                    self.fail("启动脚本执行后，Web 服务未能正常响应请求")

                pid_file = runtime_dir / "desktop_web.pid"
                self.assertTrue(pid_file.exists())

                stop = subprocess.run(
                    [sys.executable, str(STOP_SCRIPT)],
                    cwd=str(PROJECT_ROOT),
                    env=env,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(stop.returncode, 0, msg=stop.stderr or stop.stdout)

                for _ in range(30):
                    try:
                        urllib.request.urlopen(url, timeout=1)
                    except Exception:
                        break
                    time.sleep(0.3)
                else:
                    self.fail("停止脚本执行后，Web 服务仍然处于监听状态")

                self.assertFalse(pid_file.exists())
            finally:
                subprocess.run(
                    [sys.executable, str(STOP_SCRIPT)],
                    cwd=str(PROJECT_ROOT),
                    env=env,
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=20,
                )
