from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from vuln_assessor.gui_launcher import LauncherConfig, ManagedWebServer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
USER_HOME = Path.home()
if os.name == "nt":
    local_appdata = Path(os.environ.get("LOCALAPPDATA", str(USER_HOME / "AppData" / "Local"))).resolve()
    DEFAULT_DATA_ROOT = local_appdata
    DEFAULT_STATE_ROOT = local_appdata
else:
    DEFAULT_DATA_ROOT = Path(os.environ.get("XDG_DATA_HOME", str(USER_HOME / ".local" / "share"))).resolve()
    DEFAULT_STATE_ROOT = Path(os.environ.get("XDG_STATE_HOME", str(USER_HOME / ".local" / "state"))).resolve()
APP_DATA_DIR = DEFAULT_DATA_ROOT / "intra_vuln_assessor"
APP_STATE_DIR = DEFAULT_STATE_ROOT / "intra_vuln_assessor"

RUNTIME_DIR = Path(os.environ.get("INTRA_VULN_RUNTIME_DIR", str(APP_STATE_DIR))).resolve()
PID_FILE = RUNTIME_DIR / "desktop_web.pid"
STOP_FILE = RUNTIME_DIR / "desktop_web.stop"
LOG_FILE = RUNTIME_DIR / "desktop_web.log"
SERVICE_SCRIPT = PROJECT_ROOT / "desktop_web_service.py"

HOST = os.environ.get("INTRA_VULN_WEB_HOST", "127.0.0.1")
PORT = int(os.environ.get("INTRA_VULN_WEB_PORT", "5000"))
MAX_CONCURRENT = int(os.environ.get("INTRA_VULN_MAX_CONCURRENT", "3"))
default_db_path = Path(os.environ.get("INTRA_VULN_DB_PATH", str(APP_DATA_DIR / "scans.db"))).resolve()
default_report_root = default_db_path.parent if "INTRA_VULN_DB_PATH" in os.environ else APP_DATA_DIR
DB_PATH = default_db_path
REPORT_DIR = Path(os.environ.get("INTRA_VULN_REPORT_DIR", str(default_report_root / "reports"))).resolve()
URL = f"http://{HOST}:{PORT}"

os.environ.setdefault("INTRA_VULN_DB_PATH", str(DB_PATH))
os.environ.setdefault("INTRA_VULN_REPORT_DIR", str(REPORT_DIR))


def start_main() -> int:
    _ensure_runtime_dir()
    if _is_web_alive():
        _log("检测到 Web 已在运行，直接打开浏览器。")
        return _open_or_notify_running()

    existing_pid = _read_pid()
    if existing_pid is not None and _process_exists(existing_pid):
        _log(f"检测到后台服务进程已存在，PID={existing_pid}，等待服务就绪。")
        if _wait_for_web_ready(timeout_seconds=15):
            return _open_or_notify_running()
        _notify("Web 启动失败", f"已有后台进程但服务未就绪。\n\n日志文件:\n{LOG_FILE}")
        return 1

    _clear_stale_runtime_files()
    _log("准备启动后台 Web 服务。")
    try:
        _spawn_service_process()
    except Exception as exc:
        _log(f"拉起后台服务失败: {exc}")
        _notify("Web 启动失败", f"{exc}\n\n日志文件:\n{LOG_FILE}")
        return 1

    if not _wait_for_web_ready(timeout_seconds=15):
        _log("Web 服务未在预期时间内就绪。")
        _notify("Web 启动失败", f"服务未在预期时间内就绪。\n\n日志文件:\n{LOG_FILE}")
        return 1

    _log(f"Web 服务启动成功，访问地址: {URL}")
    return _open_or_notify_running()


def stop_main() -> int:
    _ensure_runtime_dir()
    pid = _read_pid()
    if pid is None:
        _notify("无需停止", "没有检测到由双击启动器管理的 Web 进程。")
        return 0

    STOP_FILE.write_text("stop", encoding="utf-8")
    _log(f"已发出停止信号，目标 PID={pid}。")
    if _wait_for_shutdown(pid, timeout_seconds=10):
        _cleanup_runtime_files(remove_log=False)
        _notify("Web 已停止", "后台 Web 服务已经停止。")
        return 0

    _log("优雅停止超时，开始强制结束后台进程。")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        _cleanup_runtime_files(remove_log=False)
        _notify("Web 已停止", "后台 Web 服务已经停止。")
        return 0
    except Exception as exc:
        _log(f"强制停止失败: {exc}")
        _notify("停止失败", f"无法结束后台 Web 进程。\n\n日志文件:\n{LOG_FILE}")
        return 1

    if _wait_for_shutdown(pid, timeout_seconds=5):
        _cleanup_runtime_files(remove_log=False)
        _notify("Web 已停止", "后台 Web 服务已经停止。")
        return 0

    _notify("停止失败", f"后台 Web 进程仍未退出。\n\n日志文件:\n{LOG_FILE}")
    return 1


def service_main() -> int:
    _ensure_runtime_dir()
    if not _claim_service_pid():
        _log("检测到已有后台服务在运行，当前服务进程直接退出。")
        return 0

    if STOP_FILE.exists():
        STOP_FILE.unlink()

    stop_requested = False
    server = ManagedWebServer()

    def _request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True

    for signal_name in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, signal_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _request_stop)
        except Exception:
            continue

    _log("后台 Web 服务开始启动。")
    try:
        server.start(
            LauncherConfig(
                host=HOST,
                port=PORT,
                db_path=DB_PATH,
                max_concurrent=MAX_CONCURRENT,
                auto_open_browser=False,
            ),
            log_callback=_log,
        )
    except Exception as exc:
        _log(f"后台 Web 服务启动失败: {exc}")
        _release_service_pid()
        return 1

    try:
        while not stop_requested and not STOP_FILE.exists():
            time.sleep(1)
    finally:
        _log("后台 Web 服务开始停止。")
        try:
            server.stop(log_callback=_log)
        finally:
            _release_service_pid()
            if STOP_FILE.exists():
                STOP_FILE.unlink()
    return 0


def _ensure_runtime_dir() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)


def _spawn_service_process() -> None:
    command = [_python_executable(), str(SERVICE_SCRIPT)]
    stdout_handle = LOG_FILE.open("a", encoding="utf-8")
    kwargs: dict[str, object] = {
        "cwd": str(PROJECT_ROOT),
        "stdin": subprocess.DEVNULL,
        "stdout": stdout_handle,
        "stderr": stdout_handle,
        "close_fds": True,
        "start_new_session": True,
    }

    try:
        subprocess.Popen(command, **kwargs)
    finally:
        stdout_handle.close()


def _python_executable() -> str:
    if sys.executable:
        return sys.executable
    return "python3"


def _open_or_notify_running() -> int:
    if _open_browser(URL):
        return 0
    _notify("Web 已启动", f"浏览器未能自动打开，请手动访问:\n{URL}")
    return 0


def _open_browser(url: str) -> bool:
    if os.environ.get("INTRA_VULN_NO_BROWSER") == "1":
        return True
    try:
        return webbrowser.open(url)
    except Exception:
        return False


def _notify(title: str, message: str) -> None:
    try:
        subprocess.Popen(
            ["xmessage", "-center", f"{title}\n\n{message}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError:
        pass


def _log(message: str) -> None:
    _ensure_runtime_dir()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(f"[{timestamp}] {message}\n")


def _is_web_alive() -> bool:
    try:
        with urllib.request.urlopen(URL, timeout=1.5) as response:
            return 200 <= response.status < 500
    except urllib.error.URLError:
        return False
    except Exception:
        return False


def _wait_for_web_ready(timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _is_web_alive():
            return True
        time.sleep(0.3)
    return False


def _wait_for_shutdown(pid: int, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _process_exists(pid) and not _is_web_alive():
            return True
        if not PID_FILE.exists() and not _is_web_alive():
            return True
        time.sleep(0.3)
    return False


def _read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except Exception:
        return None


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror in {5}:
            return True
        return False
    except SystemError:
        return False
    return True


def _claim_service_pid() -> bool:
    while True:
        try:
            fd = os.open(PID_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            pid = _read_pid()
            if pid is not None and _process_exists(pid):
                return False
            try:
                PID_FILE.unlink()
            except FileNotFoundError:
                continue
            except Exception:
                return False
            continue

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(str(os.getpid()))
        return True


def _release_service_pid() -> None:
    try:
        if PID_FILE.exists() and PID_FILE.read_text(encoding="utf-8").strip() == str(os.getpid()):
            PID_FILE.unlink()
    except Exception:
        pass


def _cleanup_runtime_files(remove_log: bool) -> None:
    for path in (PID_FILE, STOP_FILE):
        try:
            if path.exists():
                path.unlink()
        except Exception:
            continue
    if remove_log:
        try:
            if LOG_FILE.exists():
                LOG_FILE.unlink()
        except Exception:
            pass


def _clear_stale_runtime_files() -> None:
    pid = _read_pid()
    if pid is None or not _process_exists(pid):
        try:
            if PID_FILE.exists():
                PID_FILE.unlink()
        except Exception:
            pass
    try:
        if STOP_FILE.exists():
            STOP_FILE.unlink()
    except Exception:
        pass
