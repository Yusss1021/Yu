from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAB_ROOT = Path(__file__).resolve().parent
LAB_RUN_DIR = LAB_ROOT / "run"
DEMO_TARGET_CIDR = "127.0.0.0/29"
DEFAULT_SCAN_PORTS = [2121, 2222, 6379, 8080]
DEFAULT_SCAN_METHODS = "icmp"


@dataclass(frozen=True)
class DemoService:
    name: str
    host: str
    port: int
    script_path: Path

    @property
    def pid_path(self) -> Path:
        return LAB_RUN_DIR / f"{self.name}.pid"

    @property
    def log_path(self) -> Path:
        return LAB_RUN_DIR / f"{self.name}.log"


def build_demo_services() -> list[DemoService]:
    return [
        DemoService("mock_ssh", "127.0.0.2", 2222, LAB_ROOT / "mock_ssh.py"),
        DemoService("mock_http_nginx", "127.0.0.1", 8080, LAB_ROOT / "mock_http_nginx.py"),
        DemoService("mock_ftp", "127.0.0.3", 2121, LAB_ROOT / "mock_ftp.py"),
        DemoService("mock_redis", "127.0.0.4", 6379, LAB_ROOT / "mock_redis.py"),
    ]


def build_scan_command(scan_name: str = "demo_lab_scan") -> list[str]:
    return [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        "scan",
        "--target",
        DEMO_TARGET_CIDR,
        "--methods",
        DEFAULT_SCAN_METHODS,
        "--ports",
        ",".join(str(port) for port in DEFAULT_SCAN_PORTS),
        "--name",
        scan_name,
        "--db",
        str(PROJECT_ROOT / "data" / "scans.db"),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the local Windows-friendly demo lab")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Start the lab if needed and run a demo scan")
    scan_parser.add_argument("--name", default="demo_lab_scan")
    subparsers.add_parser("start", help="Start all demo services")
    subparsers.add_parser("stop", help="Stop all demo services")
    subparsers.add_parser("status", help="Show current demo service status")
    args = parser.parse_args(argv)

    command = str(args.command)
    if command == "start":
        return start_lab()
    if command == "stop":
        return stop_lab()
    if command == "status":
        return status_lab()
    if command == "scan":
        return scan_lab(scan_name=str(args.name))
    return 1


def start_lab() -> int:
    LAB_RUN_DIR.mkdir(parents=True, exist_ok=True)
    started_any = False
    for service in build_demo_services():
        if _service_running(service):
            print(f"{service.name} already running at {service.host}:{service.port}")
            continue
        _remove_stale_pid(service)
        _start_service(service)
        started_any = True
    if started_any:
        print("demo lab is ready.")
    print(f"scan target: {DEMO_TARGET_CIDR}")
    print(f"scan ports: {','.join(str(port) for port in DEFAULT_SCAN_PORTS)}")
    return 0


def stop_lab() -> int:
    for service in build_demo_services():
        if not service.pid_path.exists():
            print(f"{service.name} not running")
            continue
        pid = _read_pid(service.pid_path)
        if pid is None:
            service.pid_path.unlink(missing_ok=True)
            print(f"{service.name} pid file invalid")
            continue
        if _process_exists(pid):
            _terminate_process(pid)
            print(f"stopped {service.name} (PID {pid})")
        else:
            print(f"{service.name} pid file exists but process is not alive")
        service.pid_path.unlink(missing_ok=True)
    return 0


def status_lab() -> int:
    for service in build_demo_services():
        pid = _read_pid(service.pid_path)
        running = pid is not None and _process_exists(pid)
        status = "running" if running else "stopped"
        print(f"{service.name} {service.host}:{service.port} {status}")
    return 0


def scan_lab(scan_name: str) -> int:
    start_result = start_lab()
    if start_result != 0:
        return start_result
    print("")
    print("running demo scan...")
    command = build_scan_command(scan_name=scan_name)
    result = subprocess.run(command, cwd=str(PROJECT_ROOT), check=False)
    return int(result.returncode)


def _start_service(service: DemoService) -> None:
    flags = 0
    kwargs: dict[str, object] = {"cwd": str(PROJECT_ROOT), "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    else:
        kwargs["start_new_session"] = True
    with service.log_path.open("a", encoding="utf-8") as handle:
        process = subprocess.Popen(
            [
                sys.executable,
                str(service.script_path),
                "--host",
                service.host,
                "--port",
                str(service.port),
            ],
            stdout=handle,
            stderr=handle,
            creationflags=flags,
            **kwargs,
        )
    service.pid_path.write_text(str(process.pid), encoding="utf-8")
    time.sleep(0.4)
    if not _process_exists(process.pid):
        raise RuntimeError(f"failed to start {service.name}, check {service.log_path}")


def _service_running(service: DemoService) -> bool:
    pid = _read_pid(service.pid_path)
    return pid is not None and _process_exists(pid)


def _remove_stale_pid(service: DemoService) -> None:
    pid = _read_pid(service.pid_path)
    if pid is None or not _process_exists(pid):
        service.pid_path.unlink(missing_ok=True)


def _read_pid(pid_path: Path) -> int | None:
    if not pid_path.exists():
        return None
    try:
        return int(pid_path.read_text(encoding="utf-8").strip())
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


def _terminate_process(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    try:
        os.kill(pid, 15)
    except Exception:
        return


if __name__ == "__main__":
    raise SystemExit(main())
