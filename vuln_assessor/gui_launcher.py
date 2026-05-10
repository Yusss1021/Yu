from __future__ import annotations

import contextlib
import threading
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from werkzeug.serving import BaseWSGIServer, make_server

from vuln_assessor.config import DEFAULT_DB_PATH
from vuln_assessor.webapp import create_app

try:
    from tkinter import BooleanVar, StringVar, TclError, Text, Tk, messagebox, ttk

    TKINTER_IMPORT_ERROR: Exception | None = None
except ModuleNotFoundError as exc:
    BooleanVar = StringVar = Text = Tk = Any  # type: ignore[assignment]
    messagebox = ttk = Any  # type: ignore[assignment]
    TKINTER_IMPORT_ERROR = exc

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(slots=True)
class LauncherConfig:
    host: str
    port: int
    db_path: Path
    max_concurrent: int
    auto_open_browser: bool = True

    def validate(self) -> "LauncherConfig":
        host = self.host.strip()
        if not host:
            raise ValueError("监听地址不能为空")
        if self.port < 0 or self.port > 65535:
            raise ValueError("端口范围必须在 0-65535 之间")
        if self.max_concurrent < 1:
            raise ValueError("并发任务数至少为 1")
        db_path = self.db_path.expanduser()
        if not db_path.is_absolute():
            db_path = (PROJECT_ROOT / db_path).resolve()
        return LauncherConfig(
            host=host,
            port=self.port,
            db_path=db_path,
            max_concurrent=self.max_concurrent,
            auto_open_browser=self.auto_open_browser,
        )


class ManagedWebServer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._server: BaseWSGIServer | None = None
        self._thread: threading.Thread | None = None
        self._config: LauncherConfig | None = None

    def is_running(self) -> bool:
        with self._lock:
            thread = self._thread
            return bool(thread and thread.is_alive())

    def current_url(self) -> str | None:
        with self._lock:
            server = self._server
            config = self._config
            if server is None or config is None:
                return None
            return f"http://{config.host}:{server.server_port}"

    def start(self, config: LauncherConfig, log_callback: Callable[[str], None] | None = None) -> str:
        resolved = config.validate()
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("Web 服务已经在运行中")

            resolved.db_path.parent.mkdir(parents=True, exist_ok=True)
            app = create_app(db_path=resolved.db_path, max_concurrent=resolved.max_concurrent)
            # Web 已退回报告中心，优先选择更稳定的单线程模式，减少 Windows 下的停止竞态。
            server = make_server(resolved.host, resolved.port, app, threaded=False)
            thread = threading.Thread(
                target=self._serve_forever,
                args=(server, log_callback),
                name="intra-vuln-web-server",
                daemon=True,
            )

            self._server = server
            self._thread = thread
            self._config = resolved
            thread.start()

        url = self.current_url()
        if url is None:
            raise RuntimeError("Web 服务启动失败")

        self._log(log_callback, f"Web 服务已启动：{url}")
        self._log(log_callback, f"数据库路径：{resolved.db_path}")
        self._log(log_callback, f"并发扫描任务数：{resolved.max_concurrent}")
        if resolved.auto_open_browser:
            webbrowser.open(url)
            self._log(log_callback, "已自动打开浏览器。")
        return url

    def stop(self, log_callback: Callable[[str], None] | None = None) -> None:
        with self._lock:
            server = self._server
            thread = self._thread

        if server is None:
            return

        self._log(log_callback, "正在停止 Web 服务...")
        server.shutdown()
        if thread is not None:
            thread.join(timeout=5)
        server.server_close()

        with self._lock:
            self._server = None
            self._thread = None
            self._config = None
        self._log(log_callback, "Web 服务已停止。")

    def _serve_forever(self, server: BaseWSGIServer, log_callback: Callable[[str], None] | None) -> None:
        try:
            server.serve_forever()
        except Exception as exc:
            self._log(log_callback, f"Web 服务异常退出：{exc}")
            with contextlib.suppress(Exception):
                server.server_close()
            with self._lock:
                if self._server is server:
                    self._server = None
                    self._thread = None
                    self._config = None

    @staticmethod
    def _log(log_callback: Callable[[str], None] | None, message: str) -> None:
        if log_callback is not None:
            log_callback(message)


class WebLauncherGUI:
    def __init__(self) -> None:
        self.server = ManagedWebServer()
        self.root = Tk()
        self.root.title("企业内网脆弱性扫描系统 Web 启动器")
        self.root.geometry("760x560")
        self.root.minsize(680, 500)

        self.host_var = StringVar(master=self.root, value="127.0.0.1")
        self.port_var = StringVar(master=self.root, value="5000")
        self.db_var = StringVar(master=self.root, value=str(DEFAULT_DB_PATH))
        self.concurrent_var = StringVar(master=self.root, value="3")
        self.auto_open_var = BooleanVar(master=self.root, value=True)
        self.status_var = StringVar(value="未启动")
        self.url_var = StringVar(master=self.root, value="http://127.0.0.1:5000")

        self.start_button: ttk.Button
        self.stop_button: ttk.Button
        self.open_button: ttk.Button
        self.log_text: Text

        self._build_layout()
        self._refresh_buttons()
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close)

    def run(self) -> None:
        self.root.mainloop()

    def _build_layout(self) -> None:
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill="both", expand=True)

        title = ttk.Label(frame, text="一键启动本地 Web 控制台", font=("TkDefaultFont", 16, "bold"))
        title.pack(anchor="w")

        desc = ttk.Label(
            frame,
            text="填写启动参数后点击“启动 Web”，系统会拉起 Flask 服务并自动打开浏览器。",
        )
        desc.pack(anchor="w", pady=(8, 16))

        form = ttk.LabelFrame(frame, text="启动参数", padding=12)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        self._add_form_row(form, 0, "监听地址", self.host_var)
        self._add_form_row(form, 1, "端口", self.port_var)
        self._add_form_row(form, 2, "数据库路径", self.db_var)
        self._add_form_row(form, 3, "并发任务数", self.concurrent_var)

        ttk.Checkbutton(form, text="启动后自动打开浏览器", variable=self.auto_open_var).grid(
            row=4,
            column=0,
            columnspan=2,
            sticky="w",
            pady=(8, 0),
        )

        status_frame = ttk.LabelFrame(frame, text="运行状态", padding=12)
        status_frame.pack(fill="x", pady=(16, 0))
        status_frame.columnconfigure(1, weight=1)

        ttk.Label(status_frame, text="当前状态").grid(row=0, column=0, sticky="w", padx=(0, 12))
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=1, sticky="w")

        ttk.Label(status_frame, text="访问地址").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=(8, 0))
        ttk.Label(status_frame, textvariable=self.url_var).grid(row=1, column=1, sticky="w", pady=(8, 0))

        button_row = ttk.Frame(frame)
        button_row.pack(fill="x", pady=(16, 0))

        self.start_button = ttk.Button(button_row, text="启动 Web", command=self._start_server)
        self.start_button.pack(side="left")

        self.stop_button = ttk.Button(button_row, text="停止 Web", command=self._stop_server)
        self.stop_button.pack(side="left", padx=(8, 0))

        self.open_button = ttk.Button(button_row, text="打开浏览器", command=self._open_browser)
        self.open_button.pack(side="left", padx=(8, 0))

        log_frame = ttk.LabelFrame(frame, text="运行日志", padding=12)
        log_frame.pack(fill="both", expand=True, pady=(16, 0))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = Text(log_frame, height=14, wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.configure(state="disabled")

        self._append_log("GUI 启动器已就绪，等待启动 Web 服务。")

    @staticmethod
    def _add_form_row(parent: ttk.LabelFrame, row: int, label: str, variable: StringVar) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=(0, 8))
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=(0, 8))

    def _start_server(self) -> None:
        try:
            config = LauncherConfig(
                host=self.host_var.get(),
                port=int(self.port_var.get().strip()),
                db_path=Path(self.db_var.get().strip()),
                max_concurrent=int(self.concurrent_var.get().strip()),
                auto_open_browser=bool(self.auto_open_var.get()),
            )
            url = self.server.start(config, log_callback=self._append_log)
        except ValueError as exc:
            messagebox.showerror("参数错误", f"启动失败：{exc}")
            self._append_log(f"启动失败：{exc}")
            return
        except OSError as exc:
            messagebox.showerror("端口占用", f"启动失败：{exc}")
            self._append_log(f"启动失败：{exc}")
            return
        except Exception as exc:
            messagebox.showerror("启动失败", f"启动失败：{exc}")
            self._append_log(f"启动失败：{exc}")
            return

        self.url_var.set(url)
        self.status_var.set("运行中")
        self._refresh_buttons()

    def _stop_server(self) -> None:
        try:
            self.server.stop(log_callback=self._append_log)
        except Exception as exc:
            messagebox.showerror("停止失败", f"停止失败：{exc}")
            self._append_log(f"停止失败：{exc}")
            return

        self.status_var.set("已停止")
        self._refresh_buttons()

    def _open_browser(self) -> None:
        url = self.server.current_url() or self.url_var.get().strip()
        if not url:
            messagebox.showwarning("无法打开", "当前没有可用的访问地址。")
            return
        webbrowser.open(url)
        self._append_log(f"已手动打开浏览器：{url}")

    def _handle_close(self) -> None:
        if self.server.is_running():
            try:
                self.server.stop(log_callback=self._append_log)
            except Exception:
                pass
        self._release_tk_variables()
        try:
            self.root.update_idletasks()
        except (RuntimeError, TclError):
            pass
        try:
            self.root.destroy()
        except (RuntimeError, TclError):
            pass

    def _refresh_buttons(self) -> None:
        running = self.server.is_running()
        self.start_button.configure(state="disabled" if running else "normal")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.open_button.configure(state="normal")

    def _append_log(self, message: str) -> None:
        try:
            self.root.after(0, self._append_log_sync, message)
        except (RuntimeError, TclError):
            return

    def _append_log_sync(self, message: str) -> None:
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"{message}\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
            self._refresh_buttons()
        except (RuntimeError, TclError):
            return

    def _release_tk_variables(self) -> None:
        for name in ("host_var", "port_var", "db_var", "concurrent_var", "auto_open_var", "status_var", "url_var"):
            if hasattr(self, name):
                setattr(self, name, None)


def run_gui_launcher() -> None:
    if TKINTER_IMPORT_ERROR is not None:
        raise RuntimeError(
            "当前 Python 环境未安装 tkinter，无法启动桌面 GUI。"
            " Windows 请重新安装带 Tcl/Tk 组件的 Python；"
            " Linux 请安装对应 Tk 组件后再执行。"
        ) from TKINTER_IMPORT_ERROR
    from vuln_assessor.desktop_gui import DesktopControlCenterGUI

    gui = DesktopControlCenterGUI()
    gui.run()
