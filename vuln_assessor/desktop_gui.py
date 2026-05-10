from __future__ import annotations

import importlib.util
import os
import shlex
import threading
import webbrowser
from pathlib import Path
from typing import Any, Callable

from tkinter import BooleanVar, StringVar, TclError, Text, Tk, filedialog, messagebox, ttk

from vuln_assessor.config import DEFAULT_DB_PATH, DEFAULT_DISCOVERY_DIR, DEFAULT_PORTS, DEFAULT_REPORT_DIR, RULE_FILE_PATH
from vuln_assessor.config import parse_ports
from vuln_assessor.desktop_profiles import DEFAULT_ANALYSIS_PRESET, DEFAULT_DISCOVERY_PRESET, DISCOVERY_PRESET_METHODS
from vuln_assessor.desktop_profiles import resolve_discovery_methods, resolve_nmap_arguments
from vuln_assessor.gui_launcher import LauncherConfig, ManagedWebServer
from vuln_assessor.port_expression import COMMON_PORT_RANGE_EXPRESSION, FULL_PORT_RANGE_EXPRESSION, PORT_INPUT_FORMAT_HINT
from vuln_assessor.port_expression import append_port_expression, build_port_range_expression
from vuln_assessor.scanners.service_fingerprint import NmapUnavailableError
from vuln_assessor.workbench import ScanWorkbench

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DISCOVERY_PRESET_LABELS = {
    "递进式智能扫描（ICMP -> ARP -> SYN）": DEFAULT_DISCOVERY_PRESET,
    "自定义扫描方式": "custom",
}
ANALYSIS_PROFILE_LABELS = {
    "快速扫描": "quick",
    "标准扫描（推荐）": DEFAULT_ANALYSIS_PRESET,
    "深度扫描": "deep",
}
ANALYSIS_PROFILE_DESCRIPTIONS = {
    "quick": "速度优先，适合快速摸底",
    "standard": "速度与识别率平衡，适合默认分析",
    "deep": "版本探测更完整，适合深度确认",
}


class DesktopControlCenterGUI:
    def __init__(
        self,
        workbench: ScanWorkbench | None = None,
        server: ManagedWebServer | None = None,
    ) -> None:
        self.workbench = workbench or ScanWorkbench(
            db_path=DEFAULT_DB_PATH,
            report_dir=DEFAULT_REPORT_DIR,
            discovery_dir=DEFAULT_DISCOVERY_DIR,
            rules_file=RULE_FILE_PATH,
        )
        self.server = server or ManagedWebServer()
        self.root = Tk()
        self.root.title("企业内网脆弱性扫描系统桌面控制台")
        self.root.geometry("1500x960")
        self.root.minsize(1220, 780)

        default_ports = ",".join(str(port) for port in DEFAULT_PORTS)
        self._default_ports_text = default_ports
        discovery_methods = ",".join(DISCOVERY_PRESET_METHODS[DEFAULT_DISCOVERY_PRESET])
        self.discovery_target_var = StringVar(master=self.root, value="127.0.0.1/32")
        self.discovery_preset_var = StringVar(
            master=self.root,
            value=self._label_for_preset(DEFAULT_DISCOVERY_PRESET, DISCOVERY_PRESET_LABELS),
        )
        self.discovery_methods_var = StringVar(master=self.root, value=discovery_methods)
        self.discovery_ports_var = StringVar(master=self.root, value=default_ports)
        self.discovery_port_range_start_var = StringVar(master=self.root, value="")
        self.discovery_port_range_end_var = StringVar(master=self.root, value="")
        self.discovery_profile_var = StringVar(master=self.root, value="")
        self.discovery_profile_hint_var = StringVar(master=self.root, value="")
        self.discovery_name_var = StringVar(master=self.root, value="")
        self.discovery_status_var = StringVar(value="等待执行资产发现")
        self.discovery_advanced_var = BooleanVar(master=self.root, value=False)

        self.analysis_target_var = StringVar(master=self.root, value="127.0.0.1/32")
        self.analysis_name_var = StringVar(master=self.root, value="")
        self.analysis_output_var = StringVar(master=self.root, value=str(DEFAULT_REPORT_DIR))
        self.analysis_profile_var = StringVar(master=self.root, value="")
        self.analysis_nmap_profile_var = StringVar(
            master=self.root,
            value=self._label_for_preset(DEFAULT_ANALYSIS_PRESET, ANALYSIS_PROFILE_LABELS),
        )
        self.analysis_ports_var = StringVar(master=self.root, value=default_ports)
        self.analysis_port_range_start_var = StringVar(master=self.root, value="")
        self.analysis_port_range_end_var = StringVar(master=self.root, value="")
        self.analysis_extra_args_var = StringVar(master=self.root, value="")
        self.analysis_profile_hint_var = StringVar(master=self.root, value="")
        self.analysis_asset_profile_hint_var = StringVar(master=self.root, value="")
        self.analysis_status_var = StringVar(value="等待执行服务识别与漏洞匹配")
        self.analysis_advanced_var = BooleanVar(master=self.root, value=False)
        self.analysis_active_checks_var = BooleanVar(master=self.root, value=True)
        self.analysis_auth_checks_var = BooleanVar(master=self.root, value=False)

        self.rules_file_var = StringVar(master=self.root, value="")
        self.rules_url_var = StringVar(master=self.root, value="")
        self.rules_mode_var = StringVar(master=self.root, value="merge")
        self.rules_status_var = StringVar(value="规则库状态待刷新")
        self.rules_advanced_var = BooleanVar(master=self.root, value=False)

        self.compare_base_var = StringVar(master=self.root, value="")
        self.compare_new_var = StringVar(master=self.root, value="")
        self.compare_status_var = StringVar(value="等待选择两份分析报告")

        self.web_host_var = StringVar(master=self.root, value="127.0.0.1")
        self.web_port_var = StringVar(master=self.root, value="5000")
        self.web_db_var = StringVar(master=self.root, value=str(DEFAULT_DB_PATH))
        self.web_status_var = StringVar(value="报告中心未启动")
        self.web_url_var = StringVar(master=self.root, value="http://127.0.0.1:5000")

        self._busy = False
        self._latest_scan_id: int | None = None
        self._current_snapshot_path = ""
        self._current_snapshot_scan_id: int | None = None
        self._scan_option_map: dict[str, int] = {}
        self._snapshot_scan_map: dict[str, int] = {}
        self._platform_note_logged = False

        self.notebook: ttk.Notebook
        self.assets_tree: ttk.Treeview
        self.snapshots_tree: ttk.Treeview
        self.services_tree: ttk.Treeview
        self.vulnerabilities_tree: ttk.Treeview
        self.reports_tree: ttk.Treeview
        self.compare_base_combo: ttk.Combobox
        self.compare_new_combo: ttk.Combobox
        self.compare_text: Text
        self.log_text: Text
        self.discovery_advanced_frame: ttk.Frame
        self.discovery_advanced_toggle: ttk.Checkbutton
        self.analysis_advanced_frame: ttk.Frame
        self.analysis_auth_checks_toggle: ttk.Checkbutton
        self.rules_advanced_frame: ttk.Frame

        self._build_layout()
        self._bind_variable_traces()
        self._refresh_rule_summary()
        self._refresh_discovery_snapshots(select_latest=True)
        self._refresh_scan_history(select_latest=True)
        self.root.protocol("WM_DELETE_WINDOW", self._handle_close)

    def run(self) -> None:
        self.root.mainloop()

    def _bind_variable_traces(self) -> None:
        self.discovery_profile_var.trace_add("write", self._update_discovery_profile_hint)
        self.analysis_profile_var.trace_add("write", self._update_analysis_asset_profile_hint)
        self.analysis_active_checks_var.trace_add("write", self._sync_analysis_check_toggles)
        self._update_discovery_profile_hint()
        self._update_analysis_asset_profile_hint()
        self._sync_analysis_check_toggles()

    def _build_layout(self) -> None:
        shell = ttk.Frame(self.root, padding=14)
        shell.pack(fill="both", expand=True)
        shell.rowconfigure(1, weight=1)
        shell.rowconfigure(2, weight=1)
        shell.columnconfigure(0, weight=1)

        title_frame = ttk.Frame(shell)
        title_frame.grid(row=0, column=0, sticky="ew")
        title_frame.columnconfigure(0, weight=1)
        ttk.Label(title_frame, text="Windows 主控桌面控制台", font=("TkDefaultFont", 18, "bold")).grid(
            row=0,
            column=0,
            sticky="w",
        )
        ttk.Label(
            title_frame,
            text="Web 端只承担报告查看与历史对比；资产发现、漏洞匹配、规则管理统一回到 GUI。",
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))

        self.notebook = ttk.Notebook(shell)
        self.notebook.grid(row=1, column=0, sticky="nsew", pady=(12, 12))
        for label, builder in (
            ("资产发现", self._build_discovery_tab),
            ("漏洞匹配与服务识别", self._build_analysis_tab),
            ("规则库导入", self._build_rules_tab),
            ("报告对比", self._build_compare_tab),
            ("Web 报告中心", self._build_web_tab),
        ):
            tab = ttk.Frame(self.notebook, padding=14)
            self.notebook.add(tab, text=label)
            builder(tab)

        log_frame = ttk.LabelFrame(shell, text="运行日志", padding=10)
        log_frame.grid(row=2, column=0, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log_text = Text(log_frame, height=10, wrap="word")
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.log_text.configure(state="disabled")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)
        ttk.Button(log_frame, text="清空日志", command=self._clear_log).grid(row=1, column=0, sticky="w", pady=(8, 0))
        self._append_log("桌面控制台已启动，当前 Web 仅作为报告中心。")

    def _build_discovery_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(3, weight=1)
        ttk.Label(
            parent,
            text="资产发现仅负责主机探测与资产报告生成，不会自动触发服务识别与漏洞匹配。",
        ).grid(row=0, column=0, sticky="w")

        form = ttk.LabelFrame(parent, text="发现参数", padding=10)
        form.grid(row=1, column=0, sticky="ew", pady=(10, 10))
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)
        ttk.Label(form, text="目标网段").grid(row=0, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.discovery_target_var).grid(row=0, column=1, sticky="ew", padx=(8, 18))
        ttk.Label(form, text="扫描方式").grid(row=0, column=2, sticky="w")
        preset_box = ttk.Combobox(
            form,
            textvariable=self.discovery_preset_var,
            values=tuple(DISCOVERY_PRESET_LABELS.keys()),
            state="readonly",
        )
        preset_box.grid(row=0, column=3, sticky="ew")
        preset_box.bind("<<ComboboxSelected>>", self._apply_discovery_preset)
        ttk.Label(form, text="报告名称").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(form, textvariable=self.discovery_name_var).grid(row=1, column=1, sticky="ew", padx=(8, 18), pady=(8, 0))
        self.discovery_advanced_toggle = ttk.Checkbutton(
            form,
            text="展开高级参数",
            variable=self.discovery_advanced_var,
            command=self._toggle_discovery_advanced,
        )
        self.discovery_advanced_toggle.grid(row=1, column=2, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Label(form, text="资产画像").grid(row=2, column=0, sticky="w", pady=(8, 0))
        discovery_profile_row = ttk.Frame(form)
        discovery_profile_row.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(8, 0))
        discovery_profile_row.columnconfigure(0, weight=1)
        ttk.Entry(discovery_profile_row, textvariable=self.discovery_profile_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(
            discovery_profile_row,
            text="选择文件",
            command=lambda: self._choose_asset_profile(self.discovery_profile_var),
        ).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(
            discovery_profile_row,
            text="清空",
            command=lambda: self._clear_asset_profile(self.discovery_profile_var, "资产发现"),
        ).grid(row=0, column=2, padx=(8, 0))
        ttk.Label(
            form,
            textvariable=self.discovery_profile_hint_var,
            wraplength=880,
            justify="left",
        ).grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))

        self.discovery_advanced_frame = ttk.Frame(form)
        self.discovery_advanced_frame.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        self.discovery_advanced_frame.columnconfigure(1, weight=1)
        self.discovery_advanced_frame.columnconfigure(3, weight=1)
        ttk.Label(self.discovery_advanced_frame, text="方法组合").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.discovery_advanced_frame, textvariable=self.discovery_methods_var).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=(8, 18),
        )
        ttk.Label(self.discovery_advanced_frame, text="端口候选").grid(row=0, column=2, sticky="w")
        discovery_ports_row = ttk.Frame(self.discovery_advanced_frame)
        discovery_ports_row.grid(row=0, column=3, sticky="ew")
        discovery_ports_row.columnconfigure(0, weight=1)
        ttk.Entry(discovery_ports_row, textvariable=self.discovery_ports_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(discovery_ports_row, text="恢复默认", command=self._restore_discovery_default_ports).grid(
            row=0,
            column=1,
            padx=(8, 0),
        )
        ttk.Label(self.discovery_advanced_frame, text="端口范围").grid(row=1, column=0, sticky="w", pady=(8, 0))
        discovery_range_row = ttk.Frame(self.discovery_advanced_frame)
        discovery_range_row.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Entry(discovery_range_row, textvariable=self.discovery_port_range_start_var, width=10).grid(row=0, column=0)
        ttk.Label(discovery_range_row, text="-").grid(row=0, column=1, padx=4)
        ttk.Entry(discovery_range_row, textvariable=self.discovery_port_range_end_var, width=10).grid(row=0, column=2)
        ttk.Button(discovery_range_row, text="覆盖候选", command=self._replace_discovery_port_range).grid(
            row=0,
            column=3,
            padx=(8, 0),
        )
        ttk.Button(discovery_range_row, text="追加到候选", command=self._append_discovery_port_range).grid(
            row=0,
            column=4,
            padx=(8, 0),
        )
        ttk.Button(discovery_range_row, text="常见范围 1-1024", command=self._set_discovery_common_port_range).grid(
            row=0,
            column=5,
            padx=(8, 0),
        )
        ttk.Button(discovery_range_row, text="全端口 1-65535", command=self._set_discovery_full_port_range).grid(
            row=0,
            column=6,
            padx=(8, 0),
        )
        ttk.Label(
            self.discovery_advanced_frame,
            text=f"{PORT_INPUT_FORMAT_HINT}；留空时会自动恢复为默认端口：{self._default_ports_text}",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))
        self._toggle_discovery_advanced()

        action_row = ttk.Frame(parent)
        action_row.grid(row=2, column=0, sticky="ew")
        ttk.Button(action_row, text="开始资产发现", command=self._start_asset_discovery).pack(side="left")
        ttk.Button(action_row, text="刷新发现记录", command=self._refresh_discovery_snapshots).pack(side="left", padx=(8, 0))
        ttk.Button(action_row, text="打开选中资产报告", command=self._open_selected_asset_report).pack(
            side="left",
            padx=(8, 0),
        )
        ttk.Button(action_row, text="删除选中资产报告", command=self._delete_selected_asset_report).pack(side="left", padx=(8, 0))
        ttk.Label(action_row, textvariable=self.discovery_status_var).pack(side="right")

        pane = ttk.Panedwindow(parent, orient="horizontal")
        pane.grid(row=3, column=0, sticky="nsew")
        snapshot_frame = ttk.LabelFrame(pane, text="资产发现历史", padding=10)
        asset_frame = ttk.LabelFrame(pane, text="当前资产结果", padding=10)
        for frame in (snapshot_frame, asset_frame):
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
        pane.add(snapshot_frame, weight=4)
        pane.add(asset_frame, weight=5)
        self.snapshots_tree = self._create_treeview(
            snapshot_frame,
            ("name", "time", "target", "assets", "methods", "report"),
            {"name": "名称", "time": "时间", "target": "目标", "assets": "主机数", "methods": "方法", "report": "报告"},
            {"name": 150, "time": 150, "target": 180, "assets": 70, "methods": 130, "report": 120},
        )
        self.snapshots_tree.grid(row=0, column=0, sticky="nsew")
        self.snapshots_tree.bind("<<TreeviewSelect>>", self._handle_snapshot_selection)
        self.assets_tree = self._create_treeview(
            asset_frame,
            ("ip", "mac", "methods", "ports", "criticality"),
            {"ip": "IP", "mac": "MAC", "methods": "发现方式", "ports": "开放端口", "criticality": "画像重要性"},
            {"ip": 170, "mac": 170, "methods": 140, "ports": 220, "criticality": 100},
        )
        self.assets_tree.grid(row=0, column=0, sticky="nsew")

    def _build_analysis_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(3, weight=1)
        ttk.Label(
            parent,
            text="该模块直接输入目标网段并独立运行 nmap 分析，不依赖资产发现快照。",
        ).grid(row=0, column=0, sticky="w")

        form = ttk.LabelFrame(parent, text="分析参数", padding=10)
        form.grid(row=1, column=0, sticky="ew", pady=(10, 10))
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)
        ttk.Label(form, text="目标网段").grid(row=0, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.analysis_target_var).grid(row=0, column=1, sticky="ew", padx=(8, 18))
        ttk.Label(form, text="扫描预设").grid(row=0, column=2, sticky="w")
        preset_frame = ttk.Frame(form)
        preset_frame.grid(row=0, column=3, sticky="ew")
        preset_frame.columnconfigure(0, weight=1)
        preset_box = ttk.Combobox(
            preset_frame,
            textvariable=self.analysis_nmap_profile_var,
            values=tuple(ANALYSIS_PROFILE_LABELS.keys()),
            state="readonly",
        )
        preset_box.grid(row=0, column=0, sticky="ew")
        preset_box.bind("<<ComboboxSelected>>", self._update_analysis_profile_hint)
        ttk.Label(
            preset_frame,
            textvariable=self.analysis_profile_hint_var,
            wraplength=360,
            justify="left",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Label(form, text="报告名称").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(form, textvariable=self.analysis_name_var).grid(row=1, column=1, sticky="ew", padx=(8, 18), pady=(8, 0))
        ttk.Label(form, text="报告目录").grid(row=1, column=2, sticky="w", pady=(8, 0))
        output_row = ttk.Frame(form)
        output_row.grid(row=1, column=3, sticky="ew", pady=(8, 0))
        output_row.columnconfigure(0, weight=1)
        ttk.Entry(output_row, textvariable=self.analysis_output_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(output_row, text="选择", command=self._choose_output_dir).grid(row=0, column=1, padx=(8, 0))
        ttk.Label(form, text="资产画像").grid(row=2, column=0, sticky="w", pady=(8, 0))
        profile_row = ttk.Frame(form)
        profile_row.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(8, 0))
        profile_row.columnconfigure(0, weight=1)
        ttk.Entry(profile_row, textvariable=self.analysis_profile_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(
            profile_row,
            text="选择文件",
            command=lambda: self._choose_asset_profile(self.analysis_profile_var),
        ).grid(row=0, column=1, padx=(8, 0))
        ttk.Button(
            profile_row,
            text="清空",
            command=lambda: self._clear_asset_profile(self.analysis_profile_var, "漏洞匹配与服务识别"),
        ).grid(row=0, column=2, padx=(8, 0))
        ttk.Label(
            form,
            textvariable=self.analysis_asset_profile_hint_var,
            wraplength=880,
            justify="left",
        ).grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))
        ttk.Checkbutton(
            form,
            text="展开高级参数",
            variable=self.analysis_advanced_var,
            command=self._toggle_analysis_advanced,
        ).grid(row=4, column=0, columnspan=4, sticky="w", pady=(10, 0))

        self.analysis_advanced_frame = ttk.Frame(form)
        self.analysis_advanced_frame.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        self.analysis_advanced_frame.columnconfigure(1, weight=1)
        self.analysis_advanced_frame.columnconfigure(3, weight=1)
        ttk.Label(self.analysis_advanced_frame, text="候选端口").grid(row=0, column=0, sticky="w")
        ports_row = ttk.Frame(self.analysis_advanced_frame)
        ports_row.grid(row=0, column=1, sticky="ew", padx=(8, 18))
        ports_row.columnconfigure(0, weight=1)
        ttk.Entry(ports_row, textvariable=self.analysis_ports_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(ports_row, text="恢复默认", command=self._restore_analysis_default_ports).grid(row=0, column=1, padx=(8, 0))
        ttk.Label(self.analysis_advanced_frame, text="额外 nmap 参数").grid(row=0, column=2, sticky="w")
        ttk.Entry(self.analysis_advanced_frame, textvariable=self.analysis_extra_args_var).grid(
            row=0,
            column=3,
            sticky="ew",
        )
        ttk.Label(self.analysis_advanced_frame, text="端口范围").grid(row=1, column=0, sticky="w", pady=(8, 0))
        analysis_range_row = ttk.Frame(self.analysis_advanced_frame)
        analysis_range_row.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(8, 0))
        ttk.Entry(analysis_range_row, textvariable=self.analysis_port_range_start_var, width=10).grid(row=0, column=0)
        ttk.Label(analysis_range_row, text="-").grid(row=0, column=1, padx=4)
        ttk.Entry(analysis_range_row, textvariable=self.analysis_port_range_end_var, width=10).grid(row=0, column=2)
        ttk.Button(analysis_range_row, text="覆盖候选", command=self._replace_analysis_port_range).grid(
            row=0,
            column=3,
            padx=(8, 0),
        )
        ttk.Button(analysis_range_row, text="追加到候选", command=self._append_analysis_port_range).grid(
            row=0,
            column=4,
            padx=(8, 0),
        )
        ttk.Button(analysis_range_row, text="常见范围 1-1024", command=self._set_analysis_common_port_range).grid(
            row=0,
            column=5,
            padx=(8, 0),
        )
        ttk.Button(analysis_range_row, text="全端口 1-65535", command=self._set_analysis_full_port_range).grid(
            row=0,
            column=6,
            padx=(8, 0),
        )
        ttk.Label(
            self.analysis_advanced_frame,
            text=f"{PORT_INPUT_FORMAT_HINT}；留空时会自动恢复为默认端口：{self._default_ports_text}",
        ).grid(row=2, column=0, columnspan=4, sticky="w", pady=(6, 0))
        ttk.Checkbutton(
            self.analysis_advanced_frame,
            text="启用主动探测（Telnet / SNMP / Redis / FTP 匿名）",
            variable=self.analysis_active_checks_var,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.analysis_auth_checks_toggle = ttk.Checkbutton(
            self.analysis_advanced_frame,
            text="启用少量空密码/弱口令尝试（SSH / MySQL / FTP）",
            variable=self.analysis_auth_checks_var,
        )
        self.analysis_auth_checks_toggle.grid(row=3, column=2, columnspan=2, sticky="w", pady=(8, 0))
        self._update_analysis_profile_hint()
        self._sync_analysis_check_toggles()
        self._toggle_analysis_advanced()

        action_row = ttk.Frame(parent)
        action_row.grid(row=2, column=0, sticky="ew")
        ttk.Button(action_row, text="开始服务识别与漏洞匹配", command=self._start_analysis).pack(side="left")
        ttk.Button(action_row, text="打开最新分析报告", command=self._open_latest_report).pack(side="left", padx=(8, 0))
        ttk.Button(action_row, text="刷新分析历史", command=self._refresh_scan_history).pack(side="left", padx=(8, 0))
        ttk.Label(action_row, textvariable=self.analysis_status_var).pack(side="right")

        pane = ttk.Panedwindow(parent, orient="horizontal")
        pane.grid(row=3, column=0, sticky="nsew")
        service_frame = ttk.LabelFrame(pane, text="服务识别结果", padding=10)
        risk_frame = ttk.LabelFrame(pane, text="漏洞匹配结果", padding=10)
        for frame in (service_frame, risk_frame):
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
        pane.add(service_frame, weight=3)
        pane.add(risk_frame, weight=3)
        self.services_tree = self._create_treeview(
            service_frame,
            ("host", "port", "service", "product", "version", "method", "confidence"),
            {
                "host": "主机",
                "port": "端口",
                "service": "服务",
                "product": "产品",
                "version": "版本",
                "method": "方法",
                "confidence": "置信度",
            },
            {"host": 150, "port": 70, "service": 110, "product": 140, "version": 100, "method": 90, "confidence": 80},
        )
        self.services_tree.grid(row=0, column=0, sticky="nsew")
        self.vulnerabilities_tree = self._create_treeview(
            risk_frame,
            ("host", "port", "cve", "level", "score", "asset", "confidence", "manual"),
            {
                "host": "主机",
                "port": "端口",
                "cve": "漏洞/规则ID",
                "level": "等级",
                "score": "风险分",
                "asset": "资产重要性",
                "confidence": "置信等级",
                "manual": "人工确认",
            },
            {"host": 150, "port": 70, "cve": 130, "level": 90, "score": 80, "asset": 90, "confidence": 90, "manual": 90},
        )
        self.vulnerabilities_tree.grid(row=0, column=0, sticky="nsew")

    def _build_rules_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        ttk.Label(parent, textvariable=self.rules_status_var).grid(row=0, column=0, sticky="w")
        import_frame = ttk.LabelFrame(parent, text="本地规则文件导入", padding=10)
        import_frame.grid(row=1, column=0, sticky="ew", pady=(10, 10))
        import_frame.columnconfigure(1, weight=1)
        ttk.Label(import_frame, text="规则文件").grid(row=0, column=0, sticky="w")
        ttk.Entry(import_frame, textvariable=self.rules_file_var).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(import_frame, text="浏览", command=self._choose_rule_file).grid(row=0, column=2)
        ttk.Label(import_frame, text="导入模式").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Combobox(
            import_frame,
            textvariable=self.rules_mode_var,
            values=("merge", "replace"),
            state="readonly",
            width=12,
        ).grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(8, 0))
        ttk.Button(import_frame, text="执行导入", command=self._import_rules).grid(row=1, column=2, pady=(8, 0))
        ttk.Checkbutton(
            parent,
            text="显示高级功能（远程 URL 更新）",
            variable=self.rules_advanced_var,
            command=self._toggle_rules_advanced,
        ).grid(row=2, column=0, sticky="w")
        self.rules_advanced_frame = ttk.LabelFrame(parent, text="高级功能", padding=10)
        self.rules_advanced_frame.grid(row=3, column=0, sticky="ew", pady=(10, 0))
        self.rules_advanced_frame.columnconfigure(1, weight=1)
        ttk.Label(self.rules_advanced_frame, text="更新 URL").grid(row=0, column=0, sticky="w")
        ttk.Entry(self.rules_advanced_frame, textvariable=self.rules_url_var).grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(self.rules_advanced_frame, text="执行更新", command=self._update_rules_from_url).grid(row=0, column=2)
        self._toggle_rules_advanced()
        ttk.Label(
            parent,
            text="远程更新只建议用于可信规则源；该入口不会暴露到 Web 报告中心。",
        ).grid(row=4, column=0, sticky="w", pady=(10, 0))

    def _build_compare_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(3, weight=1)
        ttk.Label(parent, text="报告对比默认只针对漏洞匹配与服务识别生成的分析报告。").grid(row=0, column=0, sticky="w")
        form = ttk.LabelFrame(parent, text="选择分析报告", padding=10)
        form.grid(row=1, column=0, sticky="ew", pady=(10, 10))
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)
        ttk.Label(form, text="基线报告").grid(row=0, column=0, sticky="w")
        self.compare_base_combo = ttk.Combobox(form, textvariable=self.compare_base_var, state="readonly")
        self.compare_base_combo.grid(row=0, column=1, sticky="ew", padx=(8, 18))
        ttk.Label(form, text="新报告").grid(row=0, column=2, sticky="w")
        self.compare_new_combo = ttk.Combobox(form, textvariable=self.compare_new_var, state="readonly")
        self.compare_new_combo.grid(row=0, column=3, sticky="ew")
        action_row = ttk.Frame(parent)
        action_row.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(action_row, text="执行历史报告对比", command=self._run_compare).pack(side="left")
        ttk.Button(action_row, text="打开 Web 对比页", command=self._open_compare_page).pack(side="left", padx=(8, 0))
        ttk.Button(action_row, text="刷新报告列表", command=self._refresh_scan_history).pack(side="left", padx=(8, 0))
        ttk.Label(action_row, textvariable=self.compare_status_var).pack(side="right")
        compare_frame = ttk.LabelFrame(parent, text="对比摘要", padding=10)
        compare_frame.grid(row=3, column=0, sticky="nsew")
        compare_frame.rowconfigure(0, weight=1)
        compare_frame.columnconfigure(0, weight=1)
        self.compare_text = Text(compare_frame, wrap="word")
        self.compare_text.grid(row=0, column=0, sticky="nsew")
        self.compare_text.configure(state="disabled")
        scroll = ttk.Scrollbar(compare_frame, orient="vertical", command=self.compare_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.compare_text.configure(yscrollcommand=scroll.set)

    def _build_web_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(2, weight=1)
        control_frame = ttk.LabelFrame(parent, text="报告中心控制", padding=10)
        control_frame.grid(row=0, column=0, sticky="ew")
        control_frame.columnconfigure(1, weight=1)
        control_frame.columnconfigure(3, weight=1)
        control_frame.columnconfigure(5, weight=1)
        ttk.Label(control_frame, text="监听地址").grid(row=0, column=0, sticky="w")
        ttk.Entry(control_frame, textvariable=self.web_host_var, width=14).grid(row=0, column=1, sticky="ew", padx=(8, 14))
        ttk.Label(control_frame, text="端口").grid(row=0, column=2, sticky="w")
        ttk.Entry(control_frame, textvariable=self.web_port_var, width=10).grid(row=0, column=3, sticky="ew", padx=(8, 14))
        ttk.Label(control_frame, text="数据库").grid(row=0, column=4, sticky="w")
        ttk.Entry(control_frame, textvariable=self.web_db_var).grid(row=0, column=5, sticky="ew", padx=(8, 14))
        ttk.Button(control_frame, text="启动报告中心", command=self._start_report_center).grid(row=0, column=6, padx=(0, 8))
        ttk.Button(control_frame, text="打开报告中心", command=self._open_report_center).grid(row=0, column=7, padx=(0, 8))
        ttk.Button(control_frame, text="停止报告中心", command=self._stop_report_center).grid(row=0, column=8)
        ttk.Label(control_frame, textvariable=self.web_status_var).grid(row=1, column=0, columnspan=4, sticky="w", pady=(10, 0))
        ttk.Label(control_frame, textvariable=self.web_url_var).grid(row=1, column=4, columnspan=5, sticky="e", pady=(10, 0))

        ttk.Label(
            parent,
            text="此页默认展示分析报告历史；资产发现报告请在“资产发现”页内查看和打开。",
        ).grid(row=1, column=0, sticky="w", pady=(10, 10))

        report_frame = ttk.LabelFrame(parent, text="分析报告历史", padding=10)
        report_frame.grid(row=2, column=0, sticky="nsew")
        report_frame.rowconfigure(1, weight=1)
        report_frame.columnconfigure(0, weight=1)
        action_row = ttk.Frame(report_frame)
        action_row.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Button(action_row, text="刷新历史报告", command=self._refresh_scan_history).pack(side="left")
        ttk.Button(action_row, text="打开选中报告", command=self._open_selected_report).pack(side="left", padx=(8, 0))
        ttk.Button(action_row, text="打开扫描详情", command=self._open_selected_scan_detail).pack(side="left", padx=(8, 0))
        ttk.Button(action_row, text="删除选中报告", command=self._delete_selected_report).pack(side="left", padx=(8, 0))
        report_body = ttk.Frame(report_frame)
        report_body.grid(row=1, column=0, sticky="nsew")
        report_body.rowconfigure(0, weight=1)
        report_body.columnconfigure(0, weight=1)
        self.reports_tree = self._create_treeview(
            report_body,
            ("id", "time", "target", "services", "risks", "report"),
            {"id": "ID", "time": "时间", "target": "目标", "services": "服务数", "risks": "风险数", "report": "报告目录"},
            {"id": 60, "time": 150, "target": 180, "services": 80, "risks": 80, "report": 140},
        )
        self.reports_tree.grid(row=0, column=0, sticky="nsew")
        self.reports_tree.bind("<<TreeviewSelect>>", self._handle_report_selection)

    def _create_treeview(
        self,
        parent: ttk.Frame,
        columns: tuple[str, ...],
        headings: dict[str, str],
        widths: dict[str, int],
    ) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        for column in columns:
            tree.heading(column, text=headings[column])
            tree.column(column, width=widths.get(column, 120), anchor="w")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        tree.configure(yscrollcommand=scroll.set)
        return tree

    def _label_for_preset(self, code: str, mapping: dict[str, str]) -> str:
        for label, value in mapping.items():
            if value == code:
                return label
        return next(iter(mapping))

    def _selected_discovery_preset(self) -> str:
        return DISCOVERY_PRESET_LABELS.get(self.discovery_preset_var.get().strip(), DEFAULT_DISCOVERY_PRESET)

    def _selected_analysis_profile(self) -> str:
        return ANALYSIS_PROFILE_LABELS.get(self.analysis_nmap_profile_var.get().strip(), DEFAULT_ANALYSIS_PRESET)

    def _apply_discovery_preset(self, _event: object | None = None) -> None:
        if self._selected_discovery_preset() == DEFAULT_DISCOVERY_PRESET:
            self.discovery_methods_var.set(",".join(DISCOVERY_PRESET_METHODS[DEFAULT_DISCOVERY_PRESET]))
            if self.discovery_advanced_var.get():
                self.discovery_advanced_var.set(False)
        else:
            self.discovery_advanced_var.set(True)
        self._toggle_discovery_advanced()

    def _toggle_discovery_advanced(self) -> None:
        self._sync_discovery_advanced_toggle()
        if self._selected_discovery_preset() == "custom" or self.discovery_advanced_var.get():
            self.discovery_advanced_frame.grid()
            return
        self.discovery_advanced_frame.grid_remove()

    def _toggle_analysis_advanced(self) -> None:
        if self.analysis_advanced_var.get():
            self.analysis_advanced_frame.grid()
            return
        self.analysis_advanced_frame.grid_remove()

    def _sync_analysis_check_toggles(self, *_args: object) -> None:
        if not hasattr(self, "analysis_auth_checks_toggle"):
            return
        if self.analysis_active_checks_var.get():
            self.analysis_auth_checks_toggle.state(["!disabled"])
            return
        self.analysis_auth_checks_var.set(False)
        self.analysis_auth_checks_toggle.state(["disabled"])

    def _missing_auth_dependencies(self) -> list[str]:
        missing: list[str] = []
        for module_name in ("paramiko", "pymysql"):
            if importlib.util.find_spec(module_name) is None:
                missing.append(module_name)
        return missing

    def _toggle_rules_advanced(self) -> None:
        if self.rules_advanced_var.get():
            self.rules_advanced_frame.grid()
            return
        self.rules_advanced_frame.grid_remove()

    def _sync_discovery_advanced_toggle(self) -> None:
        if self._selected_discovery_preset() == "custom":
            self.discovery_advanced_var.set(True)
            self.discovery_advanced_toggle.configure(text="自定义扫描方式需填写高级参数")
            self.discovery_advanced_toggle.state(["disabled"])
            return
        self.discovery_advanced_toggle.configure(text="展开高级参数")
        self.discovery_advanced_toggle.state(["!disabled"])

    def _update_analysis_profile_hint(self, _event: object | None = None) -> None:
        profile = self._selected_analysis_profile()
        arguments = " ".join(resolve_nmap_arguments(profile))
        description = ANALYSIS_PROFILE_DESCRIPTIONS.get(profile, ANALYSIS_PROFILE_DESCRIPTIONS[DEFAULT_ANALYSIS_PRESET])
        self.analysis_profile_hint_var.set(f"{description}。当前预设参数：{arguments}")

    def _update_discovery_profile_hint(self, *_args: object) -> None:
        label = self._profile_display_name(self.discovery_profile_var.get())
        self.discovery_profile_hint_var.set(
            f"当前资产画像：{label}。仅用于资产重要性标注，不会改变主机发现数量。"
        )

    def _update_analysis_asset_profile_hint(self, *_args: object) -> None:
        label = self._profile_display_name(self.analysis_profile_var.get())
        self.analysis_asset_profile_hint_var.set(
            f"当前资产画像：{label}。会影响资产重要性与最终风险评分；清空后恢复为默认重要性。"
        )

    def _start_asset_discovery(self) -> None:
        self._append_platform_note()

        def worker() -> Any:
            normalized_ports = self._normalize_ports_var(self.discovery_ports_var)
            methods = resolve_discovery_methods(self._selected_discovery_preset(), self.discovery_methods_var.get().strip())
            ports = parse_ports(normalized_ports)
            profile_raw = self.discovery_profile_var.get().strip()
            return self.workbench.discover_assets(
                target=self.discovery_target_var.get().strip(),
                methods=methods,
                ports=ports,
                snapshot_name=self.discovery_name_var.get().strip(),
                asset_profile_path=Path(profile_raw) if profile_raw else None,
            )

        def on_success(snapshot: Any) -> None:
            self.discovery_status_var.set(f"资产发现完成：{snapshot.asset_count} 台主机，快照 {snapshot.snapshot_name}")
            self.analysis_target_var.set(self.discovery_target_var.get().strip())
            self._render_assets(snapshot.assets)
            self._refresh_discovery_snapshots(select_path=str(snapshot.file_path))
            self._append_log(f"资产发现本次使用画像：{self._profile_display_name(getattr(snapshot, 'asset_profile_path', ''))}")
            if getattr(snapshot, "report_path", ""):
                self._append_log(f"资产发现报告已生成：{snapshot.report_path}")

        self._run_async_task("资产发现", worker, on_success=on_success)

    def _start_analysis(self) -> None:
        target = self.analysis_target_var.get().strip()
        if not target:
            messagebox.showwarning("缺少目标", "请输入要执行服务识别与漏洞匹配的目标网段。")
            return
        self._append_platform_note()
        if self.analysis_auth_checks_var.get():
            missing_modules = self._missing_auth_dependencies()
            if missing_modules:
                self._append_log(
                    f"弱口令探测依赖缺失：{', '.join(missing_modules)}。对应协议会被跳过，可通过 requirements-advanced.txt 安装。"
                )

        def worker() -> dict[str, object]:
            profile_raw = self.analysis_profile_var.get().strip()
            extra_raw = self.analysis_extra_args_var.get().strip()
            normalized_ports = self._normalize_ports_var(self.analysis_ports_var)
            return self.workbench.analyze_target(
                target=target,
                ports=parse_ports(normalized_ports),
                nmap_profile=self._selected_analysis_profile(),
                extra_nmap_args=shlex.split(extra_raw) if extra_raw else None,
                scan_name=self.analysis_name_var.get().strip(),
                output_dir=self._resolve_output_dir(self.analysis_output_var.get().strip()),
                asset_profile_path=Path(profile_raw) if profile_raw else None,
                enable_active_checks=self.analysis_active_checks_var.get(),
                enable_auth_checks=self.analysis_auth_checks_var.get(),
            )

        def on_success(result: dict[str, object]) -> None:
            scan_id = int(result["scan_id"])
            self._latest_scan_id = scan_id
            self.analysis_status_var.set(
                f"分析完成：扫描 #{scan_id}，服务 {result['total_services']} 条，风险 {result['total_risks']} 条"
            )
            self._append_log(f"分析本次使用画像：{self._profile_display_name(self.analysis_profile_var.get())}")
            self._append_log(f"分析报告已生成：{result['report_path']}")
            self._refresh_scan_history(select_scan_id=scan_id)
            self._render_analysis_result(scan_id)

        self._run_async_task("服务识别与漏洞匹配", worker, on_success=on_success)

    def _import_rules(self) -> None:
        input_path = self.rules_file_var.get().strip()
        if not input_path:
            messagebox.showwarning("缺少文件", "请选择待导入的本地规则文件。")
            return

        def worker() -> dict[str, Any]:
            return self.workbench.get_rule_manager().import_from_file(Path(input_path), mode=self.rules_mode_var.get().strip())

        def on_success(result: dict[str, Any]) -> None:
            self._refresh_rule_summary()
            self._append_log(f"本地规则导入完成：新增 {result['added_count']} 条，更新 {result['updated_count']} 条。")

        self._run_async_task("本地规则库导入", worker, on_success=on_success)

    def _update_rules_from_url(self) -> None:
        source_url = self.rules_url_var.get().strip()
        if not source_url:
            messagebox.showwarning("缺少地址", "请输入远程规则更新地址。")
            return

        def worker() -> dict[str, Any]:
            return self.workbench.get_rule_manager().update_from_url(
                source_url,
                mode=self.rules_mode_var.get().strip(),
                timeout_seconds=20,
            )

        def on_success(result: dict[str, Any]) -> None:
            self._refresh_rule_summary()
            self._append_log(f"远程规则更新完成：新增 {result['added_count']} 条，更新 {result['updated_count']} 条。")

        self._run_async_task("远程规则库更新", worker, on_success=on_success)

    def _run_compare(self) -> None:
        base_id = self._selected_scan_id(self.compare_base_var.get())
        new_id = self._selected_scan_id(self.compare_new_var.get())
        if base_id is None or new_id is None:
            messagebox.showwarning("缺少报告", "请先选择基线报告和新报告。")
            return

        def worker() -> dict[str, Any]:
            return self.workbench.compare_reports(base_scan_id=base_id, new_scan_id=new_id)

        def on_success(result: dict[str, Any]) -> None:
            self.compare_status_var.set(
                f"对比完成：新增服务 {len(result['service_new'])}，新增漏洞 {len(result['vulnerability_new'])}"
            )
            self._render_compare_result(result)

        self._run_async_task("历史报告对比", worker, on_success=on_success)

    def _run_async_task(
        self,
        task_name: str,
        worker: Callable[[], Any],
        on_success: Callable[[Any], None] | None = None,
    ) -> None:
        if self._busy:
            messagebox.showinfo("任务执行中", "当前已有任务在运行，请等待它结束后再继续。")
            return
        self._busy = True
        self._append_log(f"{task_name}已开始。")

        def runner() -> None:
            try:
                result = worker()
            except Exception as exc:
                self.root.after(0, self._finish_async_error, task_name, exc)
                return
            self.root.after(0, self._finish_async_success, task_name, result, on_success)

        threading.Thread(target=runner, name=f"desktop-task-{task_name}", daemon=True).start()

    def _finish_async_success(
        self,
        task_name: str,
        result: Any,
        on_success: Callable[[Any], None] | None,
    ) -> None:
        self._busy = False
        self._append_log(f"{task_name}执行完成。")
        if on_success is not None:
            on_success(result)

    def _finish_async_error(self, task_name: str, exc: Exception) -> None:
        self._busy = False
        if isinstance(exc, NmapUnavailableError):
            self.analysis_status_var.set("nmap 不可用，请先在当前 Windows 主机安装 nmap。")
        self._append_log(f"{task_name}执行失败：{exc}")
        messagebox.showerror(f"{task_name}失败", str(exc))

    def _refresh_discovery_snapshots(self, select_latest: bool = False, select_path: str | None = None) -> None:
        rows = self.workbench.list_discovery_snapshots(limit=50)
        self._replace_tree_rows(self.snapshots_tree)
        self._snapshot_scan_map = {}
        selected_path = select_path or ""
        if not selected_path and rows and (select_latest or not self._current_snapshot_path):
            selected_path = str(rows[0]["file_path"])
        for row in rows:
            path = str(row["file_path"])
            scan_id = row.get("scan_id")
            if isinstance(scan_id, int):
                self._snapshot_scan_map[path] = scan_id
            report_name = "-"
            report_path = str(row.get("report_path", ""))
            if report_path:
                report_name = Path(report_path).parent.name or Path(report_path).name
            self.snapshots_tree.insert(
                "",
                "end",
                iid=path,
                values=(row["snapshot_name"], row["created_at"], row["target"], row["asset_count"], row["methods"], report_name),
            )
        if selected_path and self.snapshots_tree.exists(selected_path):
            self.snapshots_tree.selection_set(selected_path)
            self.snapshots_tree.focus(selected_path)
            self._load_snapshot_assets(selected_path)

    def _refresh_scan_history(self, select_latest: bool = False, select_scan_id: int | None = None) -> None:
        rows = self.workbench.list_scans(limit=50, scan_type="analysis")
        self._replace_tree_rows(self.reports_tree)
        self._scan_option_map = {}
        values: list[str] = []
        selected_option = ""
        current_new_option = self.compare_new_var.get().strip()
        current_base_option = self.compare_base_var.get().strip()
        self._latest_scan_id = int(rows[0]["id"]) if rows else None
        for row in rows:
            option = self._format_scan_option(row)
            values.append(option)
            self._scan_option_map[option] = int(row["id"])
            self.reports_tree.insert(
                "",
                "end",
                iid=str(row["id"]),
                values=(
                    row["id"],
                    row["started_at"],
                    row["target"],
                    row["total_services"],
                    row["total_risks"],
                    Path(str(row["report_path"])).parent.name,
                ),
            )
            if select_scan_id is not None and int(row["id"]) == int(select_scan_id):
                selected_option = option
        self.compare_base_combo.configure(values=values)
        self.compare_new_combo.configure(values=values)
        if not values:
            self.compare_base_var.set("")
            self.compare_new_var.set("")
            return
        if current_new_option not in self._scan_option_map:
            current_new_option = ""
        if current_base_option not in self._scan_option_map:
            current_base_option = ""
        if not selected_option:
            if select_latest or not current_new_option:
                selected_option = values[0]
            else:
                selected_option = current_new_option
        if selected_option:
            self.compare_new_var.set(selected_option)
            scan_id = self._selected_scan_id(selected_option)
            if scan_id is not None and self.reports_tree.exists(str(scan_id)):
                self.reports_tree.selection_set(str(scan_id))
                self.reports_tree.focus(str(scan_id))
        base_option = current_base_option
        if not base_option:
            if len(values) > 1:
                base_option = values[1]
            else:
                base_option = values[0]
        self.compare_base_var.set(base_option)

    def _refresh_rule_summary(self) -> None:
        summary = self.workbench.get_rule_manager().summary()
        severity_count = summary.get("severity_count", {})
        if isinstance(severity_count, dict) and severity_count:
            levels = " | ".join(f"{level}:{count}" for level, count in severity_count.items())
        else:
            levels = "暂无规则"
        self.rules_status_var.set(f"当前规则库共 {summary.get('total', 0)} 条，分布：{levels}")

    def _render_assets(self, assets: list[Any]) -> None:
        self._replace_tree_rows(self.assets_tree)
        for item in assets:
            ports = ",".join(str(port) for port in getattr(item, "open_ports", []) or [])
            self.assets_tree.insert(
                "",
                "end",
                values=(
                    getattr(item, "ip", ""),
                    getattr(item, "mac", "") or "-",
                    ",".join(getattr(item, "discovered_by", []) or []),
                    ports or "-",
                    getattr(item, "asset_criticality", 5.0),
                ),
            )

    def _render_analysis_result(self, scan_id: int) -> None:
        services = self.workbench.get_services(scan_id)
        vulnerabilities = self.workbench.get_vulnerabilities(scan_id)
        self._replace_tree_rows(self.services_tree)
        for item in services[:300]:
            self.services_tree.insert(
                "",
                "end",
                values=(
                    item["host_ip"],
                    item["port"],
                    item["service_name"],
                    item.get("product") or "-",
                    item.get("version") or "-",
                    item.get("fingerprint_method") or "-",
                    item.get("fingerprint_confidence", 0.0),
                ),
            )
        self._replace_tree_rows(self.vulnerabilities_tree)
        for item in vulnerabilities[:300]:
            self.vulnerabilities_tree.insert(
                "",
                "end",
                values=(
                    item["host_ip"],
                    item["port"],
                    item["cve_id"],
                    item["risk_level"],
                    item["risk_score"],
                    item.get("asset_criticality", 5.0),
                    item.get("confidence_tier") or "-",
                    "是" if item.get("manual_confirmation_needed") else "否",
                ),
            )

    def _render_compare_result(self, result: dict[str, Any]) -> None:
        lines = [
            f"基线报告: #{result['base_scan_id']}",
            f"新报告: #{result['new_scan_id']}",
            "",
            "服务识别差异",
            f"新增服务: {len(result['service_new'])}",
            f"消失服务: {len(result['service_resolved'])}",
            f"持续服务: {len(result['service_persisted'])}",
            "",
            "漏洞匹配差异",
            f"新增漏洞: {len(result['vulnerability_new'])}",
            f"已修复漏洞: {len(result['vulnerability_resolved'])}",
            f"持续漏洞: {len(result['vulnerability_persisted'])}",
            f"风险变化漏洞: {len(result['vulnerability_changed'])}",
        ]
        if result["vulnerability_new"]:
            lines.append("")
            lines.append("新增漏洞样例")
            for item in result["vulnerability_new"][:10]:
                lines.append(f"+ {item['host_ip']}:{item['port']} {item['cve_id']} {item['risk_level']} {item['risk_score']}")
        if result["vulnerability_changed"]:
            lines.append("")
            lines.append("风险变化样例")
            for item in result["vulnerability_changed"][:10]:
                lines.append(
                    f"* {item['host_ip']}:{item['port']} {item['cve_id']} "
                    f"{item['base_risk_score']}->{item['new_risk_score']} "
                    f"{item['base_risk_level']}->{item['new_risk_level']}"
                )
        self._set_text_content(self.compare_text, "\n".join(lines))

    def _handle_snapshot_selection(self, _event: object | None = None) -> None:
        selected = self.snapshots_tree.selection()
        if not selected:
            return
        self._load_snapshot_assets(selected[0])

    def _handle_report_selection(self, _event: object | None = None) -> None:
        selected = self.reports_tree.selection()
        if not selected:
            return
        scan_id = int(selected[0])
        for option, option_scan_id in self._scan_option_map.items():
            if option_scan_id == scan_id:
                self.compare_new_var.set(option)
                break

    def _load_snapshot_assets(self, snapshot_path: str) -> None:
        snapshot = self.workbench.load_discovery_snapshot(Path(snapshot_path))
        self._current_snapshot_path = snapshot_path
        self._current_snapshot_scan_id = self._snapshot_scan_map.get(snapshot_path)
        self.discovery_status_var.set(
            f"当前快照：{snapshot.snapshot_name}，时间 {snapshot.created_at}，主机 {snapshot.asset_count} 台"
        )
        self._render_assets(snapshot.assets)

    def _selected_scan_id(self, option: str) -> int | None:
        normalized = option.strip()
        if not normalized:
            return None
        return self._scan_option_map.get(normalized)

    def _selected_report_scan_id(self) -> int | None:
        selected = self.reports_tree.selection()
        if not selected:
            return None
        return int(selected[0])

    def _open_selected_asset_report(self) -> None:
        if self._current_snapshot_scan_id is None:
            messagebox.showinfo("暂无资产报告", "请先在资产发现历史中选择一条记录。")
            return
        self._open_report_by_scan_id(self._current_snapshot_scan_id)

    def _delete_selected_asset_report(self) -> None:
        scan_id = self._current_snapshot_scan_id
        if scan_id is None:
            messagebox.showinfo("未选择资产报告", "请先在资产发现历史中选择一条记录。")
            return
        if not messagebox.askyesno("确认删除", f"确定要删除资产发现报告 #{scan_id} 吗？该操作会同时删除快照、数据库记录和报告目录。"):
            return

        def worker() -> dict[str, Any]:
            return self.workbench.delete_scan(scan_id)

        def on_success(result: dict[str, Any]) -> None:
            deleted_scan_id = int(result["scan_id"])
            self._clear_asset_views()
            self._refresh_discovery_snapshots(select_latest=True)
            self.discovery_status_var.set(f"资产发现报告 #{deleted_scan_id} 已删除")
            self._append_log(f"资产发现报告 #{deleted_scan_id} 已删除。")

        self._run_async_task("删除资产发现报告", worker, on_success=on_success)

    def _start_report_center(self) -> None:
        try:
            url = self._ensure_report_center_running()
        except Exception as exc:
            messagebox.showerror("启动失败", str(exc))
            self._append_log(f"报告中心启动失败：{exc}")
            return
        self.web_status_var.set("报告中心运行中")
        self.web_url_var.set(url)

    def _open_report_center(self) -> None:
        try:
            url = self._ensure_report_center_running()
        except Exception as exc:
            messagebox.showerror("打开失败", str(exc))
            self._append_log(f"报告中心打开失败：{exc}")
            return
        webbrowser.open(url)
        self._append_log(f"已打开报告中心：{url}")

    def _stop_report_center(self) -> None:
        try:
            self.server.stop(log_callback=self._append_log)
        except Exception as exc:
            messagebox.showerror("停止失败", str(exc))
            self._append_log(f"报告中心停止失败：{exc}")
            return
        self.web_status_var.set("报告中心已停止")

    def _ensure_report_center_running(self) -> str:
        if self.server.is_running():
            url = self.server.current_url()
            if url is None:
                raise RuntimeError("报告中心当前状态异常，无法获取访问地址。")
            return url
        config = LauncherConfig(
            host=self.web_host_var.get().strip(),
            port=int(self.web_port_var.get().strip()),
            db_path=Path(self.web_db_var.get().strip()),
            max_concurrent=1,
            auto_open_browser=False,
        )
        url = self.server.start(config, log_callback=self._append_log)
        self.web_status_var.set("报告中心运行中")
        self.web_url_var.set(url)
        return url

    def _open_selected_report(self) -> None:
        scan_id = self._selected_report_scan_id()
        if scan_id is None:
            messagebox.showinfo("未选择报告", "请先在分析报告历史中选择一条记录。")
            return
        self._open_report_by_scan_id(scan_id)

    def _delete_selected_report(self) -> None:
        scan_id = self._selected_report_scan_id()
        if scan_id is None:
            messagebox.showinfo("未选择报告", "请先在分析报告历史中选择一条记录。")
            return
        if not messagebox.askyesno("确认删除", f"确定要删除报告 #{scan_id} 吗？该操作会同时删除数据库记录和报告目录。"):
            return

        def worker() -> dict[str, Any]:
            return self.workbench.delete_scan(scan_id)

        def on_success(result: dict[str, Any]) -> None:
            deleted_scan_id = int(result["scan_id"])
            self._clear_analysis_views()
            self._set_text_content(self.compare_text, "")
            self._refresh_scan_history(select_latest=True)
            self.analysis_status_var.set(f"报告 #{deleted_scan_id} 已删除")
            self.compare_status_var.set("等待选择两份分析报告")
            self._append_log(f"分析报告 #{deleted_scan_id} 已删除。")

        self._run_async_task("删除分析报告", worker, on_success=on_success)

    def _open_selected_scan_detail(self) -> None:
        scan_id = self._selected_report_scan_id()
        if scan_id is None:
            messagebox.showinfo("未选择记录", "请先在分析报告历史中选择一条记录。")
            return
        self._open_scan_detail(scan_id)

    def _open_latest_report(self) -> None:
        if self._latest_scan_id is None:
            messagebox.showinfo("暂无报告", "当前还没有可打开的分析报告。")
            return
        self._open_report_by_scan_id(self._latest_scan_id)

    def _open_report_by_scan_id(self, scan_id: int) -> None:
        try:
            base_url = self._ensure_report_center_running()
        except Exception as exc:
            messagebox.showerror("打开报告失败", str(exc))
            return
        url = f"{base_url}/report/{scan_id}"
        webbrowser.open(url)
        self._append_log(f"已打开报告 #{scan_id}：{url}")

    def _open_scan_detail(self, scan_id: int) -> None:
        try:
            base_url = self._ensure_report_center_running()
        except Exception as exc:
            messagebox.showerror("打开详情失败", str(exc))
            return
        url = f"{base_url}/scan/{scan_id}"
        webbrowser.open(url)
        self._append_log(f"已打开扫描详情 #{scan_id}：{url}")

    def _open_compare_page(self) -> None:
        base_id = self._selected_scan_id(self.compare_base_var.get())
        new_id = self._selected_scan_id(self.compare_new_var.get())
        if base_id is None or new_id is None:
            messagebox.showinfo("缺少报告", "请先选择两份分析报告。")
            return
        try:
            base_url = self._ensure_report_center_running()
        except Exception as exc:
            messagebox.showerror("打开对比页失败", str(exc))
            return
        url = f"{base_url}/compare?base={base_id}&new={new_id}"
        webbrowser.open(url)
        self._append_log(f"已打开报告对比页：{url}")

    def _choose_rule_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="选择规则文件",
            initialdir=str(PROJECT_ROOT),
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
        )
        if selected:
            self.rules_file_var.set(selected)

    def _choose_asset_profile(self, variable: StringVar) -> None:
        selected = filedialog.askopenfilename(
            title="选择资产画像文件",
            initialdir=str(PROJECT_ROOT),
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
        )
        if selected:
            variable.set(selected)

    def _clear_asset_profile(self, variable: StringVar, scope: str) -> None:
        if not variable.get().strip():
            return
        variable.set("")
        self._append_log(f"{scope}页的资产画像已清空，后续扫描将恢复默认重要性。")

    def _choose_output_dir(self) -> None:
        selected = filedialog.askdirectory(title="选择报告输出目录", initialdir=str(PROJECT_ROOT))
        if selected:
            self.analysis_output_var.set(selected)

    def _restore_discovery_default_ports(self) -> None:
        self.discovery_ports_var.set(self._default_ports_text)
        self._append_log("资产发现候选端口已恢复为默认端口集合。")

    def _restore_analysis_default_ports(self) -> None:
        self.analysis_ports_var.set(self._default_ports_text)
        self._append_log("候选端口已恢复为默认端口集合。")

    def _replace_discovery_port_range(self) -> None:
        self._apply_port_range(
            self.discovery_ports_var,
            self.discovery_port_range_start_var,
            self.discovery_port_range_end_var,
            scope="资产发现",
            append_mode=False,
        )

    def _append_discovery_port_range(self) -> None:
        self._apply_port_range(
            self.discovery_ports_var,
            self.discovery_port_range_start_var,
            self.discovery_port_range_end_var,
            scope="资产发现",
            append_mode=True,
        )

    def _replace_analysis_port_range(self) -> None:
        self._apply_port_range(
            self.analysis_ports_var,
            self.analysis_port_range_start_var,
            self.analysis_port_range_end_var,
            scope="漏洞匹配与服务识别",
            append_mode=False,
        )

    def _append_analysis_port_range(self) -> None:
        self._apply_port_range(
            self.analysis_ports_var,
            self.analysis_port_range_start_var,
            self.analysis_port_range_end_var,
            scope="漏洞匹配与服务识别",
            append_mode=True,
        )

    def _set_discovery_common_port_range(self) -> None:
        self._set_port_expression(self.discovery_ports_var, COMMON_PORT_RANGE_EXPRESSION, "资产发现", "常见范围")

    def _set_discovery_full_port_range(self) -> None:
        self._set_port_expression(self.discovery_ports_var, FULL_PORT_RANGE_EXPRESSION, "资产发现", "全端口")

    def _set_analysis_common_port_range(self) -> None:
        self._set_port_expression(self.analysis_ports_var, COMMON_PORT_RANGE_EXPRESSION, "漏洞匹配与服务识别", "常见范围")

    def _set_analysis_full_port_range(self) -> None:
        self._set_port_expression(self.analysis_ports_var, FULL_PORT_RANGE_EXPRESSION, "漏洞匹配与服务识别", "全端口")

    def _apply_port_range(
        self,
        variable: StringVar,
        start_var: StringVar,
        end_var: StringVar,
        scope: str,
        append_mode: bool,
    ) -> None:
        try:
            expression = build_port_range_expression(start_var.get(), end_var.get())
        except ValueError as exc:
            messagebox.showerror("端口范围无效", str(exc))
            return
        if append_mode:
            variable.set(append_port_expression(variable.get().strip(), expression))
            self._append_log(f"{scope}候选端口已追加范围：{expression}")
            return
        variable.set(expression)
        self._append_log(f"{scope}候选端口已设置为范围：{expression}")

    def _set_port_expression(self, variable: StringVar, expression: str, scope: str, label: str) -> None:
        variable.set(expression)
        self._append_log(f"{scope}候选端口已设置为{label}：{expression}")

    def _replace_tree_rows(self, tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)

    def _set_text_content(self, widget: Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def _clear_analysis_views(self) -> None:
        self._replace_tree_rows(self.services_tree)
        self._replace_tree_rows(self.vulnerabilities_tree)

    def _clear_asset_views(self) -> None:
        self._replace_tree_rows(self.assets_tree)
        self._current_snapshot_path = ""
        self._current_snapshot_scan_id = None

    def _normalize_ports_var(self, variable: StringVar) -> str:
        raw = variable.get().strip()
        if raw:
            return raw
        variable.set(self._default_ports_text)
        self._append_log(f"候选端口为空，已自动恢复为默认端口集合：{self._default_ports_text}")
        return self._default_ports_text

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
        except (RuntimeError, TclError):
            return

    def _clear_log(self) -> None:
        self._set_text_content(self.log_text, "")

    def _format_scan_option(self, row: dict[str, Any]) -> str:
        return f"#{row['id']} | {row['started_at']} | {row['target']}"

    def _profile_display_name(self, raw_path: str) -> str:
        normalized = raw_path.strip()
        if not normalized:
            return "未使用"
        return Path(normalized).name

    def _resolve_output_dir(self, raw_path: str) -> Path:
        if not raw_path:
            return DEFAULT_REPORT_DIR
        candidate = Path(raw_path).expanduser()
        if candidate.is_absolute():
            return candidate
        return (PROJECT_ROOT / candidate).resolve()

    def _append_platform_note(self) -> None:
        if self._platform_note_logged or os.name != "nt":
            return
        self._platform_note_logged = True
        self._append_log("Windows 主控提示：ICMP 已切换为 Windows ping 参数；ARP/SYN 受 scapy、Npcap 与权限影响，不满足条件时会自动降级。")
        self._append_log("Windows 主控提示：漏洞匹配与服务识别依赖 nmap；如果 nmap 不可用，分析页会直接报错而不是给出伪结果。")

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

    def _release_tk_variables(self) -> None:
        for name in (
            "discovery_target_var",
            "discovery_preset_var",
            "discovery_methods_var",
            "discovery_ports_var",
            "discovery_port_range_start_var",
            "discovery_port_range_end_var",
            "discovery_profile_var",
            "discovery_profile_hint_var",
            "discovery_name_var",
            "discovery_status_var",
            "discovery_advanced_var",
            "analysis_target_var",
            "analysis_name_var",
            "analysis_output_var",
            "analysis_profile_var",
            "analysis_nmap_profile_var",
            "analysis_ports_var",
            "analysis_port_range_start_var",
            "analysis_port_range_end_var",
            "analysis_extra_args_var",
            "analysis_profile_hint_var",
            "analysis_asset_profile_hint_var",
            "analysis_status_var",
            "analysis_advanced_var",
            "analysis_active_checks_var",
            "analysis_auth_checks_var",
            "rules_file_var",
            "rules_url_var",
            "rules_mode_var",
            "rules_status_var",
            "rules_advanced_var",
            "compare_base_var",
            "compare_new_var",
            "compare_status_var",
            "web_host_var",
            "web_port_var",
            "web_db_var",
            "web_status_var",
            "web_url_var",
        ):
            if hasattr(self, name):
                setattr(self, name, None)
