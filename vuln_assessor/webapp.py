from __future__ import annotations

# pyright: reportMissingImports=false
# pyright: reportUnknownVariableType=false
# pyright: reportUnknownMemberType=false
# pyright: reportUnknownParameterType=false
# pyright: reportUnknownArgumentType=false
# pyright: reportUntypedFunctionDecorator=false
# pyright: reportUnusedFunction=false
# pyright: reportUnusedCallResult=false
# pyright: reportExplicitAny=false
# pyright: reportAny=false
# pyright: reportUnannotatedClassAttribute=false

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any
from uuid import uuid4

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, url_for

from vuln_assessor.config import DEFAULT_REPORT_DIR, parse_methods, parse_ports
from vuln_assessor.orchestrator import ScanOrchestrator
from vuln_assessor.risk import load_asset_profile
from vuln_assessor.storage import ScanRepository


class ConcurrentScanTaskManager:
    def __init__(self, db_path: Path, max_workers: int = 3) -> None:
        self.db_path = db_path
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.lock = Lock()
        self.tasks: dict[str, dict[str, Any]] = {}

    def submit_scan(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        output_dir: Path,
        scan_name: str,
        asset_profile_path: Path | None,
    ) -> str:
        task_id = uuid4().hex[:12]
        task = {
            "task_id": task_id,
            "status": "queued",
            "target": target,
            "methods": ",".join(methods),
            "ports": ",".join(str(port) for port in ports),
            "scan_name": scan_name,
            "asset_profile": str(asset_profile_path) if asset_profile_path else "",
            "submitted_at": self._now_text(),
            "started_at": "",
            "finished_at": "",
            "scan_id": None,
            "report_path": "",
            "message": "任务已进入队列",
        }
        with self.lock:
            self.tasks[task_id] = task
        self.executor.submit(
            self._run_scan_task,
            task_id,
            target,
            methods,
            ports,
            output_dir,
            scan_name,
            asset_profile_path,
        )
        return task_id

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self.lock:
            task = self.tasks.get(task_id)
            return dict(task) if task else None

    def list_tasks(self, limit: int = 30) -> list[dict[str, Any]]:
        with self.lock:
            rows = [dict(item) for item in self.tasks.values()]
        rows.sort(key=lambda item: item.get("submitted_at", ""), reverse=True)
        return rows[:limit]

    def _run_scan_task(
        self,
        task_id: str,
        target: str,
        methods: list[str],
        ports: list[int],
        output_dir: Path,
        scan_name: str,
        asset_profile_path: Path | None,
    ) -> None:
        self._update_task(task_id, status="running", started_at=self._now_text(), message="扫描执行中")
        try:
            asset_map, default_asset = load_asset_profile(asset_profile_path)
            repository = ScanRepository(self.db_path)
            repository.initialize()
            orchestrator = ScanOrchestrator(
                repository,
                asset_criticality_map=asset_map,
                default_asset_criticality=default_asset,
            )
            result = orchestrator.run_scan(
                target_cidr=target,
                methods=methods,
                ports=ports,
                output_dir=output_dir,
                scan_name=scan_name,
            )
            self._update_task(
                task_id,
                status="finished",
                finished_at=self._now_text(),
                scan_id=result.get("scan_id"),
                report_path=result.get("report_path", ""),
                message=f"扫描完成，发现风险 {result.get('total_risks', 0)} 条",
            )
        except Exception as exc:
            self._update_task(
                task_id,
                status="failed",
                finished_at=self._now_text(),
                message=f"任务失败: {exc}",
            )

    def _update_task(self, task_id: str, **fields: Any) -> None:
        with self.lock:
            task = self.tasks.get(task_id)
            if task is None:
                return
            task.update(fields)

    def _now_text(self) -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def create_app(db_path: Path, max_concurrent: int = 3) -> Flask:
    project_root = Path(__file__).resolve().parent
    template_dir = project_root / "web" / "templates"
    static_dir = project_root / "web" / "static"

    app = Flask(__name__, template_folder=str(template_dir), static_folder=str(static_dir))
    app.secret_key = "intra-vuln-assessor-web-secret"

    repository = ScanRepository(db_path)
    repository.initialize()
    task_manager = ConcurrentScanTaskManager(db_path=db_path, max_workers=max_concurrent)

    @app.get("/")
    def dashboard() -> str:
        scans = repository.list_scans(limit=30)
        tasks = task_manager.list_tasks(limit=30)
        has_running_task = any(task["status"] in {"queued", "running"} for task in tasks)
        latest_scan_id = scans[0]["id"] if scans else None
        manual_confirm_needed_latest = 0
        if latest_scan_id is not None:
            try:
                vulnerabilities = repository.get_vulnerabilities(latest_scan_id)
                manual_confirm_needed_latest = sum(
                    1 for item in vulnerabilities if item.get("manual_confirmation_needed")
                )
            except Exception:
                manual_confirm_needed_latest = 0
        stats = {
            "total_scans": len(scans),
            "total_risks": sum(int(item.get("total_risks", 0)) for item in scans),
            "latest_scan_id": latest_scan_id,
            "running_tasks": sum(1 for task in tasks if task["status"] in {"queued", "running"}),
            "max_concurrent": max_concurrent,
            "manual_confirm_needed_latest": int(manual_confirm_needed_latest),
        }
        return render_template("dashboard.html", scans=scans, tasks=tasks, stats=stats, has_running_task=has_running_task)

    @app.post("/scan/submit")
    def submit_scan() -> Response:
        target = str(request.form.get("target", "")).strip()
        methods_raw = str(request.form.get("methods", "")).strip()
        ports_raw = str(request.form.get("ports", "")).strip()
        output_dir_raw = str(request.form.get("output_dir", "")).strip()
        scan_name = str(request.form.get("scan_name", "")).strip()
        asset_profile_raw = str(request.form.get("asset_profile", "")).strip()

        if not target:
            flash("目标网段不能为空。", "error")
            return redirect(url_for("dashboard"))

        try:
            methods = parse_methods(methods_raw)
            ports = parse_ports(ports_raw)
            output_dir = _resolve_output_dir(output_dir_raw)
            asset_profile_path = Path(asset_profile_raw) if asset_profile_raw else None
            task_id = task_manager.submit_scan(
                target=target,
                methods=methods,
                ports=ports,
                output_dir=output_dir,
                scan_name=scan_name,
                asset_profile_path=asset_profile_path,
            )
        except Exception as exc:
            flash(f"提交扫描任务失败: {exc}", "error")
            return redirect(url_for("dashboard"))

        flash(f"扫描任务已提交，任务ID: {task_id}", "success")
        return redirect(url_for("dashboard"))

    @app.get("/task/<task_id>")
    def task_status(task_id: str) -> Response:
        task = task_manager.get_task(task_id)
        if task is None:
            return jsonify({"error": "task not found"}), 404
        return jsonify(task)

    @app.get("/scan/<int:scan_id>")
    def scan_detail(scan_id: int) -> str:
        scan = repository.get_scan(scan_id)
        if scan is None:
            abort(404)
        assets = repository.get_assets(scan_id)
        services = repository.get_services(scan_id)
        vulnerabilities = repository.get_vulnerabilities(scan_id)
        return render_template(
            "scan_detail.html",
            scan=scan,
            assets=assets,
            services=services,
            vulnerabilities=vulnerabilities,
        )

    @app.get("/compare")
    def compare_page() -> str:
        scans = repository.list_scans(limit=50)
        base_id = request.args.get("base", type=int)
        new_id = request.args.get("new", type=int)
        comparison = None
        if base_id is not None and new_id is not None:
            try:
                comparison = repository.compare_scan_outputs(base_scan_id=base_id, new_scan_id=new_id)
            except ValueError as exc:
                flash(f"结果对比失败: {exc}", "error")
        return render_template(
            "compare.html",
            scans=scans,
            base_id=base_id,
            new_id=new_id,
            comparison=comparison,
        )

    @app.get("/report/<int:scan_id>")
    def view_report(scan_id: int) -> Response:
        scan = repository.get_scan(scan_id)
        if scan is None:
            abort(404)
            raise AssertionError("unreachable")
        report_path = _resolve_report_path(scan["report_path"])
        if not report_path.exists():
            abort(404)
        html = report_path.read_text(encoding="utf-8")
        return Response(html, mimetype="text/html")

    return app


def run_web_app(db_path: Path, host: str = "127.0.0.1", port: int = 5000, max_concurrent: int = 3, debug: bool = False) -> None:
    app = create_app(db_path=db_path, max_concurrent=max_concurrent)
    app.run(host=host, port=port, debug=debug, threaded=True)


def _resolve_report_path(raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return (Path.cwd() / candidate).resolve()


def _resolve_output_dir(raw_path: str) -> Path:
    base_dir = (Path.cwd() / DEFAULT_REPORT_DIR).resolve()
    raw_path = (raw_path or "").strip()
    if not raw_path or raw_path in {".", "reports"}:
        return base_dir
    candidate = Path(raw_path)
    if candidate.is_absolute():
        raise ValueError("输出目录仅支持相对路径")
    if raw_path.startswith("reports/") or raw_path.startswith("reports\\"):
        resolved = (Path.cwd() / candidate).resolve()
    else:
        resolved = (base_dir / candidate).resolve()
    if resolved != base_dir and base_dir not in resolved.parents:
        raise ValueError("输出目录必须位于 reports 目录下")
    return resolved
