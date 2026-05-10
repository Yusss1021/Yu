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

import os
import re
from pathlib import Path

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, send_from_directory, url_for

from vuln_assessor.config import DEFAULT_REPORT_DIR
from vuln_assessor.report_lifecycle import resolve_report_path
from vuln_assessor.storage import ScanRepository
from vuln_assessor.workbench import ScanWorkbench

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = Path(os.environ.get("INTRA_VULN_REPORT_DIR", str(PROJECT_ROOT / DEFAULT_REPORT_DIR))).resolve()


def create_app(db_path: Path, max_concurrent: int = 3) -> Flask:
    project_root = Path(__file__).resolve().parent
    template_dir = project_root / "web" / "templates"
    static_dir = project_root / "web" / "static"

    app = Flask(__name__, template_folder=str(template_dir), static_folder=str(static_dir))
    app.secret_key = "intra-vuln-assessor-web-secret"

    repository = ScanRepository(db_path)
    repository.initialize()
    workbench = ScanWorkbench(db_path=db_path, report_dir=REPORT_ROOT)

    @app.get("/")
    def dashboard() -> str:
        scans = repository.list_scans(limit=30, scan_type="analysis")
        latest_scan_id = scans[0]["id"] if scans else None
        manual_confirm_needed_latest = 0
        latest_report_path = ""
        if latest_scan_id is not None:
            try:
                vulnerabilities = repository.get_vulnerabilities(latest_scan_id)
                manual_confirm_needed_latest = sum(
                    1 for item in vulnerabilities if item.get("manual_confirmation_needed")
                )
            except Exception:
                manual_confirm_needed_latest = 0
            latest_scan = repository.get_scan(latest_scan_id)
            if latest_scan is not None:
                latest_report_path = str(latest_scan.get("report_path", ""))
        stats = {
            "total_scans": len(scans),
            "total_risks": sum(int(item.get("total_risks", 0)) for item in scans),
            "latest_scan_id": latest_scan_id,
            "manual_confirm_needed_latest": int(manual_confirm_needed_latest),
            "latest_report_path": latest_report_path,
            "total_services": sum(int(item.get("total_services", 0)) for item in scans),
        }
        return render_template("dashboard.html", scans=scans, stats=stats)

    @app.post("/scan/submit")
    def submit_scan() -> Response:
        flash("扫描控制已迁移到桌面端，请使用桌面控制台执行资产发现或漏洞匹配。", "error")
        return redirect(url_for("dashboard"))

    @app.get("/task/<task_id>")
    def task_status(task_id: str) -> Response:
        return jsonify(
            {
                "error": "desktop-control-only",
                "message": "Web 报告中心不再负责扫描任务调度，请改用桌面控制台。",
                "task_id": task_id,
            }
        ), 410

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

    @app.post("/scan/<int:scan_id>/delete")
    def delete_scan(scan_id: int) -> Response:
        try:
            result = workbench.delete_scan(scan_id)
        except ValueError:
            abort(404)
        flash(f"报告 #{scan_id} 已删除。", "success")
        deleted_paths = result.get("deleted_paths", [])
        if deleted_paths:
            flash(f"已清理报告产物：{', '.join(str(item) for item in deleted_paths)}", "success")
        return redirect(url_for("dashboard"))

    @app.get("/compare")
    def compare_page() -> str:
        scans = repository.list_scans(limit=50, scan_type="analysis")
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
        report_path = resolve_report_path(str(scan["report_path"]), REPORT_ROOT)
        if not report_path.exists():
            abort(404)
        html = report_path.read_text(encoding="utf-8")
        asset_prefix = url_for("view_report_asset", scan_id=scan_id, asset_name="").rstrip("/")
        html = re.sub(r'([\"\'])assets/', rf"\1{asset_prefix}/", html)
        return Response(html, mimetype="text/html")

    @app.get("/report/<int:scan_id>/assets/<path:asset_name>")
    def view_report_asset(scan_id: int, asset_name: str) -> Response:
        scan = repository.get_scan(scan_id)
        if scan is None:
            abort(404)
            raise AssertionError("unreachable")
        report_path = resolve_report_path(str(scan["report_path"]), REPORT_ROOT)
        asset_root = (report_path.parent / "assets").resolve()
        candidate = (asset_root / asset_name).resolve()
        try:
            candidate.relative_to(asset_root)
        except ValueError:
            abort(404)
            raise AssertionError("unreachable")
        if not candidate.exists() or not candidate.is_file():
            abort(404)
            raise AssertionError("unreachable")
        return send_from_directory(str(asset_root), asset_name)

    return app


def run_web_app(db_path: Path, host: str = "127.0.0.1", port: int = 5000, max_concurrent: int = 3, debug: bool = False) -> None:
    app = create_app(db_path=db_path, max_concurrent=max_concurrent)
    app.run(host=host, port=port, debug=debug, threaded=True)
