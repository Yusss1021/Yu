"""
Flask views and routes.
"""

from datetime import datetime
from pathlib import Path

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app

from vulnscan.config import get_config
from vulnscan.core.models import RiskLevel
from vulnscan.core.scoring import calculate_scan_risk_summary
from vulnscan.storage.database import Database
from vulnscan.storage.repository import (
    HostRepository,
    RiskResultRepository,
    ScanRepository,
    ServiceRepository,
    VulnerabilityRepository,
)

views_bp = Blueprint("views", __name__)

# i18n strings
I18N = {
    "zh_CN": {
        "title": "脆弱性扫描系统",
        "dashboard": "仪表盘",
        "new_scan": "新建扫描",
        "history": "扫描历史",
        "total_scans": "扫描总数",
        "hosts_scanned": "已扫描主机",
        "vulns_found": "发现漏洞",
        "critical_hosts": "高危主机",
        "recent_scans": "最近扫描",
        "target": "目标",
        "status": "状态",
        "started": "开始时间",
        "actions": "操作",
        "view_details": "查看详情",
        "scan_target": "扫描目标",
        "discovery_method": "发现方式",
        "port_range": "端口范围",
        "start_scan": "开始扫描",
        "scan_details": "扫描详情",
        "host_list": "主机列表",
        "ip_address": "IP地址",
        "hostname": "主机名",
        "os": "操作系统",
        "services": "服务",
        "risk_score": "风险评分",
        "risk_level": "风险等级",
        "vulnerabilities": "漏洞列表",
        "cve_id": "CVE编号",
        "severity": "严重程度",
        "cvss": "CVSS评分",
        "description": "描述",
        "export_report": "导出报告",
        "scanning": "扫描中...",
        "completed": "已完成",
        "failed": "失败",
        "pending": "等待中",
    },
    "en_US": {
        "title": "Vulnerability Scanner",
        "dashboard": "Dashboard",
        "new_scan": "New Scan",
        "history": "History",
        "total_scans": "Total Scans",
        "hosts_scanned": "Hosts Scanned",
        "vulns_found": "Vulns Found",
        "critical_hosts": "Critical Hosts",
        "recent_scans": "Recent Scans",
        "target": "Target",
        "status": "Status",
        "started": "Started",
        "actions": "Actions",
        "view_details": "View Details",
        "scan_target": "Scan Target",
        "discovery_method": "Discovery Method",
        "port_range": "Port Range",
        "start_scan": "Start Scan",
        "scan_details": "Scan Details",
        "host_list": "Host List",
        "ip_address": "IP Address",
        "hostname": "Hostname",
        "os": "OS",
        "services": "Services",
        "risk_score": "Risk Score",
        "risk_level": "Risk Level",
        "vulnerabilities": "Vulnerabilities",
        "cve_id": "CVE ID",
        "severity": "Severity",
        "cvss": "CVSS",
        "description": "Description",
        "export_report": "Export Report",
        "scanning": "Scanning...",
        "completed": "Completed",
        "failed": "Failed",
        "pending": "Pending",
    },
}


def get_i18n():
    lang = current_app.config.get("LANGUAGE", "zh_CN")
    return I18N.get(lang, I18N["en_US"])


def get_db():
    db_path = current_app.config.get("DATABASE_PATH")
    return Database(Path(db_path) if db_path else None)


@views_bp.route("/")
def dashboard():
    """Dashboard with scan overview."""
    i18n = get_i18n()
    db = get_db()

    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    risk_repo = RiskResultRepository(db)

    scans = scan_repo.get_all(limit=10)

    # Calculate stats
    total_scans = len(scan_repo.get_all(limit=1000))
    total_hosts = 0
    total_vulns = 0
    critical_hosts = 0

    for scan in scans[:5]:
        hosts = host_repo.get_by_scan(scan.id)
        total_hosts += len(hosts)
        risks = risk_repo.get_by_scan(scan.id)
        for r in risks:
            total_vulns += r.vuln_count
            if r.risk_level == RiskLevel.CRITICAL:
                critical_hosts += 1

    return render_template(
        "dashboard.html",
        i18n=i18n,
        scans=scans,
        stats={
            "total_scans": total_scans,
            "total_hosts": total_hosts,
            "total_vulns": total_vulns,
            "critical_hosts": critical_hosts,
        },
    )


@views_bp.route("/scans/new", methods=["GET", "POST"])
def new_scan():
    """Create a new scan."""
    i18n = get_i18n()

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        method = request.form.get("method", "icmp")
        ports = request.form.get("ports", "1-1024")
        verify = request.form.get("verify") == "on"

        if not target:
            flash("Target is required", "error")
            return render_template("new_scan.html", i18n=i18n)

        import threading
        from vulnscan.config import get_config
        from vulnscan.core.pipeline import ScanPipelineRunner

        db = get_db()
        config = get_config()
        lang = current_app.config.get("LANGUAGE", "zh_CN")

        def run_scan():
            try:
                runner = ScanPipelineRunner(db=db)
                runner.run(
                    target_range=target,
                    discovery_method=method,
                    port_range=ports,
                    verify_services=verify,
                    language=lang,
                )
            except Exception as e:
                current_app.logger.error(f"Scan failed: {e}")

        thread = threading.Thread(target=run_scan)
        thread.start()

        flash(f"扫描已启动: {target}", "success")
        return redirect(url_for("views.history"))

    return render_template("new_scan.html", i18n=i18n)


@views_bp.route("/scans/<int:scan_id>")
def scan_detail(scan_id: int):
    """Show scan details."""
    i18n = get_i18n()
    db = get_db()

    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    service_repo = ServiceRepository(db)
    risk_repo = RiskResultRepository(db)
    vuln_repo = VulnerabilityRepository(db)

    scan = scan_repo.get(scan_id)
    if not scan:
        flash("Scan not found", "error")
        return redirect(url_for("views.dashboard"))

    hosts = host_repo.get_by_scan(scan_id)
    risk_results = risk_repo.get_by_scan(scan_id)
    risk_map = {r.host_id: r for r in risk_results}

    # Get services and vulnerabilities for each host
    host_data = []
    all_vulns = []
    seen_vulns = set()

    for host in hosts:
        services = service_repo.get_by_host(host.id)
        risk = risk_map.get(host.id)

        for svc in services:
            svc_vulns = vuln_repo.get_by_service(svc.id)
            for v in svc_vulns:
                if v.cve_id not in seen_vulns:
                    seen_vulns.add(v.cve_id)
                    all_vulns.append(v)

        host_data.append({
            "host": host,
            "services": services,
            "risk": risk,
        })

    summary = calculate_scan_risk_summary(risk_results)

    return render_template(
        "scan_detail.html",
        i18n=i18n,
        scan=scan,
        host_data=host_data,
        vulnerabilities=sorted(all_vulns, key=lambda v: v.cvss_base or 0, reverse=True),
        summary=summary,
    )


@views_bp.route("/scans/<int:scan_id>/topology")
def topology(scan_id: int):
    """Show network topology visualization."""
    i18n = get_i18n()
    db = get_db()

    scan_repo = ScanRepository(db)
    scan = scan_repo.get(scan_id)
    if not scan:
        flash("Scan not found", "error")
        return redirect(url_for("views.dashboard"))

    return render_template("topology.html", i18n=i18n, scan=scan)


@views_bp.route("/history")
def history():
    """Show scan history."""
    i18n = get_i18n()
    db = get_db()

    scan_repo = ScanRepository(db)
    scans = scan_repo.get_all(limit=100)

    return render_template("history.html", i18n=i18n, scans=scans)


@views_bp.route("/compare/<int:scan_id_old>/<int:scan_id_new>")
def compare(scan_id_old: int, scan_id_new: int):
    """Compare two scan results."""
    i18n = get_i18n()
    db = get_db()

    from vulnscan.core.diff import ScanComparator
    from vulnscan.storage.repository import VulnerabilityRepository

    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    service_repo = ServiceRepository(db)
    vuln_repo = VulnerabilityRepository(db)
    risk_repo = RiskResultRepository(db)

    scan_old = scan_repo.get(scan_id_old)
    scan_new = scan_repo.get(scan_id_new)

    if not scan_old or not scan_new:
        flash("Scan not found", "error")
        return redirect(url_for("views.history"))

    # Gather data
    hosts_old = host_repo.get_by_scan(scan_id_old)
    hosts_new = host_repo.get_by_scan(scan_id_new)

    services_old, services_new = [], []
    vulns_old, vulns_new = [], []
    vuln_ids_old, vuln_ids_new = set(), set()

    for h in hosts_old:
        svcs = service_repo.get_by_host(h.id)
        services_old.extend(svcs)
        for s in svcs:
            for v in vuln_repo.get_by_service(s.id):
                if v.id not in vuln_ids_old:
                    vuln_ids_old.add(v.id)
                    vulns_old.append(v)

    for h in hosts_new:
        svcs = service_repo.get_by_host(h.id)
        services_new.extend(svcs)
        for s in svcs:
            for v in vuln_repo.get_by_service(s.id):
                if v.id not in vuln_ids_new:
                    vuln_ids_new.add(v.id)
                    vulns_new.append(v)

    risks_old = risk_repo.get_by_scan(scan_id_old)
    risks_new = risk_repo.get_by_scan(scan_id_new)

    comparator = ScanComparator()
    diff = comparator.compare(
        scan_old, scan_new,
        hosts_old, hosts_new,
        services_old, services_new,
        vulns_old, vulns_new,
        risks_old, risks_new,
    )

    return render_template(
        "compare.html",
        i18n=i18n,
        scan_old=scan_old,
        scan_new=scan_new,
        diff=diff,
    )


@views_bp.route("/schedules")
def schedules():
    """Show scheduled scans management."""
    i18n = get_i18n()
    db = get_db()

    from vulnscan.scheduler import ScheduleRepository

    repo = ScheduleRepository(db)
    schedule_list = repo.get_all()

    return render_template("schedules.html", i18n=i18n, schedules=schedule_list)


@views_bp.route("/schedules/add", methods=["POST"])
def schedule_add():
    """Add a new scheduled scan."""
    import re
    db = get_db()

    from vulnscan.scheduler import ScheduledScan, ScheduleRepository
    from vulnscan.scheduler.runner import get_next_run

    name = request.form.get("name", "").strip()
    target = request.form.get("target", "").strip()
    cron_expr = request.form.get("cron", "").strip()
    method = request.form.get("method", "icmp")
    ports = request.form.get("ports", "1-1024").strip()

    if not all([name, target, cron_expr]):
        flash("All fields are required", "error")
        return redirect(url_for("views.schedules"))

    # Validate target (IP, CIDR, or range)
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?(-\d{1,3})?$'
    if not re.match(ip_pattern, target):
        flash("Invalid target format", "error")
        return redirect(url_for("views.schedules"))

    # Validate ports
    port_pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'
    if not re.match(port_pattern, ports):
        flash("Invalid port format", "error")
        return redirect(url_for("views.schedules"))

    # Validate method
    if method not in ("icmp", "arp", "syn", "all"):
        method = "icmp"

    next_run = get_next_run(cron_expr)
    if not next_run:
        flash("Invalid cron expression", "error")
        return redirect(url_for("views.schedules"))

    try:
        repo = ScheduleRepository(db)
        schedule = ScheduledScan(
            name=name,
            target_range=target,
            cron_expr=cron_expr,
            method=method,
            ports=ports,
            next_run=next_run,
        )
        repo.create(schedule)
        repo.bump_schedule_version()
        flash(f"Schedule '{name}' created", "success")
    except Exception as e:
        flash(f"Failed to create schedule: {e}", "error")

    return redirect(url_for("views.schedules"))


@views_bp.route("/schedules/<int:schedule_id>/toggle", methods=["POST"])
def schedule_toggle(schedule_id: int):
    """Toggle a scheduled scan."""
    db = get_db()

    from vulnscan.scheduler import ScheduleRepository

    repo = ScheduleRepository(db)
    if repo.toggle(schedule_id):
        repo.bump_schedule_version()
        flash("Schedule toggled", "success")
    else:
        flash("Schedule not found", "error")

    return redirect(url_for("views.schedules"))


@views_bp.route("/schedules/<int:schedule_id>/delete", methods=["POST"])
def schedule_delete(schedule_id: int):
    """Delete a scheduled scan."""
    db = get_db()

    from vulnscan.scheduler import ScheduleRepository

    repo = ScheduleRepository(db)
    if repo.delete(schedule_id):
        repo.bump_schedule_version()
        flash("Schedule deleted", "success")
    else:
        flash("Schedule not found", "error")

    return redirect(url_for("views.schedules"))
