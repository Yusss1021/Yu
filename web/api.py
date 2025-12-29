"""
REST API endpoints.
"""

import threading
from datetime import datetime
from pathlib import Path

from flask import Blueprint, jsonify, request, current_app

from vulnscan.config import get_config
from vulnscan.core.pipeline import ScanPipelineRunner
from vulnscan.storage.database import Database
from vulnscan.storage.repository import (
    HostRepository,
    RiskResultRepository,
    ScanRepository,
    ServiceRepository,
)

api_bp = Blueprint("api", __name__)

# Store running scans
_running_scans = {}


def get_db():
    db_path = current_app.config.get("DATABASE_PATH")
    return Database(Path(db_path) if db_path else None)


@api_bp.route("/trends", methods=["GET"])
def get_trends():
    """Get security posture trend data."""
    db = get_db()
    days = request.args.get("days", 30, type=int)
    days = min(max(days, 7), 365)  # Clamp to 7-365 days

    from vulnscan.core.trend import generate_trend_response
    return jsonify(generate_trend_response(db, days))


@api_bp.route("/scans", methods=["GET"])
def list_scans():
    """List all scans."""
    db = get_db()
    scan_repo = ScanRepository(db)
    scans = scan_repo.get_all(limit=100)

    return jsonify({
        "scans": [
            {
                "id": s.id,
                "target_range": s.target_range,
                "status": s.status.value,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "finished_at": s.finished_at.isoformat() if s.finished_at else None,
            }
            for s in scans
        ]
    })


@api_bp.route("/scans", methods=["POST"])
def start_scan():
    """Start a new scan."""
    data = request.get_json() or {}
    target = data.get("target") or request.args.get("target")
    method = data.get("method", "icmp") or request.args.get("method", "icmp")
    ports = data.get("ports", "1-1024") or request.args.get("ports", "1-1024")

    if not target:
        return jsonify({"error": "Target is required"}), 400

    db = get_db()
    config = get_config()
    lang = current_app.config.get("LANGUAGE", "zh_CN")

    # Progress tracking
    scan_progress = {"stage": "starting", "percent": 0}

    def progress_callback(stage: str, percent: int):
        scan_progress["stage"] = stage
        scan_progress["percent"] = percent

    # Run scan in background thread
    def run_scan():
        try:
            runner = ScanPipelineRunner(db=db, progress_callback=progress_callback)
            result = runner.run(
                target_range=target,
                discovery_method=method,
                port_range=ports,
                language=lang,
            )
            _running_scans[result.scan.id] = {
                "status": "completed",
                "result": result,
            }
        except Exception as e:
            _running_scans.get(target, {})["status"] = "failed"
            _running_scans.get(target, {})["error"] = str(e)

    thread = threading.Thread(target=run_scan)
    thread.start()

    # Return immediately with scan ID placeholder
    return jsonify({
        "message": "Scan started",
        "target": target,
        "method": method,
    }), 202


@api_bp.route("/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    """Get scan details."""
    db = get_db()
    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    service_repo = ServiceRepository(db)
    risk_repo = RiskResultRepository(db)

    scan = scan_repo.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    hosts = host_repo.get_by_scan(scan_id)
    risk_results = risk_repo.get_by_scan(scan_id)
    risk_map = {r.host_id: r for r in risk_results}

    host_data = []
    for host in hosts:
        services = service_repo.get_by_host(host.id)
        risk = risk_map.get(host.id)

        host_data.append({
            "id": host.id,
            "ip": host.ip,
            "hostname": host.hostname,
            "os_guess": host.os_guess,
            "mac": host.mac,
            "services": [
                {
                    "port": s.port,
                    "proto": s.proto,
                    "service_name": s.service_name,
                    "product": s.product,
                    "version": s.version,
                }
                for s in services
            ],
            "risk_score": risk.risk_score if risk else 0,
            "risk_level": risk.risk_level.value if risk else "Info",
            "vuln_count": risk.vuln_count if risk else 0,
        })

    return jsonify({
        "scan": {
            "id": scan.id,
            "target_range": scan.target_range,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        },
        "hosts": host_data,
        "summary": {
            "total_hosts": len(hosts),
            "total_vulns": sum(h.get("vuln_count", 0) for h in host_data),
            "critical_hosts": sum(1 for r in risk_results if r.risk_level.value == "Critical"),
            "high_hosts": sum(1 for r in risk_results if r.risk_level.value == "High"),
        },
    })


@api_bp.route("/scans/<int:scan_id>/status", methods=["GET"])
def get_scan_status(scan_id: int):
    """Get scan status (for polling)."""
    db = get_db()
    scan_repo = ScanRepository(db)

    scan = scan_repo.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "id": scan.id,
        "status": scan.status.value,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
    })


@api_bp.route("/scans/<int:scan_id>/topology", methods=["GET"])
def get_topology(scan_id: int):
    """Get network topology data for visualization."""
    db = get_db()
    from vulnscan.reporting.topology import generate_topology_for_api

    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    service_repo = ServiceRepository(db)
    risk_repo = RiskResultRepository(db)

    scan = scan_repo.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    hosts = host_repo.get_by_scan(scan_id)
    services = service_repo.get_by_scan(scan_id)

    risk_results = risk_repo.get_by_scan(scan_id)

    topology_data = generate_topology_for_api(hosts, services, risk_results)
    return jsonify(topology_data)


@api_bp.route("/scans/<int:scan_id>/remediation", methods=["GET"])
def get_remediation(scan_id: int):
    """Get remediation recommendations for a scan."""
    try:
        db = get_db()
        from vulnscan.storage.repository import VulnerabilityRepository
        from vulnscan.remediation.engine import get_recommendations_summary

        scan_repo = ScanRepository(db)
        service_repo = ServiceRepository(db)
        vuln_repo = VulnerabilityRepository(db)

        scan = scan_repo.get(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404

        services = service_repo.get_by_scan(scan_id)
        vulnerabilities = vuln_repo.get_by_scan(scan_id)

        summary = get_recommendations_summary(services, vulnerabilities)
        return jsonify(summary)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api_bp.route("/scans/<int:scan_id>/report", methods=["GET"])
def generate_report(scan_id: int):
    """Generate and download report."""
    db = get_db()
    config = get_config()
    lang = current_app.config.get("LANGUAGE", "zh_CN")
    fmt = request.args.get("format", "html")

    from vulnscan.storage.repository import VulnerabilityRepository
    from vulnscan.reporting.generator import ReportGenerator

    scan_repo = ScanRepository(db)
    host_repo = HostRepository(db)
    service_repo = ServiceRepository(db)
    vuln_repo = VulnerabilityRepository(db)
    risk_repo = RiskResultRepository(db)

    scan = scan_repo.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    hosts = host_repo.get_by_scan(scan_id)
    services = []
    for host in hosts:
        services.extend(service_repo.get_by_host(host.id))

    risk_results = risk_repo.get_by_scan(scan_id)

    # Get vulnerabilities
    vuln_ids = set()
    vulnerabilities = []
    for svc in services:
        svc_vulns = vuln_repo.get_by_service(svc.id)
        for vuln in svc_vulns:
            if vuln.id not in vuln_ids:
                vuln_ids.add(vuln.id)
                vulnerabilities.append(vuln)

    generator = ReportGenerator(language=lang)

    from flask import Response
    import tempfile

    if fmt == "pdf":
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            pdf_bytes = generator.generate_pdf(
                scan=scan,
                hosts=hosts,
                services=services,
                vulnerabilities=vulnerabilities,
                risk_results=risk_results,
                output_path=Path(tmp.name),
            )
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.pdf"}
        )
    elif fmt == "json":
        data = generator.generate_json(
            scan=scan,
            hosts=hosts,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_results=risk_results,
        )
        return jsonify(data)
    else:
        html = generator.generate(
            scan=scan,
            hosts=hosts,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_results=risk_results,
        )
        return Response(
            html,
            mimetype="text/html",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}_report.html"}
        )
