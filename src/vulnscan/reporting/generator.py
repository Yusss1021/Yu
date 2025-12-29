"""
Report generator - Generate HTML vulnerability reports.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, PackageLoader, select_autoescape

from ..core.models import (
    Host,
    HostRiskResult,
    RiskLevel,
    Scan,
    ScanResult,
    Service,
    Vulnerability,
)
from ..core.scoring import calculate_scan_risk_summary
from .charts import ChartGenerator


# HTML Report Template
REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="{{ language }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.0/dist/echarts.min.js"></script>
    <style>
        body { background-color: #f8f9fa; }
        .report-header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 2rem; }
        .risk-critical { color: #dc3545; font-weight: bold; }
        .risk-high { color: #fd7e14; font-weight: bold; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #0d6efd; }
        .chart-container { height: 400px; width: 100%; }
        .severity-badge { padding: 0.25rem 0.5rem; border-radius: 0.25rem; color: white; }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; color: #212529; }
        .severity-low { background-color: #0d6efd; }
        .card-stat { border-left: 4px solid; }
        .card-stat-critical { border-left-color: #dc3545; }
        .card-stat-high { border-left-color: #fd7e14; }
        .card-stat-medium { border-left-color: #ffc107; }
        .card-stat-hosts { border-left-color: #0d6efd; }
        .vuln-item { border-left: 3px solid; padding-left: 1rem; margin-bottom: 1rem; }
        .vuln-critical { border-left-color: #dc3545; }
        .vuln-high { border-left-color: #fd7e14; }
        .vuln-medium { border-left-color: #ffc107; }
        .vuln-low { border-left-color: #0d6efd; }
        @media print {
            .no-print { display: none !important; }
            .chart-container { page-break-inside: avoid; }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="report-header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1>{{ i18n.report_title }}</h1>
                    <p class="mb-0">{{ i18n.target }}: {{ scan.target_range }}</p>
                    <p class="mb-0">{{ i18n.scan_time }}: {{ scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A' }}</p>
                </div>
                <div class="col-md-4 text-end">
                    <span class="display-4">{{ summary.average_score }}</span>
                    <p class="mb-0">{{ i18n.average_risk_score }}</p>
                </div>
            </div>
        </div>
    </div>

    <div class="container my-4">
        <!-- Executive Summary -->
        <div class="card mb-4">
            <div class="card-header">
                <h4 class="mb-0">{{ i18n.executive_summary }}</h4>
            </div>
            <div class="card-body">
                <div class="row">
                    <div class="col-md-3">
                        <div class="card card-stat card-stat-hosts">
                            <div class="card-body text-center">
                                <h2>{{ summary.total_hosts }}</h2>
                                <p class="mb-0">{{ i18n.hosts_scanned }}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card card-stat card-stat-critical">
                            <div class="card-body text-center">
                                <h2 class="risk-critical">{{ summary.critical_hosts }}</h2>
                                <p class="mb-0">{{ i18n.critical_hosts }}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card card-stat card-stat-high">
                            <div class="card-body text-center">
                                <h2 class="risk-high">{{ summary.high_hosts }}</h2>
                                <p class="mb-0">{{ i18n.high_risk_hosts }}</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card card-stat card-stat-medium">
                            <div class="card-body text-center">
                                <h2>{{ summary.total_vulnerabilities }}</h2>
                                <p class="mb-0">{{ i18n.vulnerabilities_found }}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        {% if severity_chart_image %}
                        <img src="data:image/png;base64,{{ severity_chart_image }}" style="width:100%;height:auto;" alt="Severity Distribution">
                        {% else %}
                        <div id="severity-chart" class="chart-container"></div>
                        {% endif %}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        {% if risk_chart_image %}
                        <img src="data:image/png;base64,{{ risk_chart_image }}" style="width:100%;height:auto;" alt="Risk Scores">
                        {% else %}
                        <div id="risk-chart" class="chart-container"></div>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>

        <!-- Host Inventory -->
        <div class="card mb-4">
            <div class="card-header">
                <h4 class="mb-0">{{ i18n.host_inventory }}</h4>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead class="table-dark">
                            <tr>
                                <th>{{ i18n.ip_address }}</th>
                                <th>{{ i18n.hostname }}</th>
                                <th>{{ i18n.os }}</th>
                                <th>{{ i18n.open_ports }}</th>
                                <th>{{ i18n.risk_score }}</th>
                                <th>{{ i18n.risk_level }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for host in hosts %}
                            {% set risk = risk_results.get(host.id) %}
                            <tr>
                                <td>{{ host.ip }}</td>
                                <td>{{ host.hostname or '-' }}</td>
                                <td>{{ host.os_guess or '-' }}</td>
                                <td>{{ host_services.get(host.ip, [])|length }}</td>
                                <td>{{ risk.risk_score if risk else 0 }}</td>
                                <td>
                                    {% if risk %}
                                    <span class="badge severity-{{ risk.risk_level.value|lower }}">
                                        {{ risk.risk_level.value }}
                                    </span>
                                    {% else %}
                                    <span class="badge bg-secondary">N/A</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Vulnerability Details -->
        <div class="card mb-4">
            <div class="card-header">
                <h4 class="mb-0">{{ i18n.vulnerability_details }}</h4>
            </div>
            <div class="card-body">
                <div class="accordion" id="vulnAccordion">
                    {% for vuln in vulnerabilities[:50] %}
                    <div class="accordion-item">
                        <h2 class="accordion-header" id="heading{{ loop.index }}">
                            <button class="accordion-button collapsed" type="button"
                                    data-bs-toggle="collapse" data-bs-target="#collapse{{ loop.index }}">
                                <span class="severity-badge severity-{{ vuln.severity.value|lower }} me-2">
                                    {{ vuln.severity.value }}
                                </span>
                                {{ vuln.cve_id }}
                            </button>
                        </h2>
                        <div id="collapse{{ loop.index }}" class="accordion-collapse collapse"
                             data-bs-parent="#vulnAccordion">
                            <div class="accordion-body">
                                <p><strong>CVSS Score:</strong> {{ vuln.cvss_base }}</p>
                                <p><strong>{{ i18n.description }}:</strong> {{ vuln.description or 'N/A' }}</p>
                                {% if vuln.affected_cpe %}
                                <p><strong>{{ i18n.affected_products }}:</strong> {{ vuln.affected_cpe }}</p>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <!-- Remediation Recommendations -->
        {% if recommendations %}
        <div class="card mb-4">
            <div class="card-header bg-success text-white">
                <h4 class="mb-0">{{ i18n.remediation_title }}</h4>
            </div>
            <div class="card-body">
                <p class="text-muted mb-4">{{ i18n.remediation_intro }}</p>

                {% for priority in ['critical', 'high', 'medium', 'low'] %}
                {% set recs = recommendations.by_priority.get(priority, []) %}
                {% if recs %}
                <h5 class="mt-3">
                    <span class="badge {% if priority == 'critical' %}bg-danger{% elif priority == 'high' %}bg-warning{% elif priority == 'medium' %}bg-info{% else %}bg-secondary{% endif %}">
                        {{ priority|upper }}
                    </span>
                    {{ i18n.priority_label }}
                </h5>
                {% for rec in recs %}
                <div class="card mb-2 border-start border-4 {% if priority == 'critical' %}border-danger{% elif priority == 'high' %}border-warning{% elif priority == 'medium' %}border-info{% else %}border-secondary{% endif %}">
                    <div class="card-body py-2">
                        <h6 class="mb-1">{{ rec.title }}</h6>
                        <p class="text-muted small mb-1">{{ rec.description }}</p>
                        <p class="mb-0"><strong>{{ i18n.action_label }}:</strong> {{ rec.action }}</p>
                        {% if rec.reference %}
                        <a href="{{ rec.reference }}" target="_blank" class="small">{{ i18n.reference_link }}</a>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
                {% endif %}
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <!-- Footer -->
        <div class="text-center text-muted py-4">
            <p>{{ i18n.generated_by }} VulnScanner &copy; {{ current_year }}</p>
            <p class="no-print">
                <button class="btn btn-primary" onclick="window.print()">{{ i18n.print_report }}</button>
            </p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Severity Pie Chart
        var severityChart = echarts.init(document.getElementById('severity-chart'));
        severityChart.setOption({{ severity_chart_json|safe }});

        // Risk Bar Chart
        var riskChart = echarts.init(document.getElementById('risk-chart'));
        riskChart.setOption({{ risk_chart_json|safe }});

        // Responsive charts
        window.addEventListener('resize', function() {
            severityChart.resize();
            riskChart.resize();
        });
    </script>
</body>
</html>
"""

# Internationalization strings
I18N = {
    "zh_CN": {
        "report_title": "网络脆弱性扫描报告",
        "target": "扫描目标",
        "scan_time": "扫描时间",
        "average_risk_score": "平均风险评分",
        "executive_summary": "执行摘要",
        "hosts_scanned": "扫描主机数",
        "critical_hosts": "严重风险主机",
        "high_risk_hosts": "高风险主机",
        "vulnerabilities_found": "发现漏洞数",
        "host_inventory": "主机清单",
        "ip_address": "IP地址",
        "hostname": "主机名",
        "os": "操作系统",
        "open_ports": "开放端口",
        "risk_score": "风险评分",
        "risk_level": "风险等级",
        "vulnerability_details": "漏洞详情",
        "description": "描述",
        "affected_products": "受影响产品",
        "generated_by": "报告生成工具",
        "print_report": "打印报告",
        "remediation_title": "修复建议",
        "remediation_intro": "以下是针对发现的安全问题的修复建议，按优先级排序。",
        "priority_label": "优先级",
        "action_label": "建议操作",
        "reference_link": "参考链接",
    },
    "en_US": {
        "report_title": "Network Vulnerability Scan Report",
        "target": "Target",
        "scan_time": "Scan Time",
        "average_risk_score": "Average Risk Score",
        "executive_summary": "Executive Summary",
        "hosts_scanned": "Hosts Scanned",
        "critical_hosts": "Critical Hosts",
        "high_risk_hosts": "High Risk Hosts",
        "vulnerabilities_found": "Vulnerabilities Found",
        "host_inventory": "Host Inventory",
        "ip_address": "IP Address",
        "hostname": "Hostname",
        "os": "Operating System",
        "open_ports": "Open Ports",
        "risk_score": "Risk Score",
        "risk_level": "Risk Level",
        "vulnerability_details": "Vulnerability Details",
        "description": "Description",
        "affected_products": "Affected Products",
        "generated_by": "Generated by",
        "print_report": "Print Report",
        "remediation_title": "Remediation Recommendations",
        "remediation_intro": "The following are remediation recommendations for the security issues found, sorted by priority.",
        "priority_label": "Priority",
        "action_label": "Recommended Action",
        "reference_link": "Reference",
    },
}


class ReportGenerator:
    """
    Generate HTML vulnerability reports.
    """

    def __init__(self, language: str = "zh_CN"):
        """
        Initialize report generator.

        Args:
            language: Report language (zh_CN or en_US)
        """
        self.language = language
        self.i18n = I18N.get(language, I18N["en_US"])
        self.charts = ChartGenerator()

    def generate(
        self,
        scan: Scan,
        hosts: List[Host],
        services: List[Service],
        vulnerabilities: List[Vulnerability],
        risk_results: List[HostRiskResult],
        output_path: Optional[Path] = None,
        severity_chart_image: Optional[str] = None,
        risk_chart_image: Optional[str] = None,
    ) -> str:
        """
        Generate HTML report.

        Args:
            scan: Scan object
            hosts: List of discovered hosts
            services: List of discovered services
            vulnerabilities: List of matched vulnerabilities
            risk_results: List of risk assessment results
            output_path: Optional path to save report

        Returns:
            HTML report string
        """
        from jinja2 import Template

        # Calculate summary
        summary = calculate_scan_risk_summary(risk_results)

        # Build host services mapping
        host_services = {}
        for svc in services:
            if svc.host_ip not in host_services:
                host_services[svc.host_ip] = []
            host_services[svc.host_ip].append(svc)

        # Build risk results mapping
        risk_map = {r.host_id: r for r in risk_results}

        # Generate chart configs
        total_critical = sum(r.critical_count for r in risk_results)
        total_high = sum(r.high_count for r in risk_results)
        total_medium = sum(r.medium_count for r in risk_results)
        total_low = sum(r.low_count for r in risk_results)

        severity_chart = self.charts.severity_pie_chart(
            total_critical, total_high, total_medium, total_low,
            title=self.i18n.get("vulnerability_details", "Severity Distribution"),
        )

        # Top 10 hosts by risk score
        top_hosts = sorted(risk_results, key=lambda r: r.risk_score, reverse=True)[:10]
        host_ips = []
        host_scores = []
        for r in top_hosts:
            host = next((h for h in hosts if h.id == r.host_id), None)
            if host:
                host_ips.append(host.ip)
                host_scores.append(r.risk_score)

        risk_chart = self.charts.risk_bar_chart(
            host_ips, host_scores,
            title=self.i18n.get("risk_score", "Host Risk Scores"),
        )

        # Generate remediation recommendations
        recommendations = None
        try:
            from ..remediation.engine import get_recommendations_summary
            recommendations = get_recommendations_summary(services, vulnerabilities)
        except Exception:
            pass  # Remediation module not available

        # Render template
        template = Template(REPORT_TEMPLATE)
        html = template.render(
            title=f"{self.i18n['report_title']} - {scan.target_range}",
            language=self.language[:2],
            i18n=self.i18n,
            scan=scan,
            hosts=hosts,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_results=risk_map,
            host_services=host_services,
            summary=summary,
            recommendations=recommendations,
            severity_chart_json=json.dumps(severity_chart, ensure_ascii=False),
            risk_chart_json=json.dumps(risk_chart, ensure_ascii=False),
            severity_chart_image=severity_chart_image,
            risk_chart_image=risk_chart_image,
            current_year=datetime.now().year,
        )

        # Save to file if path provided
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html, encoding="utf-8")

        return html

    def generate_json(
        self,
        scan: Scan,
        hosts: List[Host],
        services: List[Service],
        vulnerabilities: List[Vulnerability],
        risk_results: List[HostRiskResult],
    ) -> Dict[str, Any]:
        """
        Generate JSON report data.

        Args:
            scan: Scan object
            hosts: List of discovered hosts
            services: List of discovered services
            vulnerabilities: List of matched vulnerabilities
            risk_results: List of risk assessment results

        Returns:
            Report data dictionary
        """
        summary = calculate_scan_risk_summary(risk_results)

        return {
            "scan": {
                "id": scan.id,
                "target_range": scan.target_range,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
                "status": scan.status.value,
            },
            "summary": summary,
            "hosts": [
                {
                    "id": h.id,
                    "ip": h.ip,
                    "hostname": h.hostname,
                    "os_guess": h.os_guess,
                    "mac": h.mac,
                }
                for h in hosts
            ],
            "services": [
                {
                    "id": s.id,
                    "host_ip": s.host_ip,
                    "port": s.port,
                    "proto": s.proto,
                    "service_name": s.service_name,
                    "product": s.product,
                    "version": s.version,
                    "cpe": s.cpe,
                }
                for s in services
            ],
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "cvss_base": v.cvss_base,
                    "severity": v.severity.value if v.severity else None,
                    "description": v.description,
                }
                for v in vulnerabilities
            ],
            "risk_results": [
                {
                    "host_id": r.host_id,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level.value,
                    "vuln_count": r.vuln_count,
                    "critical_count": r.critical_count,
                    "high_count": r.high_count,
                    "medium_count": r.medium_count,
                    "low_count": r.low_count,
                }
                for r in risk_results
            ],
        }

    def generate_pdf(
        self,
        scan: Scan,
        hosts: List[Host],
        services: List[Service],
        vulnerabilities: List[Vulnerability],
        risk_results: List[HostRiskResult],
        output_path: Path,
    ) -> bytes:
        """
        Generate PDF report.

        Args:
            scan: Scan object
            hosts: List of discovered hosts
            services: List of discovered services
            vulnerabilities: List of matched vulnerabilities
            risk_results: List of risk assessment results
            output_path: Path to save PDF file

        Returns:
            PDF bytes
        """
        try:
            from weasyprint import HTML, CSS
            from weasyprint.text.fonts import FontConfiguration
        except ImportError:
            raise ImportError("weasyprint is required for PDF generation. Install with: pip install weasyprint")

        # Generate static charts for PDF
        total_critical = sum(r.critical_count for r in risk_results)
        total_high = sum(r.high_count for r in risk_results)
        total_medium = sum(r.medium_count for r in risk_results)
        total_low = sum(r.low_count for r in risk_results)

        severity_chart_image = self.charts.severity_pie_chart_image(
            total_critical, total_high, total_medium, total_low,
            title=self.i18n.get("vulnerability_details", "Severity Distribution"),
        )

        top_hosts = sorted(risk_results, key=lambda r: r.risk_score, reverse=True)[:10]
        host_ips = []
        host_scores = []
        for r in top_hosts:
            host = next((h for h in hosts if h.id == r.host_id), None)
            if host:
                host_ips.append(host.ip)
                host_scores.append(r.risk_score)

        risk_chart_image = self.charts.risk_bar_chart_image(
            host_ips, host_scores,
            title=self.i18n.get("risk_score", "Host Risk Scores"),
        )

        html = self.generate(
            scan=scan,
            hosts=hosts,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_results=risk_results,
            severity_chart_image=severity_chart_image,
            risk_chart_image=risk_chart_image,
        )

        font_config = FontConfiguration()
        pdf_css = CSS(string="""
            @font-face {
                font-family: "Report CJK";
                font-style: normal;
                font-weight: 400;
                src: local("Noto Sans CJK SC"), local("Noto Sans CJK TC"),
                     local("Source Han Sans SC"), local("Microsoft YaHei"),
                     local("PingFang SC"), local("WenQuanYi Micro Hei"),
                     local("SimSun"), local("Noto Sans"), local("Arial");
            }
            @font-face {
                font-family: "Report CJK";
                font-style: normal;
                font-weight: 700;
                src: local("Noto Sans CJK SC Bold"), local("Source Han Sans SC Bold"),
                     local("Microsoft YaHei Bold"), local("SimHei"),
                     local("WenQuanYi Zen Hei"), local("Noto Sans Bold"), local("Arial Bold");
            }
            @page {
                size: A4;
                margin: 2cm 1.5cm;
                @bottom-center {
                    content: "— " counter(page) " / " counter(pages) " —";
                    font-size: 9pt;
                    color: #666;
                }
            }
            html, body {
                font-family: "Report CJK", "Noto Sans CJK SC", "Microsoft YaHei",
                             "WenQuanYi Micro Hei", "SimSun", sans-serif;
                font-size: 10pt;
                line-height: 1.5;
                color: #1a1a2e;
                background: white !important;
            }
            h1, h2, h3, h4, h5, h6 {
                font-family: "Report CJK", "Noto Sans CJK SC", "Microsoft YaHei", sans-serif;
                color: #1a1a2e;
                margin-top: 1em;
                margin-bottom: 0.5em;
                font-weight: 700;
            }
            h1 { font-size: 20pt; }
            h2 { font-size: 16pt; }
            h3 { font-size: 14pt; }
            h4 { font-size: 12pt; }
            p { margin: 0.5em 0; }

            .container { width: 100%; }
            .row { display: flex; flex-wrap: wrap; margin: 0 -0.5rem; }
            .col-md-3 { width: 25%; padding: 0 0.5rem; box-sizing: border-box; }
            .col-md-4 { width: 33.33%; padding: 0 0.5rem; box-sizing: border-box; }
            .col-md-6 { width: 50%; padding: 0 0.5rem; box-sizing: border-box; }
            .col-md-8 { width: 66.67%; padding: 0 0.5rem; box-sizing: border-box; }
            .text-center { text-align: center; }
            .text-end { text-align: right; }
            .text-muted { color: #666; }
            .mb-0 { margin-bottom: 0; }
            .mb-4 { margin-bottom: 1rem; }
            .me-2 { margin-right: 0.5rem; }

            .report-header {
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: white;
                padding: 1.5rem;
                border-radius: 8px;
                margin-bottom: 1.5rem;
            }
            .report-header h1 { color: white; margin: 0 0 0.5rem 0; font-size: 18pt; }
            .report-header p { margin: 0.25rem 0; color: rgba(255,255,255,0.9); }
            .display-4 { font-size: 32pt; font-weight: 700; }

            .card {
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-bottom: 1rem;
                background: white;
                break-inside: avoid;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .card-header {
                background: #f8f9fa;
                border-bottom: 1px solid #e0e0e0;
                padding: 0.75rem 1rem;
                font-weight: 600;
            }
            .card-header h4, .card-header h5 { margin: 0; font-size: 12pt; }
            .card-body { padding: 1rem; }

            .card-stat { border-left: 4px solid; }
            .card-stat-critical { border-left-color: #dc3545; }
            .card-stat-high { border-left-color: #fd7e14; }
            .card-stat-medium { border-left-color: #ffc107; }
            .card-stat-hosts { border-left-color: #0d6efd; }

            .table { width: 100%; border-collapse: collapse; font-size: 9pt; }
            .table th, .table td {
                border: 1px solid #dee2e6;
                padding: 0.5rem;
                text-align: left;
                vertical-align: top;
            }
            .table thead th, .table-dark th {
                background: #1a1a2e;
                color: white;
                font-weight: 600;
            }
            .table tbody tr:nth-child(even) { background: #f8f9fa; }
            .table-hover tbody tr { break-inside: avoid; }

            .badge, .severity-badge {
                display: inline-block;
                padding: 0.2rem 0.5rem;
                font-size: 8pt;
                font-weight: 600;
                border-radius: 4px;
            }
            .severity-critical, .bg-danger { background: #dc3545; color: white; }
            .severity-high, .bg-warning { background: #fd7e14; color: white; }
            .severity-medium, .bg-info { background: #ffc107; color: #212529; }
            .severity-low, .bg-primary { background: #0d6efd; color: white; }
            .bg-success { background: #198754; color: white; }
            .bg-secondary { background: #6c757d; color: white; }

            .risk-critical { color: #dc3545; font-weight: 700; }
            .risk-high { color: #fd7e14; font-weight: 700; }
            .risk-medium { color: #ffc107; }
            .risk-low { color: #0d6efd; }

            .accordion-item {
                border: 1px solid #dee2e6;
                border-radius: 6px;
                margin-bottom: 0.5rem;
                break-inside: avoid;
            }
            .accordion-header { margin: 0; }
            .accordion-button {
                display: flex;
                align-items: center;
                width: 100%;
                padding: 0.75rem 1rem;
                font-weight: 600;
                background: #f8f9fa;
                border: none;
                text-align: left;
            }
            .accordion-collapse { display: block !important; }
            .accordion-body {
                padding: 1rem;
                border-top: 1px solid #dee2e6;
                font-size: 9pt;
            }

            .border-start { border-left: 4px solid; padding-left: 1rem; }
            .border-danger { border-left-color: #dc3545; }
            .border-warning { border-left-color: #fd7e14; }
            .border-info { border-left-color: #0d6efd; }
            .border-secondary { border-left-color: #6c757d; }

            .chart-container { display: none; }
            .no-print { display: none !important; }

            a { color: #0d6efd; text-decoration: none; }
            code {
                background: #f1f3f5;
                padding: 0.1rem 0.3rem;
                border-radius: 3px;
                font-family: monospace;
                font-size: 9pt;
            }
        """, font_config=font_config)

        pdf_bytes = HTML(string=html).write_pdf(stylesheets=[pdf_css], font_config=font_config)

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(pdf_bytes)

        return pdf_bytes
