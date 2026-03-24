from __future__ import annotations

import json
import ipaddress
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from shutil import copyfile

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models import HostAsset, RiskFinding, ServiceFingerprint


class HtmlReportGenerator:
    def __init__(self, template_dir: Path | None = None) -> None:
        if template_dir is None:
            template_dir = Path(__file__).resolve().parent / "templates"
        self.environment: Environment = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(default_for_string=True, default=True),
        )

    def generate(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        risks: list[RiskFinding],
        output_dir: Path,
        scan_name: str = "",
    ) -> str:
        output_dir.mkdir(parents=True, exist_ok=True)
        template = self.environment.get_template("report.html.j2")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_name = self._normalize_report_name(scan_name=scan_name, fallback=f"scan_{timestamp}")

        report_dir = output_dir / report_name
        assets_dir = report_dir / "assets"
        report_path = report_dir / "report.html"

        report_dir.mkdir(parents=True, exist_ok=True)
        assets_dir.mkdir(parents=True, exist_ok=True)
        src_chart_js = Path(__file__).resolve().parent / "assets" / "chart.umd.min.js"
        dst_chart_js = assets_dir / "chart.umd.min.js"
        _ = copyfile(src_chart_js, dst_chart_js)

        high_count = sum(1 for risk in risks if risk.risk_level == "HIGH")
        medium_count = sum(1 for risk in risks if risk.risk_level == "MEDIUM")
        low_count = sum(1 for risk in risks if risk.risk_level == "LOW")

        target_network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
        target_is_ipv4 = False
        target_prefix_gt_24 = False
        try:
            target_network = ipaddress.ip_network(target, strict=False)
            if isinstance(target_network, ipaddress.IPv4Network):
                target_is_ipv4 = True
                target_prefix_gt_24 = target_network.prefixlen > 24
        except ValueError:
            target_network = None
        PAPER_FRIENDLY_IPV4_GROUP_PREFIXLEN = 24

        def _asset_subnet_key(asset_ip: str) -> str:
            if not target_is_ipv4:
                return "UNKNOWN"
            if target_network is not None and target_prefix_gt_24:
                return str(target_network)
            try:
                ip_obj = ipaddress.ip_address(asset_ip)
                if isinstance(ip_obj, ipaddress.IPv4Address):
                    return str(ipaddress.ip_network(f"{ip_obj}/{PAPER_FRIENDLY_IPV4_GROUP_PREFIXLEN}", strict=False))
            except ValueError:
                pass
            return "UNKNOWN"

        subnet_counter: Counter[str] = Counter()
        for asset in assets or []:
            subnet_counter[_asset_subnet_key(asset.ip)] += 1
        subnet_groups = [{"subnet": subnet, "host_count": count} for subnet, count in subnet_counter.items()]
        subnet_groups.sort(key=lambda row: row["subnet"])
        DISCOVERY_PRIMARY_PRIORITY = ("icmp", "arp", "syn")

        def _primary_discovery_method(discovered_by: list[str] | None) -> str:
            methods_lower = {m.strip().lower() for m in (discovered_by or []) if m and m.strip()}
            for method in DISCOVERY_PRIMARY_PRIORITY:
                if method in methods_lower:
                    return method
            return "unknown"

        discovery_counter: Counter[str] = Counter()
        for asset in assets or []:
            discovery_counter[_primary_discovery_method(asset.discovered_by)] += 1
        discovery_labels = ["icmp", "arp", "syn", "unknown"]
        discovery_primary_counts = {k: int(discovery_counter.get(k, 0)) for k in discovery_labels}
        discovery_chart_payload = json.dumps(
            {"labels": discovery_labels, "data": [discovery_primary_counts[k] for k in discovery_labels]},
            ensure_ascii=False,
        )

        port_counter: Counter[int] = Counter()
        for asset in assets or []:
            for port in asset.open_ports or []:
                try:
                    port_int = int(port)
                except (TypeError, ValueError):
                    continue
                port_counter[port_int] += 1
        ports_top10 = [{"port": port, "count": count} for port, count in port_counter.items()]
        ports_top10.sort(key=lambda row: (-row["count"], row["port"]))
        ports_top10 = ports_top10[:10]
        ports_top10_chart_payload = json.dumps(
            {"labels": [str(row["port"]) for row in ports_top10], "data": [row["count"] for row in ports_top10]},
            ensure_ascii=False,
        )

        confidence_counter: Counter[str] = Counter()
        for risk in risks or []:
            tier = (getattr(risk, "risk_confidence_tier", "") or getattr(risk, "confidence_tier", "") or "MEDIUM")
            tier = tier.strip().upper()
            if tier not in {"HIGH", "MEDIUM", "LOW"}:
                tier = "MEDIUM"
            confidence_counter[tier] += 1
        confidence_labels = ["HIGH", "MEDIUM", "LOW"]
        confidence_counts = {k: int(confidence_counter.get(k, 0)) for k in confidence_labels}
        confidence_chart_payload = json.dumps(
            {"labels": confidence_labels, "data": [confidence_counts[k] for k in confidence_labels]},
            ensure_ascii=False,
        )

        top_risks = risks[:20]
        chart_payload = json.dumps(
            {
                "labels": ["HIGH", "MEDIUM", "LOW"],
                "data": [high_count, medium_count, low_count],
            },
            ensure_ascii=False,
        )

        html = template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target=target,
            methods=",".join(methods),
            ports=",".join(str(port) for port in ports),
            risk_formula="Risk = 0.45*CVSS + 0.20*AssetCriticality + 0.15*PortExposure + 0.10*ExploitMaturity + 0.10*MatchConfidence",
            total_hosts=len(assets),
            total_services=len(services),
            total_risks=len(risks),
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            assets=assets,
            services=services,
            top_risks=top_risks,
            chart_payload=chart_payload,
            subnet_groups=subnet_groups,
            discovery_primary_counts=discovery_primary_counts,
            ports_top10=ports_top10,
            confidence_counts=confidence_counts,
            ports_top10_chart_payload=ports_top10_chart_payload,
            confidence_chart_payload=confidence_chart_payload,
            discovery_chart_payload=discovery_chart_payload,
        )
        _ = report_path.write_text(html, encoding="utf-8")
        return str(report_path)

    def _normalize_report_name(self, scan_name: str, fallback: str) -> str:
        candidate = re.sub(r"[^0-9A-Za-z_.-]+", "_", scan_name.strip())
        candidate = candidate.strip("._-")
        return candidate if candidate else fallback
