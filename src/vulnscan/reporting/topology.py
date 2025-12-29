"""
Network topology data generator for ECharts visualization.
"""

from typing import Any, Dict, List, Optional
from ..core.models import Host, Service, HostRiskResult, RiskLevel


RISK_COLORS = {
    RiskLevel.CRITICAL: "#FF6B6B",
    RiskLevel.HIGH: "#FFA94D",
    RiskLevel.MEDIUM: "#FFD93D",
    RiskLevel.LOW: "#69DB7C",
    RiskLevel.INFO: "#58A6FF",
}

CATEGORY_INDEX = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 3,
    RiskLevel.INFO: 4,
}


def get_subnet(ip: str) -> str:
    """Extract /24 subnet from IP address."""
    if "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "unknown"


def generate_topology_data(
    hosts: List[Host],
    services: List[Service],
    risk_results: List[HostRiskResult],
) -> Dict[str, Any]:
    """
    Generate ECharts Graph format data from scan results.

    Returns:
        Dictionary with nodes, links, and categories for ECharts graph.
    """
    if not hosts:
        return {"nodes": [], "links": [], "categories": []}

    risk_map = {r.host_id: r for r in risk_results}
    service_count = {}
    for svc in services:
        service_count[svc.host_id] = service_count.get(svc.host_id, 0) + 1

    categories = [
        {"name": "Critical", "itemStyle": {"color": RISK_COLORS[RiskLevel.CRITICAL]}},
        {"name": "High", "itemStyle": {"color": RISK_COLORS[RiskLevel.HIGH]}},
        {"name": "Medium", "itemStyle": {"color": RISK_COLORS[RiskLevel.MEDIUM]}},
        {"name": "Low", "itemStyle": {"color": RISK_COLORS[RiskLevel.LOW]}},
        {"name": "Info", "itemStyle": {"color": RISK_COLORS[RiskLevel.INFO]}},
    ]

    nodes = []
    links = []
    subnet_groups = {}

    for host in hosts:
        risk = risk_map.get(host.id)
        risk_level = risk.risk_level if risk else RiskLevel.INFO
        risk_score = risk.risk_score if risk else 0.0
        vuln_count = risk.vuln_count if risk else 0
        svc_count = service_count.get(host.id, 0)

        # Node size: base 25 + 3 per service, max 60
        symbol_size = min(60, max(25, 25 + svc_count * 3))

        subnet = get_subnet(host.ip)
        if subnet not in subnet_groups:
            subnet_groups[subnet] = []
        subnet_groups[subnet].append(host.ip)

        nodes.append({
            "id": host.ip,
            "name": host.ip,
            "symbolSize": symbol_size,
            "value": risk_score,
            "category": CATEGORY_INDEX.get(risk_level, 4),
            "itemStyle": {"color": RISK_COLORS.get(risk_level, RISK_COLORS[RiskLevel.INFO])},
            "label": {"show": True},
            "details": {
                "ip": host.ip,
                "hostname": host.hostname or "Unknown",
                "os": host.os_guess or "Unknown OS",
                "mac": host.mac,
                "risk_score": risk_score,
                "risk_level": risk_level.value if risk_level else "Info",
                "vuln_count": vuln_count,
                "service_count": svc_count,
            },
        })

    # Create links between hosts in the same subnet
    for subnet, ips in subnet_groups.items():
        if len(ips) > 1:
            # Connect all hosts in subnet to first host (star topology within subnet)
            hub = ips[0]
            for ip in ips[1:]:
                links.append({
                    "source": hub,
                    "target": ip,
                    "lineStyle": {"color": "#30363D", "width": 1, "curveness": 0.1},
                })

    # If multiple subnets exist, connect subnet hubs
    subnet_hubs = [ips[0] for ips in subnet_groups.values() if ips]
    if len(subnet_hubs) > 1:
        for i in range(len(subnet_hubs) - 1):
            links.append({
                "source": subnet_hubs[i],
                "target": subnet_hubs[i + 1],
                "lineStyle": {"color": "#58A6FF", "width": 2, "type": "dashed"},
            })

    return {
        "nodes": nodes,
        "links": links,
        "categories": categories,
    }


def generate_topology_for_api(
    hosts: List[Host],
    services: List[Service],
    risk_results: List[HostRiskResult],
) -> Dict[str, Any]:
    """
    Generate complete ECharts option for API response.
    """
    data = generate_topology_data(hosts, services, risk_results)

    return {
        "backgroundColor": "#161B22",
        "tooltip": {
            "trigger": "item",
            "backgroundColor": "rgba(22, 27, 34, 0.95)",
            "borderColor": "#30363D",
            "textStyle": {"color": "#C9D1D9"},
        },
        "legend": {
            "data": [c["name"] for c in data["categories"]],
            "orient": "vertical",
            "left": 10,
            "top": 20,
            "textStyle": {"color": "#C9D1D9"},
        },
        "series": [{
            "type": "graph",
            "layout": "force",
            "data": data["nodes"],
            "links": data["links"],
            "categories": data["categories"],
            "roam": True,
            "draggable": True,
            "label": {
                "show": True,
                "position": "right",
                "color": "#C9D1D9",
                "fontSize": 10,
            },
            "lineStyle": {
                "color": "source",
                "curveness": 0.1,
            },
            "force": {
                "repulsion": 300,
                "edgeLength": [80, 150],
                "layoutAnimation": False,
            },
            "emphasis": {
                "focus": "adjacency",
                "lineStyle": {"width": 3},
            },
        }],
    }
