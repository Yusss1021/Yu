"""
Remediation recommendation engine.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .knowledge_base import HARDENING_GUIDES, CVE_REMEDIATION

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class Recommendation:
    """A remediation recommendation."""
    title: str
    description: str
    action: str
    priority: str = "medium"  # critical, high, medium, low
    source: str = "knowledge_base"  # knowledge_base, nvd, cve_specific
    reference: Optional[str] = None


class RemediationEngine:
    """Engine for generating remediation recommendations."""

    SERVICE_MAP = {
        "ssh": ["ssh", "openssh", "sshd"],
        "http": ["http", "https", "apache", "nginx", "httpd", "tomcat", "iis"],
        "mysql": ["mysql", "mariadb", "mysqld"],
        "redis": ["redis", "redis-server"],
        "ftp": ["ftp", "vsftpd", "proftpd", "pure-ftpd"],
        "smb": ["smb", "samba", "cifs", "microsoft-ds", "netbios"],
    }

    def __init__(self):
        self.guides = HARDENING_GUIDES
        self.cve_remediation = CVE_REMEDIATION

    def get_service_type(self, service_name: str, product: str = None) -> str:
        """Map service/product name to known service type."""
        check = (service_name or "").lower()
        if product:
            check += " " + product.lower()

        for svc_type, keywords in self.SERVICE_MAP.items():
            for kw in keywords:
                if kw in check:
                    return svc_type

        return "default"

    def get_recommendations_for_service(
        self,
        service_name: str,
        product: str = None,
        version: str = None,
    ) -> List[Recommendation]:
        """Get hardening recommendations for a service."""
        svc_type = self.get_service_type(service_name, product)
        guide = self.guides.get(svc_type, self.guides["default"])

        recommendations = []
        for rec in guide["recommendations"]:
            recommendations.append(Recommendation(
                title=rec["title"],
                description=rec["description"],
                action=rec["action"],
                priority=rec["priority"],
                source="knowledge_base",
            ))

        return recommendations

    def get_recommendations_for_vuln(
        self,
        cve_id: str,
        description: str = None,
    ) -> List[Recommendation]:
        """Get specific remediation for a CVE."""
        recommendations = []

        if not cve_id or not cve_id.strip():
            return recommendations

        cve_id = cve_id.strip().upper()
        if not CVE_ID_RE.match(cve_id):
            return recommendations

        # Check for known CVE-specific remediation
        if cve_id in self.cve_remediation:
            cve_info = self.cve_remediation[cve_id]
            recommendations.append(Recommendation(
                title=f"修复 {cve_id}: {cve_info['title']}",
                description=cve_info.get("title", ""),
                action=cve_info["action"],
                priority="critical",
                source="cve_specific",
                reference=cve_info.get("reference"),
            ))
        else:
            # Generic remediation based on CVE
            recommendations.append(Recommendation(
                title=f"修复 {cve_id}",
                description="应用厂商发布的安全补丁",
                action="访问 NVD (nvd.nist.gov) 查看详细修复信息和厂商公告",
                priority="high",
                source="nvd",
                reference=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            ))

        return recommendations


def get_recommendations(
    service_name: str = None,
    product: str = None,
    cve_id: str = None,
) -> List[Recommendation]:
    """Convenience function to get recommendations."""
    engine = RemediationEngine()
    recommendations = []

    if cve_id:
        recommendations.extend(engine.get_recommendations_for_vuln(cve_id))

    if service_name:
        recommendations.extend(
            engine.get_recommendations_for_service(service_name, product)
        )

    return recommendations


def get_recommendations_summary(
    services: list,
    vulnerabilities: list,
) -> Dict[str, Any]:
    """
    Generate a summary of recommendations for scan results.

    Args:
        services: List of Service objects
        vulnerabilities: List of Vulnerability objects

    Returns:
        Summary dict with categorized recommendations
    """
    engine = RemediationEngine()
    seen_services = set()
    all_recommendations = []

    # Get service-based recommendations (deduplicated)
    for svc in services:
        svc_type = engine.get_service_type(svc.service_name, svc.product)
        if svc_type not in seen_services:
            seen_services.add(svc_type)
            recs = engine.get_recommendations_for_service(svc.service_name, svc.product)
            all_recommendations.extend(recs)

    # Get vulnerability-specific recommendations
    for vuln in vulnerabilities:
        recs = engine.get_recommendations_for_vuln(vuln.cve_id)
        all_recommendations.extend(recs)

    # Categorize by priority
    by_priority = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    for rec in all_recommendations:
        by_priority.get(rec.priority, by_priority["medium"]).append({
            "title": rec.title,
            "description": rec.description,
            "action": rec.action,
            "source": rec.source,
            "reference": rec.reference,
        })

    return {
        "total": len(all_recommendations),
        "by_priority": by_priority,
        "critical_count": len(by_priority["critical"]),
        "high_count": len(by_priority["high"]),
    }
