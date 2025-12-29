"""
Scan Diff - Compare two scan results to identify changes.
"""

from dataclasses import dataclass, field
from typing import List, Set, Tuple

from .models import Host, HostRiskResult, Scan, Service, Vulnerability


@dataclass
class ScanDiff:
    scan_old: Scan
    scan_new: Scan
    hosts_added: List[Host] = field(default_factory=list)
    hosts_removed: List[Host] = field(default_factory=list)
    hosts_unchanged: List[Host] = field(default_factory=list)
    services_added: List[Tuple[str, Service]] = field(default_factory=list)
    services_removed: List[Tuple[str, Service]] = field(default_factory=list)
    vulns_added: List[Vulnerability] = field(default_factory=list)
    vulns_fixed: List[Vulnerability] = field(default_factory=list)
    risk_delta: float = 0.0

    @property
    def has_changes(self) -> bool:
        return bool(
            self.hosts_added or self.hosts_removed or
            self.services_added or self.services_removed or
            self.vulns_added or self.vulns_fixed
        )

    @property
    def summary(self) -> dict:
        return {
            "hosts_added": len(self.hosts_added),
            "hosts_removed": len(self.hosts_removed),
            "services_added": len(self.services_added),
            "services_removed": len(self.services_removed),
            "vulns_added": len(self.vulns_added),
            "vulns_fixed": len(self.vulns_fixed),
            "risk_delta": self.risk_delta,
        }


class ScanComparator:
    """Compare two scan results."""

    def compare(
        self,
        scan_old: Scan,
        scan_new: Scan,
        hosts_old: List[Host],
        hosts_new: List[Host],
        services_old: List[Service],
        services_new: List[Service],
        vulns_old: List[Vulnerability],
        vulns_new: List[Vulnerability],
        risks_old: List[HostRiskResult],
        risks_new: List[HostRiskResult],
    ) -> ScanDiff:
        diff = ScanDiff(scan_old=scan_old, scan_new=scan_new)

        # Compare hosts by IP
        old_ips = {h.ip: h for h in hosts_old}
        new_ips = {h.ip: h for h in hosts_new}

        for ip, host in new_ips.items():
            if ip not in old_ips:
                diff.hosts_added.append(host)
            else:
                diff.hosts_unchanged.append(host)

        for ip, host in old_ips.items():
            if ip not in new_ips:
                diff.hosts_removed.append(host)

        # Compare services by (host_ip, port, proto)
        def service_key(s: Service) -> Tuple[str, int, str]:
            return (s.host_ip, s.port, s.proto)

        old_svcs = {service_key(s): s for s in services_old}
        new_svcs = {service_key(s): s for s in services_new}

        for key, svc in new_svcs.items():
            if key not in old_svcs:
                diff.services_added.append((key[0], svc))

        for key, svc in old_svcs.items():
            if key not in new_svcs:
                diff.services_removed.append((key[0], svc))

        # Compare vulnerabilities by CVE ID
        old_cves = {v.cve_id: v for v in vulns_old}
        new_cves = {v.cve_id: v for v in vulns_new}

        for cve_id, vuln in new_cves.items():
            if cve_id not in old_cves:
                diff.vulns_added.append(vuln)

        for cve_id, vuln in old_cves.items():
            if cve_id not in new_cves:
                diff.vulns_fixed.append(vuln)

        # Calculate risk delta
        old_avg = sum(r.risk_score for r in risks_old) / len(risks_old) if risks_old else 0
        new_avg = sum(r.risk_score for r in risks_new) / len(risks_new) if risks_new else 0
        diff.risk_delta = round(new_avg - old_avg, 2)

        return diff
