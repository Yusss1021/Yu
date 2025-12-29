"""
NSE-based vulnerability verification using Nmap.
"""

import logging
import re
from datetime import datetime
from typing import Dict, List

import nmap

from ..config import get_config
from ..core.models import Service, VerificationResult, Severity
from .base import ServiceVerifier

logger = logging.getLogger(__name__)

_VULN_RE = re.compile(r"(?i)\bVULNERABLE\b")
_NOT_VULN_RE = re.compile(r"(?i)NOT VULNERABLE")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


class NseVulnVerifier(ServiceVerifier):
    """Runs Nmap NSE vulnerability scripts against services."""

    def __init__(self, timeout: float = None):
        config = get_config()
        self.timeout = timeout or config.scan.timeout * 10

    @property
    def name(self) -> str:
        return "NSE Vulnerability Scanner"

    def verify(self, services: List[Service]) -> List[VerificationResult]:
        results: List[VerificationResult] = []
        service_map = {
            (s.host_ip, s.port, s.proto): s
            for s in services
            if s.id and s.host_id
        }
        host_ports = self._group_ports_by_host(services)
        nm = nmap.PortScanner()

        for ip, ports in host_ports.items():
            try:
                args = self._build_args(ports)
                logger.debug(f"Running NSE scan on {ip}: {args}")
                nm.scan(hosts=ip, arguments=args)
            except nmap.PortScannerError as e:
                logger.warning(f"NSE scan failed for {ip}: {e}")
                continue

            if ip not in nm.all_hosts():
                continue
            host_data = nm[ip]

            for proto in ("tcp", "udp"):
                for port, port_data in host_data.get(proto, {}).items():
                    svc = service_map.get((ip, port, proto))
                    if not svc:
                        continue
                    for script_name, output in (port_data.get("script") or {}).items():
                        if not self._is_vulnerable(output):
                            continue
                        cves = _CVE_RE.findall(output or "")
                        results.append(VerificationResult(
                            scan_id=0,
                            host_id=svc.host_id,
                            service_id=svc.id,
                            verifier="nmap-nse",
                            name=script_name,
                            severity=Severity.HIGH,
                            cve_id=cves[0] if cves else None,
                            description=f"NSE script {script_name} detected vulnerability",
                            evidence=output[:500] if output else None,
                            detected_at=datetime.now(),
                        ))

        return results

    def _group_ports_by_host(self, services: List[Service]) -> Dict[str, List[int]]:
        host_ports: Dict[str, List[int]] = {}
        for svc in services:
            if svc.host_ip and svc.port:
                host_ports.setdefault(svc.host_ip, []).append(svc.port)
        return host_ports

    def _build_args(self, ports: List[int]) -> str:
        port_str = ",".join(str(p) for p in sorted(set(ports)))
        return f"-sV --script vuln -p {port_str} --host-timeout {int(self.timeout)}s"

    def _is_vulnerable(self, output: str) -> bool:
        if not output:
            return False
        return bool(_VULN_RE.search(output)) and not _NOT_VULN_RE.search(output)
