"""
Nmap Service Scanner - Service identification using Nmap.
"""

import logging
import re
from typing import Dict, List, Optional

import nmap

from ...core.base import ServiceScanner, ScanContext
from ...core.models import Host, Service, PortState, ScanResult
from ...config import get_config

logger = logging.getLogger(__name__)


class NmapScanner(ServiceScanner):
    """
    Service identification scanner using Nmap.

    Uses python-nmap to invoke Nmap for:
    - Service version detection (-sV)
    - OS detection (-O) [optional]
    - Script scanning (-sC) [optional]
    """

    def __init__(
        self,
        timeout: float = None,
        version_intensity: int = 5,
        os_detection: bool = False,
        scripts: bool = False,
    ):
        """
        Initialize Nmap scanner.

        Args:
            timeout: Timeout for scanning in seconds
            version_intensity: Version detection intensity (0-9)
            os_detection: Enable OS detection (requires root)
            scripts: Enable default NSE scripts
        """
        config = get_config()
        self.timeout = timeout or config.scan.timeout * 10  # Nmap needs more time
        self.version_intensity = version_intensity
        self.os_detection = os_detection
        self.scripts = scripts

        # Initialize nmap scanner
        self._nm = nmap.PortScanner()

    @property
    def name(self) -> str:
        return "Nmap Service Scanner"

    def scan(self, context: ScanContext) -> ScanResult:
        """
        Scan hosts for service identification.

        Args:
            context: Scan context with discovered hosts and services

        Returns:
            ScanResult with identified services
        """
        result = ScanResult()

        # Determine what to scan
        if context.discovered_services:
            # Scan specific host:port combinations
            host_ports = self._group_services_by_host(context.discovered_services)
        elif context.discovered_hosts:
            # Scan all ports on discovered hosts
            host_ports = {h.ip: None for h in context.discovered_hosts}
        else:
            # No hosts discovered yet, scan the target range
            try:
                hosts = self._scan_range(context.target_range)
                result.hosts.extend(hosts)
                return result
            except Exception as e:
                result.errors.append(f"Nmap scan error: {e}")
                return result

        logger.info(f"Starting Nmap service scan on {len(host_ports)} hosts")

        for ip, ports in host_ports.items():
            try:
                host_result = self._scan_host(ip, ports)
                result.hosts.extend(host_result.hosts)
                result.services.extend(host_result.services)
            except Exception as e:
                logger.error(f"Error scanning {ip}: {e}")
                result.errors.append(f"Nmap error for {ip}: {e}")

        logger.info(f"Nmap scan complete: {len(result.services)} services identified")
        return result

    def _scan_host(self, ip: str, ports: List[int] = None) -> ScanResult:
        """
        Scan a single host.

        Args:
            ip: Target IP address
            ports: Specific ports to scan, or None for default

        Returns:
            ScanResult for this host
        """
        result = ScanResult()

        # Build Nmap arguments
        args = self._build_arguments(ports)

        try:
            self._nm.scan(hosts=ip, arguments=args)
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap error: {e}")

        # Process results
        if ip in self._nm.all_hosts():
            host_data = self._nm[ip]

            # Create host object
            host = Host(
                ip=ip,
                hostname=self._get_hostname(host_data),
                os_guess=self._get_os_guess(host_data),
                is_alive=True,
            )
            result.hosts.append(host)

            # Process TCP ports
            if "tcp" in host_data:
                for port, port_data in host_data["tcp"].items():
                    service = self._parse_service(ip, port, "tcp", port_data)
                    if service:
                        result.services.append(service)

            # Process UDP ports
            if "udp" in host_data:
                for port, port_data in host_data["udp"].items():
                    service = self._parse_service(ip, port, "udp", port_data)
                    if service:
                        result.services.append(service)

        return result

    def _scan_range(self, target_range: str) -> List[Host]:
        """
        Quick scan of a target range to find live hosts.

        Args:
            target_range: Target specification

        Returns:
            List of discovered hosts
        """
        hosts = []

        try:
            self._nm.scan(hosts=target_range, arguments="-sn")

            for ip in self._nm.all_hosts():
                host_data = self._nm[ip]
                host = Host(
                    ip=ip,
                    hostname=self._get_hostname(host_data),
                    is_alive=True,
                )
                hosts.append(host)

        except nmap.PortScannerError as e:
            logger.error(f"Nmap range scan error: {e}")

        return hosts

    def _build_arguments(self, ports: List[int] = None) -> str:
        """
        Build Nmap command arguments.

        Args:
            ports: Specific ports to scan

        Returns:
            Argument string
        """
        args = ["-sV"]  # Service version detection

        # Version intensity
        args.append(f"--version-intensity {self.version_intensity}")

        # OS detection
        if self.os_detection:
            args.append("-O")

        # Script scanning
        if self.scripts:
            args.append("-sC")

        # Specific ports
        if ports:
            port_str = ",".join(str(p) for p in ports)
            args.append(f"-p {port_str}")

        # Timeout
        args.append(f"--host-timeout {int(self.timeout)}s")

        return " ".join(args)

    def _parse_service(
        self, ip: str, port: int, proto: str, port_data: dict
    ) -> Optional[Service]:
        """
        Parse Nmap port data into Service object.

        Args:
            ip: Host IP
            port: Port number
            proto: Protocol (tcp/udp)
            port_data: Nmap port data dictionary

        Returns:
            Service object or None
        """
        state = port_data.get("state", "")
        if state not in ("open", "open|filtered"):
            return None

        # Extract service information
        service_name = port_data.get("name", "")
        product = port_data.get("product", "")
        version = port_data.get("version", "")
        extrainfo = port_data.get("extrainfo", "")
        cpe_list = port_data.get("cpe", "")

        # Get first CPE if available
        cpe = None
        if cpe_list:
            if isinstance(cpe_list, list):
                cpe = cpe_list[0] if cpe_list else None
            else:
                cpe = cpe_list

        # Build banner from extra info
        banner = None
        if extrainfo:
            banner = extrainfo

        return Service(
            host_ip=ip,
            port=port,
            proto=proto,
            service_name=service_name,
            product=product,
            version=version,
            cpe=cpe,
            state=PortState.OPEN,
            banner=banner,
        )

    def _get_hostname(self, host_data: dict) -> Optional[str]:
        """Extract hostname from Nmap host data."""
        hostnames = host_data.get("hostnames", [])
        if hostnames:
            for hostname in hostnames:
                name = hostname.get("name", "")
                if name:
                    return name
        return None

    def _get_os_guess(self, host_data: dict) -> Optional[str]:
        """Extract OS guess from Nmap host data."""
        osmatch = host_data.get("osmatch", [])
        if osmatch:
            # Return the best match
            best = osmatch[0]
            name = best.get("name", "")
            accuracy = best.get("accuracy", "")
            if name:
                return f"{name} ({accuracy}%)" if accuracy else name
        return None

    def _group_services_by_host(
        self, services: List[Service]
    ) -> Dict[str, List[int]]:
        """
        Group services by host IP.

        Args:
            services: List of Service objects

        Returns:
            Dictionary mapping IP to list of ports
        """
        host_ports: Dict[str, List[int]] = {}

        for svc in services:
            if svc.host_ip not in host_ports:
                host_ports[svc.host_ip] = []
            host_ports[svc.host_ip].append(svc.port)

        return host_ports


def check_nmap_installed() -> bool:
    """Check if Nmap is installed and accessible."""
    try:
        nm = nmap.PortScanner()
        nm.nmap_version()
        return True
    except nmap.PortScannerError:
        return False


def get_nmap_version() -> Optional[str]:
    """Get installed Nmap version."""
    try:
        nm = nmap.PortScanner()
        version = nm.nmap_version()
        return ".".join(str(v) for v in version)
    except nmap.PortScannerError:
        return None
