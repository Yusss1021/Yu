"""
TCP SYN Scanner - Port scanning using TCP SYN packets.
"""

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from scapy.all import IP, TCP, sr1, conf, RandShort

from ...core.base import AssetScanner, ScanContext
from ...core.models import Host, Service, PortState, ScanResult
from ...config import get_config

logger = logging.getLogger(__name__)

# Suppress Scapy warnings
conf.verb = 0


class SYNScanner(AssetScanner):
    """
    TCP SYN Scanner for port discovery.

    Sends TCP SYN packets and analyzes responses:
    - SYN-ACK: Port is open
    - RST: Port is closed
    - No response: Port is filtered

    Also known as "half-open" or "stealth" scanning.
    """

    # Common ports to scan by default
    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
    ]

    def __init__(
        self,
        timeout: float = None,
        max_threads: int = None,
        ports: List[int] = None,
    ):
        """
        Initialize SYN scanner.

        Args:
            timeout: Timeout for each probe in seconds
            max_threads: Maximum concurrent threads
            ports: List of ports to scan (uses DEFAULT_PORTS if None)
        """
        config = get_config()
        self.timeout = timeout or config.scan.timeout
        self.max_threads = max_threads or config.scan.max_threads
        self.ports = ports or self.DEFAULT_PORTS

    @property
    def name(self) -> str:
        return "TCP SYN Scanner"

    def scan(self, context: ScanContext) -> ScanResult:
        """
        Scan targets for open ports using TCP SYN.

        Args:
            context: Scan context with target range or discovered hosts

        Returns:
            ScanResult containing discovered services
        """
        result = ScanResult()

        # Use discovered hosts if available, otherwise parse targets
        if context.discovered_hosts:
            targets = [h.ip for h in context.discovered_hosts]
        else:
            try:
                targets = self._parse_targets(context.target_range)
            except ValueError as e:
                result.errors.append(f"Invalid target range: {e}")
                return result

        # Get port list from context options or use defaults
        ports = context.options.get("ports", self.ports)
        if isinstance(ports, str):
            ports = self._parse_ports(ports)

        total_probes = len(targets) * len(ports)
        logger.info(f"Starting SYN scan: {len(targets)} hosts, {len(ports)} ports ({total_probes} probes)")

        # Generate all (ip, port) combinations
        probes = [(ip, port) for ip in targets for port in ports]

        # Parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port): (ip, port)
                for ip, port in probes
            }

            for future in as_completed(futures):
                ip, port = futures[future]
                try:
                    service = future.result()
                    if service and service.state == PortState.OPEN:
                        result.services.append(service)
                        # Also add host if not already present
                        if not any(h.ip == ip for h in result.hosts):
                            result.hosts.append(Host(ip=ip, is_alive=True))
                        logger.debug(f"Open port found: {ip}:{port}")
                except Exception as e:
                    logger.warning(f"Error scanning {ip}:{port}: {e}")

        logger.info(f"SYN scan complete: {len(result.services)} open ports on {len(result.hosts)} hosts")
        return result

    def _scan_port(self, ip: str, port: int) -> Service | None:
        """
        Scan a single port on a host.

        Args:
            ip: Target IP address
            port: Target port number

        Returns:
            Service object with state, or None on error
        """
        # Build SYN packet
        src_port = RandShort()
        packet = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S")

        try:
            reply = sr1(packet, timeout=self.timeout, verbose=0)

            if reply is None:
                # No response - filtered
                return Service(
                    host_ip=ip,
                    port=port,
                    proto="tcp",
                    state=PortState.FILTERED,
                )

            if reply.haslayer(TCP):
                tcp_layer = reply.getlayer(TCP)

                if tcp_layer.flags == 0x12:  # SYN-ACK
                    # Send RST to close connection (stealth)
                    rst = IP(dst=ip) / TCP(sport=src_port, dport=port, flags="R")
                    sr1(rst, timeout=0.5, verbose=0)

                    return Service(
                        host_ip=ip,
                        port=port,
                        proto="tcp",
                        state=PortState.OPEN,
                    )

                elif tcp_layer.flags == 0x14:  # RST-ACK
                    return Service(
                        host_ip=ip,
                        port=port,
                        proto="tcp",
                        state=PortState.CLOSED,
                    )

        except Exception as e:
            logger.debug(f"SYN scan error for {ip}:{port}: {e}")

        return None

    def _parse_ports(self, port_spec: str) -> List[int]:
        """
        Parse port specification string.

        Supports:
        - Single port: "80"
        - List: "80,443,8080"
        - Range: "1-1024"
        - Mixed: "22,80,443,8000-8100"

        Args:
            port_spec: Port specification string

        Returns:
            List of port numbers
        """
        ports = []

        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

        return sorted(set(ports))

    def _parse_targets(self, target_range: str) -> List[str]:
        """Parse target range into list of IP addresses."""
        targets = []

        for part in target_range.split(","):
            part = part.strip()

            if "/" in part:
                network = ipaddress.ip_network(part, strict=False)
                targets.extend(str(ip) for ip in network.hosts())
            elif "-" in part:
                if part.count("-") == 1 and "." in part:
                    base, end = part.rsplit("-", 1)
                    if "." in end:
                        start_ip = ipaddress.ip_address(base)
                        end_ip = ipaddress.ip_address(end)
                        current = int(start_ip)
                        while current <= int(end_ip):
                            targets.append(str(ipaddress.ip_address(current)))
                            current += 1
                    else:
                        base_parts = base.rsplit(".", 1)
                        start = int(base_parts[1])
                        end_num = int(end)
                        for i in range(start, end_num + 1):
                            targets.append(f"{base_parts[0]}.{i}")
            else:
                ipaddress.ip_address(part)
                targets.append(part)

        return targets
