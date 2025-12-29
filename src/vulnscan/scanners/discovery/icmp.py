"""
ICMP Ping Scanner - Discover live hosts using ICMP Echo Request.
"""

import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from scapy.all import IP, ICMP, sr1, conf

from ...core.base import AssetScanner, ScanContext
from ...core.models import Host, ScanResult
from ...config import get_config

logger = logging.getLogger(__name__)

# Suppress Scapy warnings
conf.verb = 0


class ICMPScanner(AssetScanner):
    """
    ICMP Echo Request scanner for host discovery.

    Uses Scapy to send ICMP Echo Request packets and detect live hosts
    based on Echo Reply responses.

    Note: Requires root/admin privileges to send raw packets.
    """

    def __init__(self, timeout: float = None, max_threads: int = None):
        """
        Initialize ICMP scanner.

        Args:
            timeout: Timeout for each ICMP request in seconds
            max_threads: Maximum number of concurrent threads
        """
        config = get_config()
        self.timeout = timeout or config.scan.timeout
        self.max_threads = max_threads or config.scan.max_threads

    @property
    def name(self) -> str:
        return "ICMP Scanner"

    def scan(self, context: ScanContext) -> ScanResult:
        """
        Scan target range for live hosts using ICMP.

        Args:
            context: Scan context with target range

        Returns:
            ScanResult containing discovered hosts
        """
        result = ScanResult()

        try:
            targets = self._parse_targets(context.target_range)
        except ValueError as e:
            result.errors.append(f"Invalid target range: {e}")
            return result

        logger.info(f"Starting ICMP scan of {len(targets)} targets")

        # Parallel scanning with thread pool
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._ping_host, ip): ip for ip in targets
            }

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    host = future.result()
                    if host:
                        result.hosts.append(host)
                        logger.debug(f"Host {ip} is alive")
                except Exception as e:
                    logger.warning(f"Error scanning {ip}: {e}")
                    result.errors.append(f"ICMP scan error for {ip}: {e}")

        logger.info(f"ICMP scan complete: {len(result.hosts)} hosts found")
        return result

    def _ping_host(self, ip: str) -> Host | None:
        """
        Send ICMP Echo Request to a single host.

        Args:
            ip: Target IP address

        Returns:
            Host object if alive, None otherwise
        """
        packet = IP(dst=ip) / ICMP()

        try:
            reply = sr1(packet, timeout=self.timeout, verbose=0)

            if reply and reply.haslayer(ICMP):
                icmp_layer = reply.getlayer(ICMP)
                # Type 0 = Echo Reply
                if icmp_layer.type == 0:
                    return Host(ip=ip, is_alive=True)
        except Exception as e:
            logger.debug(f"ICMP error for {ip}: {e}")

        return None

    def _parse_targets(self, target_range: str) -> List[str]:
        """
        Parse target range into list of IP addresses.

        Supports:
        - Single IP: 192.168.1.1
        - CIDR: 192.168.1.0/24
        - Range: 192.168.1.1-192.168.1.254

        Args:
            target_range: Target specification string

        Returns:
            List of IP address strings
        """
        targets = []

        # Handle comma-separated targets
        for part in target_range.split(","):
            part = part.strip()

            if "/" in part:
                # CIDR notation
                network = ipaddress.ip_network(part, strict=False)
                targets.extend(str(ip) for ip in network.hosts())
            elif "-" in part:
                # Range notation (e.g., 192.168.1.1-254)
                if part.count("-") == 1 and "." in part:
                    base, end = part.rsplit("-", 1)
                    if "." in end:
                        # Full IP range: 192.168.1.1-192.168.1.254
                        start_ip = ipaddress.ip_address(base)
                        end_ip = ipaddress.ip_address(end)
                        current = int(start_ip)
                        while current <= int(end_ip):
                            targets.append(str(ipaddress.ip_address(current)))
                            current += 1
                    else:
                        # Short range: 192.168.1.1-254
                        base_parts = base.rsplit(".", 1)
                        start = int(base_parts[1])
                        end_num = int(end)
                        for i in range(start, end_num + 1):
                            targets.append(f"{base_parts[0]}.{i}")
            else:
                # Single IP
                ipaddress.ip_address(part)  # Validate
                targets.append(part)

        return targets
