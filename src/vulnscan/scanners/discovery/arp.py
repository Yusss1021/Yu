"""
ARP Scanner - Discover live hosts on local network using ARP.
"""

import ipaddress
import logging
from typing import List, Optional

from scapy.all import ARP, Ether, srp, conf, get_if_hwaddr

from ...core.base import AssetScanner, ScanContext
from ...core.models import Host, ScanResult
from ...config import get_config

logger = logging.getLogger(__name__)

# Suppress Scapy warnings
conf.verb = 0


class ARPScanner(AssetScanner):
    """
    ARP Scanner for local network host discovery.

    Uses ARP requests to discover hosts on the local network segment.
    More reliable than ICMP for local networks as ARP is typically not filtered.

    Note: Only works for hosts on the same network segment.
    """

    def __init__(self, timeout: float = None, interface: str = None):
        """
        Initialize ARP scanner.

        Args:
            timeout: Timeout for ARP requests in seconds
            interface: Network interface to use (auto-detect if None)
        """
        config = get_config()
        self.timeout = timeout or config.scan.timeout
        self.interface = interface

    @property
    def name(self) -> str:
        return "ARP Scanner"

    def scan(self, context: ScanContext) -> ScanResult:
        """
        Scan local network for hosts using ARP.

        Args:
            context: Scan context with target range

        Returns:
            ScanResult containing discovered hosts with MAC addresses
        """
        result = ScanResult()

        try:
            targets = self._parse_targets(context.target_range)
        except ValueError as e:
            result.errors.append(f"Invalid target range: {e}")
            return result

        logger.info(f"Starting ARP scan of {len(targets)} targets")

        # Build ARP request packets
        try:
            hosts = self._arp_scan(targets)
            result.hosts.extend(hosts)
        except PermissionError:
            result.errors.append("ARP scan requires root privileges")
        except Exception as e:
            result.errors.append(f"ARP scan error: {e}")
            logger.error(f"ARP scan failed: {e}")

        logger.info(f"ARP scan complete: {len(result.hosts)} hosts found")
        return result

    def _arp_scan(self, targets: List[str]) -> List[Host]:
        """
        Perform ARP scan on target list.

        Args:
            targets: List of IP addresses to scan

        Returns:
            List of discovered Host objects
        """
        hosts = []

        # Group targets into batches for efficiency
        batch_size = 256
        for i in range(0, len(targets), batch_size):
            batch = targets[i : i + batch_size]
            batch_hosts = self._scan_batch(batch)
            hosts.extend(batch_hosts)

        return hosts

    def _scan_batch(self, targets: List[str]) -> List[Host]:
        """
        Scan a batch of targets.

        Args:
            targets: Batch of IP addresses

        Returns:
            List of discovered hosts
        """
        hosts = []

        # Create ARP request packets for all targets
        packets = [
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in targets
        ]

        # Send packets and receive responses
        answered, _ = srp(
            packets,
            timeout=self.timeout,
            verbose=0,
            iface=self.interface,
        )

        # Process responses
        for sent, received in answered:
            if received.haslayer(ARP):
                arp_layer = received.getlayer(ARP)
                host = Host(
                    ip=arp_layer.psrc,
                    mac=arp_layer.hwsrc,
                    is_alive=True,
                )
                hosts.append(host)
                logger.debug(f"Found host: {host.ip} ({host.mac})")

        return hosts

    def _parse_targets(self, target_range: str) -> List[str]:
        """
        Parse target range into list of IP addresses.

        Args:
            target_range: Target specification (CIDR or range)

        Returns:
            List of IP address strings
        """
        targets = []

        for part in target_range.split(","):
            part = part.strip()

            if "/" in part:
                # CIDR notation
                network = ipaddress.ip_network(part, strict=False)
                targets.extend(str(ip) for ip in network.hosts())
            elif "-" in part:
                # Range notation
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
                # Single IP
                ipaddress.ip_address(part)
                targets.append(part)

        return targets


def get_local_mac(interface: str = None) -> Optional[str]:
    """
    Get MAC address of local interface.

    Args:
        interface: Interface name (auto-detect if None)

    Returns:
        MAC address string or None
    """
    try:
        if interface:
            return get_if_hwaddr(interface)
        return get_if_hwaddr(conf.iface)
    except Exception:
        return None
