from __future__ import annotations

import ipaddress
import importlib
import os
import shutil
import subprocess
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import ModuleType
from typing import Protocol, cast

from ..config import MAX_HOSTS_PER_SCAN
from ..models import HostAsset


class _ScapyTcpLayer(Protocol):
    flags: int
    dport: int
    sport: int
    ack: int


class _ScapyPacket(Protocol):
    def __truediv__(self, other: object) -> "_ScapyPacket": ...

    def haslayer(self, layer: object) -> bool: ...

    def getlayer(self, layer: object) -> _ScapyTcpLayer: ...

    def __getitem__(self, layer: object) -> _ScapyTcpLayer: ...


class _ScapyLayerFactory(Protocol):
    def __call__(self, *args: object, **kwargs: object) -> _ScapyPacket: ...


class _ScapyAll(Protocol):
    IP: _ScapyLayerFactory
    TCP: _ScapyLayerFactory
    Ether: _ScapyLayerFactory
    ARP: _ScapyLayerFactory

    def sr(
        self, *args: object, **kwargs: object
    ) -> tuple[Iterable[tuple[_ScapyPacket, _ScapyPacket]], object]: ...

    def srp(self, *args: object, **kwargs: object) -> tuple[Iterable[tuple[object, object]], object]: ...

    def send(self, *args: object, **kwargs: object) -> object: ...


class _ArpResponse(Protocol):
    psrc: str
    hwsrc: str


class AssetDiscoveryEngine:
    def __init__(
        self,
        timeout_seconds: float = 1.0,
        max_workers: int = 64,
        max_hosts_per_scan: int = MAX_HOSTS_PER_SCAN,
        logger: object | None = None,
    ) -> None:
        self.timeout_seconds: float = timeout_seconds
        self.max_workers: int = max_workers
        self.max_hosts_per_scan: int = max_hosts_per_scan
        self._logger: object | None = logger

    def _warn(self, message: str) -> None:
        if self._logger is not None and hasattr(self._logger, "warning"):
            try:
                getattr(self._logger, "warning")(message)
                return
            except Exception:
                pass
        print(message)

    def discover(self, cidr: str, ports: list[int], methods: list[str]) -> list[HostAsset]:
        network = ipaddress.ip_network(cidr, strict=False)
        host_count = self._estimate_host_count(network)
        # 限制网段规模，避免一次性展开超大地址导致内存与耗时不可控
        if host_count > self.max_hosts_per_scan:
            raise ValueError(f"目标网段过大: 约 {host_count} 台主机，超过上限 {self.max_hosts_per_scan}")
        host_ips = [str(ip) for ip in network.hosts()]
        assets: dict[str, HostAsset] = {}

        if network.version == 6 and ("arp" in methods or "syn" in methods):
            print("警告: 目标网段为 IPv6，当前发现引擎仅支持 IPv4；将跳过 ARP/SYN。")

        def _ordered_discovered_by(tags: Iterable[str]) -> list[str]:
            priority: dict[str, int] = {"icmp": 0, "arp": 1, "syn": 2}
            seen: set[str] = set()
            unique: list[str] = []
            for item in tags:
                if item in seen:
                    continue
                seen.add(item)
                unique.append(item)
            order: dict[str, int] = {item: idx for idx, item in enumerate(unique)}
            return sorted(unique, key=lambda item: (priority.get(item, 99), order[item]))

        icmp_found: set[str] = set()

        if "icmp" in methods:
            for ip in self._icmp_sweep(host_ips):
                assets.setdefault(ip, HostAsset(ip=ip)).discovered_by.append("icmp")
                icmp_found.add(ip)

        remaining_after_icmp: set[str] = set(host_ips) - icmp_found

        arp_found: set[str] = set()
        if "arp" in methods:
            if network.version != 6 and remaining_after_icmp:
                arp_results = self._arp_sweep(cidr, target_ips=remaining_after_icmp)
                arp_found = set(arp_results)
                for ip, mac in arp_results.items():
                    asset = assets.setdefault(ip, HostAsset(ip=ip))
                    asset.mac = mac
                    asset.discovered_by.append("arp")

        remaining_after_arp: set[str] = remaining_after_icmp - arp_found

        if "syn" in methods and network.version != 6 and remaining_after_arp:
            try:
                self._ensure_syn_ready()
            except RuntimeError as exc:
                self._warn(
                    "警告: 已请求 SYN 扫描，但无法执行 SYN 端口发现 (missing scapy)；"
                    + f"原因: {exc}。"
                    + "将继续并尽可能从 nmap/socket 指纹结果回填 open_ports。 "
                    + "(will backfill from nmap/socket where possible)"
                )
            except PermissionError as exc:
                self._warn(
                    "警告: 已请求 SYN 扫描，但无法执行 SYN 端口发现 (need root/CAP_NET_RAW)；"
                    + f"原因: {exc}。"
                    + "将继续并尽可能从 nmap/socket 指纹结果回填 open_ports。 "
                    + "(will backfill from nmap/socket where possible)"
                )
            else:
                open_ports_by_host = self._syn_sweep(list(remaining_after_arp), ports)
                for ip, open_ports in open_ports_by_host.items():
                    asset = assets.setdefault(ip, HostAsset(ip=ip))
                    asset.open_ports.extend(sorted(open_ports))
                    asset.discovered_by.append("syn")

        for asset in assets.values():
            asset.discovered_by = _ordered_discovered_by(asset.discovered_by)
            asset.open_ports = sorted(set(asset.open_ports))

        return sorted(assets.values(), key=lambda item: ipaddress.ip_address(item.ip))

    def _icmp_sweep(self, host_ips: list[str]) -> list[str]:
        if not host_ips:
            return []
        alive_hosts: list[str] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._ping_once, ip): ip for ip in host_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        alive_hosts.append(ip)
                except Exception:
                    continue
        return alive_hosts

    def _ping_once(self, ip: str) -> bool:
        if shutil.which("ping") is None:
            return False
        timeout = str(max(int(self.timeout_seconds), 1))
        command = ["ping", "-c", "1", "-W", timeout, ip]
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0

    def _arp_sweep(self, cidr: str, target_ips: Iterable[str] | None = None) -> dict[str, str]:
        try:
            scapy_all = self._load_scapy_all()
        except Exception as exc:
            print(
                "警告: 已请求 ARP 扫描，但无法执行 ARP 扫描；"
                + "ARP 需要安装 scapy 且需要 root 权限。"
                + f"原因: {exc}。将跳过 ARP。"
            )
            return {}
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print(
                "警告: 已请求 ARP 扫描，但当前进程非 root (geteuid!=0)。"
                + "ARP 需要安装 scapy 且需要 root 权限；将跳过 ARP。"
            )
            return {}

        pdst: object = cidr if target_ips is None else list(target_ips)
        packet = scapy_all.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy_all.ARP(pdst=pdst)
        answered, _ = scapy_all.srp(packet, timeout=self.timeout_seconds, verbose=False)
        result: dict[str, str] = {}
        for _, response in answered:
            arp = cast(_ArpResponse, response)
            ip = arp.psrc
            mac = arp.hwsrc
            if ip:
                result[ip] = mac
        return result

    def _syn_sweep(self, host_ips: list[str], ports: list[int]) -> dict[str, set[int]]:
        if not host_ips or not ports:
            return {}
        open_ports_by_host: dict[str, set[int]] = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_host_syn_open_ports, ip, ports): ip for ip in host_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    open_ports = future.result()
                except Exception:
                    continue
                if open_ports:
                    open_ports_by_host[ip] = set(open_ports)
        return open_ports_by_host

    def _scan_host_syn_open_ports(self, ip: str, ports: list[int]) -> set[int]:
        scapy_all = self._load_scapy_all()
        IP = scapy_all.IP
        TCP = scapy_all.TCP
        send = scapy_all.send
        sr = scapy_all.sr

        if ":" in ip:
            return set()
        packet = IP(dst=ip) / TCP(dport=ports, flags="S")
        answered, _ = sr(
            packet,
            timeout=self.timeout_seconds,
            retry=0,
            verbose=False,
        )
        rst_packets: list[_ScapyPacket] = []
        open_ports: set[int] = set()
        for sent, received in answered:
            if not received.haslayer(TCP):
                continue
            flags = int(received.getlayer(TCP).flags)
            if flags & 0x12 != 0x12:
                continue
            try:
                open_ports.add(int(sent[TCP].dport))
            except Exception:
                continue
            rst_packets.append(
                IP(dst=ip)
                / TCP(
                    dport=int(sent[TCP].dport),
                    sport=int(sent[TCP].sport),
                    flags="R",
                    seq=int(received[TCP].ack),
                )
            )
        if rst_packets:
            _ = send(rst_packets, verbose=False)
        return open_ports

    def _estimate_host_count(self, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
        num_addresses = int(network.num_addresses)
        if network.version == 4:
            if network.prefixlen >= 31:
                return num_addresses
            return max(num_addresses - 2, 0)
        return num_addresses

    def _ensure_syn_ready(self) -> None:
        try:
            _ = self._load_scapy_all()
        except Exception as exc:
            raise RuntimeError("SYN 扫描需要安装 scapy") from exc

        if self._has_raw_socket_permission():
            return
        raise PermissionError("SYN 扫描需要 root 或 CAP_NET_RAW")

    def _load_scapy_all(self) -> _ScapyAll:
        module: ModuleType = importlib.import_module("scapy.all")
        return cast(_ScapyAll, cast(object, module))

    def _has_raw_socket_permission(self) -> bool:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True

        if os.name != "posix":
            return False
        try:
            status_text = ""
            with open("/proc/self/status", "r", encoding="utf-8") as handle:
                status_text = handle.read()
            for line in status_text.splitlines():
                if not line.startswith("CapEff:"):
                    continue
                cap_eff_hex = line.split(":", 1)[1].strip()
                cap_eff = int(cap_eff_hex, 16)
                cap_net_raw_bit = 13
                return (cap_eff & (1 << cap_net_raw_bit)) != 0
        except Exception:
            return False
        return False
