from __future__ import annotations

import ipaddress
import importlib
import os
import shutil
import subprocess
import sys
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import ModuleType
from typing import Protocol, cast

from ..config import MAX_HOSTS_PER_SCAN
from ..models import HostAsset
from ..process_utils import windows_hidden_process_kwargs


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
        try:
            print(message)
        except UnicodeEncodeError:
            encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
            safe_message = message.encode(encoding, errors="backslashreplace").decode(encoding, errors="ignore")
            print(safe_message)

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
            if network.version != 6 and icmp_found:
                enrich_targets = [ip for ip in icmp_found if ip in assets and not assets[ip].mac]
                if enrich_targets:
                    enrich_results = self._arp_sweep(cidr, target_ips=enrich_targets)
                    for ip, mac in enrich_results.items():
                        if ip in assets:
                            assets[ip].mac = mac

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
                open_ports_by_host = self._syn_sweep(list(remaining_after_arp), ports, cidr=cidr)
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
        command = self._build_ping_command(ip)
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            **windows_hidden_process_kwargs(os.name, getattr(subprocess, "CREATE_NO_WINDOW", 0)),
        )
        return result.returncode == 0

    def _build_ping_command(self, ip: str) -> list[str]:
        timeout_seconds = max(int(self.timeout_seconds), 1)
        if os.name == "nt":
            return ["ping", "-n", "1", "-w", str(timeout_seconds * 1000), ip]
        return ["ping", "-c", "1", "-W", str(timeout_seconds), ip]

    def _arp_sweep(self, cidr: str, target_ips: Iterable[str] | None = None) -> dict[str, str]:
        result = self._arp_sweep_scapy(cidr, target_ips)
        if not result and os.name == "nt":
            ips = list(target_ips) if target_ips is not None else [
                str(ip) for ip in ipaddress.ip_network(cidr, strict=False).hosts()
            ]
            self._warn("Scapy ARP 未获得结果，尝试 Windows 原生 ARP 发现...")
            result = self._arp_sweep_native(ips)
            if result:
                self._warn(f"Windows 原生 ARP 发现了 {len(result)} 台主机")
        return result

    def _arp_sweep_scapy(self, cidr: str, target_ips: Iterable[str] | None = None) -> dict[str, str]:
        try:
            scapy_all = self._load_scapy_all()
        except Exception as exc:
            self._warn(
                "警告: 已请求 ARP 扫描，但无法加载 scapy；"
                + f"原因: {exc}。将尝试备用方案。"
            )
            return {}
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            self._warn(
                "警告: 已请求 ARP 扫描，但当前进程非 root (geteuid!=0)。"
                + "ARP 需要 root 权限；将尝试备用方案。"
            )
            return {}

        iface = self._resolve_iface_for_target(cidr)
        pdst: object = cidr if target_ips is None else list(target_ips)
        packet = scapy_all.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy_all.ARP(pdst=pdst)
        srp_kwargs: dict[str, object] = {
            "timeout": max(self.timeout_seconds, 3.0),
            "verbose": False,
        }
        if iface is not None:
            srp_kwargs["iface"] = iface
        try:
            answered, _ = scapy_all.srp(packet, **srp_kwargs)
        except Exception as exc:
            self._warn(
                "警告: Scapy ARP 发送失败；"
                + f"原因: {exc}。将尝试备用方案。"
            )
            return {}
        result: dict[str, str] = {}
        for _, response in answered:
            arp = cast(_ArpResponse, response)
            ip = arp.psrc
            mac = arp.hwsrc
            if ip:
                result[ip] = mac
        return result

    def _arp_sweep_native(self, target_ips: list[str]) -> dict[str, str]:
        """Windows fallback: ping targets to populate ARP cache, then read arp -a."""
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self._ping_once, ip) for ip in target_ips]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        try:
            proc = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, check=False,
                **windows_hidden_process_kwargs(os.name, getattr(subprocess, "CREATE_NO_WINDOW", 0)),
            )
        except Exception:
            return {}

        target_set = set(target_ips)
        found: dict[str, str] = {}
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ip_candidate = parts[0].strip()
            mac_candidate = parts[1].strip()
            if ip_candidate not in target_set:
                continue
            cleaned = mac_candidate.replace("-", "").replace(":", "")
            if len(cleaned) != 12:
                continue
            if cleaned.lower() == "ffffffffffff":
                continue
            found[ip_candidate] = mac_candidate.replace("-", ":")
        return found

    def _syn_sweep(self, host_ips: list[str], ports: list[int], cidr: str | None = None) -> dict[str, set[int]]:
        if not host_ips or not ports:
            return {}
        result = self._syn_sweep_scapy(host_ips, ports, cidr)
        if not result and os.name == "nt":
            self._warn("Scapy SYN 未获得结果，尝试 TCP Connect 扫描...")
            result = self._syn_sweep_connect(host_ips, ports)
            if result:
                total = sum(len(p) for p in result.values())
                self._warn(f"TCP Connect 扫描发现 {len(result)} 台主机共 {total} 个开放端口")
        return result

    def _syn_sweep_scapy(self, host_ips: list[str], ports: list[int], cidr: str | None = None) -> dict[str, set[int]]:
        import logging
        open_ports_by_host: dict[str, set[int]] = {}
        iface = self._resolve_iface_for_target(cidr) if cidr else None
        scapy_logger = logging.getLogger("scapy.runtime")
        prev_level = scapy_logger.level
        scapy_logger.setLevel(logging.ERROR)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_host_syn_open_ports, ip, ports, iface): ip for ip in host_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    open_ports = future.result()
                except Exception:
                    continue
                if open_ports:
                    open_ports_by_host[ip] = set(open_ports)
        scapy_logger.setLevel(prev_level)
        return open_ports_by_host

    def _syn_sweep_connect(self, host_ips: list[str], ports: list[int]) -> dict[str, set[int]]:
        """Windows fallback: TCP connect scan when Scapy SYN fails."""
        import socket
        import time

        if self._detect_proxy_tun(host_ips, ports):
            self._warn("检测到代理/TUN 拦截，跳过 TCP Connect，改用 ICMP 验证主机存活...")
            return self._syn_sweep_ping_fallback(host_ips, ports)

        open_ports_by_host: dict[str, set[int]] = {}

        def try_connect(ip: str, port: int) -> tuple[str, int, bool]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(max(self.timeout_seconds, 2.0))
                err = sock.connect_ex((ip, port))
                sock.close()
                return (ip, port, err == 0)
            except Exception:
                return (ip, port, False)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for ip in host_ips:
                for port in ports:
                    futures.append(executor.submit(try_connect, ip, port))
            for future in as_completed(futures):
                try:
                    ip, port, is_open = future.result()
                    if is_open:
                        open_ports_by_host.setdefault(ip, set()).add(port)
                except Exception:
                    continue

        if open_ports_by_host:
            open_ports_by_host = self._verify_connect_results(open_ports_by_host)
        return open_ports_by_host

    def _detect_proxy_tun(self, host_ips: list[str], ports: list[int]) -> bool:
        """Quick check: if TCP connects to random non-existent IPs succeed instantly, a proxy is active."""
        import socket
        import random
        import time

        sample_ips = random.sample(host_ips, min(3, len(host_ips)))
        test_port = ports[0] if ports else 80
        instant_count = 0

        for ip in sample_ips:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                start = time.time()
                err = sock.connect_ex((ip, test_port))
                elapsed = time.time() - start
                sock.close()
                if err == 0 and elapsed < 0.5:
                    instant_count += 1
            except Exception:
                pass

        return instant_count >= 2

    def _syn_sweep_ping_fallback(self, host_ips: list[str], ports: list[int]) -> dict[str, set[int]]:
        """When proxy/TUN is detected, discover hosts via ICMP and probe their ports."""
        import socket

        alive_ips: list[str] = self._icmp_sweep(host_ips)
        if not alive_ips:
            return {}

        open_ports_by_host: dict[str, set[int]] = {}

        def try_connect(ip: str, port: int) -> tuple[str, int, bool]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(max(self.timeout_seconds, 2.0))
                err = sock.connect_ex((ip, port))
                sock.close()
                return (ip, port, err == 0)
            except Exception:
                return (ip, port, False)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for ip in alive_ips:
                for port in ports:
                    futures.append(executor.submit(try_connect, ip, port))
            for future in as_completed(futures):
                try:
                    ip, port, is_open = future.result()
                    if is_open:
                        open_ports_by_host.setdefault(ip, set()).add(port)
                except Exception:
                    continue

        return open_ports_by_host

    def _verify_connect_results(self, open_ports_by_host: dict[str, set[int]]) -> dict[str, set[int]]:
        """Filter proxy/TUN false positives by verifying hosts respond to ICMP."""
        candidate_ips = list(open_ports_by_host.keys())
        alive_ips: set[str] = set()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._ping_once, ip): ip for ip in candidate_ips}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        alive_ips.add(ip)
                except Exception:
                    pass

        if not alive_ips:
            try:
                proc = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True, text=True, check=False,
                    **windows_hidden_process_kwargs(os.name, getattr(subprocess, "CREATE_NO_WINDOW", 0)),
                )
                candidate_set = set(candidate_ips)
                for line in proc.stdout.splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    ip_candidate = parts[0].strip()
                    if ip_candidate not in candidate_set:
                        continue
                    mac = parts[1].strip().replace("-", "").replace(":", "")
                    if len(mac) == 12 and mac.lower() != "ffffffffffff":
                        alive_ips.add(ip_candidate)
            except Exception:
                pass

        filtered = {ip: ports for ip, ports in open_ports_by_host.items() if ip in alive_ips}
        removed = len(open_ports_by_host) - len(filtered)
        if removed > 0:
            self._warn(f"TCP Connect 验证：过滤了 {removed} 个代理/TUN 误报，保留 {len(filtered)} 个真实主机")
        return filtered

    def _scan_host_syn_open_ports(self, ip: str, ports: list[int], iface: object | None = None) -> set[int]:
        scapy_all = self._load_scapy_all()
        IP = scapy_all.IP
        TCP = scapy_all.TCP
        send = scapy_all.send
        sr = scapy_all.sr

        if ":" in ip:
            return set()
        packet = IP(dst=ip) / TCP(dport=ports, flags="S")
        sr_kwargs: dict[str, object] = {
            "timeout": max(self.timeout_seconds, 3.0),
            "retry": 0,
            "verbose": False,
        }
        if iface is not None:
            sr_kwargs["iface"] = iface
        answered, _ = sr(packet, **sr_kwargs)
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

    def _resolve_iface_for_target(self, cidr: str) -> object | None:
        """Auto-detect the Scapy network interface whose IP falls in the target subnet."""
        try:
            target_net = ipaddress.ip_network(cidr, strict=False)
            from scapy.config import conf  # type: ignore[import-untyped]
            for iface_obj in conf.ifaces.values():
                ip_str = getattr(iface_obj, "ip", None)
                if not ip_str:
                    continue
                try:
                    if ipaddress.ip_address(ip_str) in target_net:
                        return iface_obj
                except ValueError:
                    continue
        except Exception:
            pass
        return None

    def _load_scapy_all(self) -> _ScapyAll:
        module: ModuleType = importlib.import_module("scapy.all")
        return cast(_ScapyAll, cast(object, module))

    def _has_raw_socket_permission(self) -> bool:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True

        if os.name != "posix":
            return True
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
