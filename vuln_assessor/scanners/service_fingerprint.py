# pyright: reportMissingImports=false, reportUnknownVariableType=false, reportUnknownParameterType=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false
from __future__ import annotations

import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import HostAsset, ServiceFingerprint

COMMON_PORT_SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    6379: "redis",
    8080: "http-proxy",
}


class ServiceFingerprintEngine:
    def __init__(self, timeout_seconds: float = 4.0, max_workers: int = 24) -> None:
        self.timeout_seconds: float = timeout_seconds
        self.max_workers: int = max_workers
        self.nmap_installed: bool = shutil.which("nmap") is not None

    def fingerprint(self, assets: list[HostAsset], fallback_ports: list[int]) -> list[ServiceFingerprint]:
        if not assets:
            return []
        if self.nmap_installed:
            return self._fingerprint_with_nmap(assets, fallback_ports)
        return self._fingerprint_with_socket(assets, fallback_ports)

    def _fingerprint_with_nmap(
        self,
        assets: list[HostAsset],
        fallback_ports: list[int],
    ) -> list[ServiceFingerprint]:
        fingerprints: list[ServiceFingerprint] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._scan_host_with_nmap, asset.ip, asset.open_ports or fallback_ports): asset.ip
                for asset in assets
            }
            for future in as_completed(futures):
                try:
                    fingerprints.extend(future.result())
                except Exception:
                    continue
        return self._dedupe(fingerprints)

    def _scan_host_with_nmap(self, ip: str, ports: list[int]) -> list[ServiceFingerprint]:
        if not ports:
            return []
        port_expression = ",".join(str(port) for port in sorted(set(ports)))
        scan_timeout_seconds = min(max(len(ports) * 8, 120), 900)
        command = [
            "nmap",
            "-sV",
            "-Pn",
            "--version-intensity",
            "5",
            "-p",
            port_expression,
            "-oX",
            "-",
            ip,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=scan_timeout_seconds,
            )
        except Exception:
            return []
        if result.returncode != 0 or not result.stdout.strip():
            return []

        try:
            xml_root = ET.fromstring(result.stdout)
        except ET.ParseError:
            return []

        host_address = ip
        host_address_node = xml_root.find("./host/address[@addrtype='ipv4']")
        if host_address_node is not None:
            host_address = host_address_node.attrib.get("addr", ip)

        fingerprints: list[ServiceFingerprint] = []
        for port_node in xml_root.findall(".//host/ports/port"):
            state_node = port_node.find("state")
            if state_node is None or state_node.attrib.get("state") != "open":
                continue
            service_node = port_node.find("service")
            service_name = "unknown"
            product = ""
            version = ""
            extra_info = ""
            fingerprint_method = ""
            fingerprint_confidence = 0.0
            if service_node is not None:
                service_name = service_node.attrib.get("name", "unknown")
                product = service_node.attrib.get("product", "")
                version = service_node.attrib.get("version", "")
                extra_info = service_node.attrib.get("extrainfo", "")
                
                method = service_node.attrib.get("method", "")
                fingerprint_method = str(method).strip().lower() if method else ""

                conf_raw = service_node.attrib.get("conf")
                if conf_raw is not None:
                    try:
                        conf_value = int(str(conf_raw).strip())
                    except (TypeError, ValueError):
                        conf_value = 0
                    if 1 <= conf_value <= 10:
                        fingerprint_confidence = float(conf_value)
                    else:
                        fingerprint_confidence = 0.0
                else:
                    fingerprint_confidence = 0.0
                if not version:
                    inferred_version = re.search(r"\d+(?:\.\d+){1,3}", f"{product} {extra_info}")
                    if inferred_version:
                        version = inferred_version.group(0)
            port = int(port_node.attrib.get("portid", "0"))
            protocol = port_node.attrib.get("protocol", "tcp")
            fingerprints.append(
                ServiceFingerprint(
                    host_ip=host_address,
                    port=port,
                    protocol=protocol,
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                    fingerprint_method=fingerprint_method,
                    fingerprint_confidence=fingerprint_confidence,
                )
            )
        return fingerprints

    def _fingerprint_with_socket(
        self,
        assets: list[HostAsset],
        fallback_ports: list[int],
    ) -> list[ServiceFingerprint]:
        fingerprints: list[ServiceFingerprint] = []
        for asset in assets:
            ports = sorted(set(asset.open_ports or fallback_ports))
            for port in ports:
                if not self._is_open(asset.ip, port):
                    continue
                service_name = COMMON_PORT_SERVICE_MAP.get(port, "unknown")
                banner = self._banner_grab(asset.ip, port)
                fingerprints.append(
                    ServiceFingerprint(
                        host_ip=asset.ip,
                        port=port,
                        protocol="tcp",
                        service_name=service_name,
                        product="",
                        version="",
                        extra_info=banner,
                        fingerprint_method="socket",
                        fingerprint_confidence=2.0,
                    )
                )
        return self._dedupe(fingerprints)

    def _dedupe(self, fingerprints: list[ServiceFingerprint]) -> list[ServiceFingerprint]:
        unique: dict[tuple[str, int, str], ServiceFingerprint] = {}
        for item in fingerprints:
            key = (item.host_ip, item.port, item.protocol)
            unique[key] = item
        return sorted(unique.values(), key=lambda item: (item.host_ip, item.port))

    def _is_open(self, ip: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(self.timeout_seconds)
            try:
                return client.connect_ex((ip, port)) == 0
            except Exception:
                return False

    def _banner_grab(self, ip: str, port: int) -> str:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout_seconds) as client:
                if port in {80, 8080}:
                    client.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = client.recv(240)
            return data.decode("utf-8", errors="ignore").replace("\r", " ").replace("\n", " ").strip()
        except Exception:
            return ""
