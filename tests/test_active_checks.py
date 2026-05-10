# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import socket
import socketserver
import threading
import unittest
from contextlib import closing

from vuln_assessor.active_checks import ActiveCheckEngine
from vuln_assessor.auth_probes import WeakCredentialHit
from vuln_assessor.models import HostAsset, ServiceFingerprint


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class _MockFTPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(b"220 mock ftp\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("utf-8", errors="ignore").strip().upper()
            if command.startswith("USER"):
                self.wfile.write(b"331 password required\r\n")
                continue
            if command.startswith("PASS"):
                self.wfile.write(b"230 login successful\r\n")
                continue
            if command.startswith("QUIT"):
                self.wfile.write(b"221 bye\r\n")
                return
            self.wfile.write(b"200 ok\r\n")


class _MockRedisHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            if b"PING" in data.upper():
                self.request.sendall(b"+PONG\r\n")
                continue
            if b"INFO" in data.upper():
                payload = b"# Server\r\nredis_version:6.2.7\r\n"
                response = b"$%d\r\n%b\r\n" % (len(payload), payload)
                self.request.sendall(response)
                continue
            self.request.sendall(b"-ERR unknown command\r\n")


class _MockSnmpServer:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = int(self.socket.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._running = True
        self._thread.start()

    def close(self) -> None:
        self._running = False
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client:
            client.sendto(b"stop", ("127.0.0.1", self.port))
        self._thread.join(timeout=1.0)
        self.socket.close()

    def _serve(self) -> None:
        while self._running:
            try:
                data, address = self.socket.recvfrom(1024)
            except OSError:
                return
            if not self._running:
                return
            if b"public" in data:
                self.socket.sendto(b"\x30\x10\x02\x01\x00\x04\x06public\xa2\x03\x02\x01\x00", address)


class _StubWeakCredentialProbeEngine:
    def probe_ftp(self, host_ip: str, port: int) -> WeakCredentialHit | None:
        _ = (host_ip, port)
        return None

    def probe_ssh(self, host_ip: str, port: int) -> WeakCredentialHit | None:
        _ = (host_ip, port)
        return WeakCredentialHit(username="root", password="toor")

    def probe_mysql(self, host_ip: str, port: int) -> WeakCredentialHit | None:
        _ = (host_ip, port)
        return None


class TestActiveCheckEngine(unittest.TestCase):
    def test_detects_ftp_anonymous_login(self) -> None:
        with _ThreadedTCPServer(("127.0.0.1", 0), _MockFTPHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = int(server.server_address[1])
                engine = ActiveCheckEngine(timeout_seconds=1.0)
                findings = engine.run(
                    assets=[HostAsset(ip="127.0.0.1", open_ports=[port])],
                    services=[
                        ServiceFingerprint(
                            host_ip="127.0.0.1",
                            port=port,
                            protocol="tcp",
                            service_name="ftp",
                            product="mockftp",
                        )
                    ],
                    fallback_ports=[port],
                )
            finally:
                server.shutdown()
                thread.join(timeout=1.0)

        self.assertIn("CFG-FTP-ANON-0001", {item.cve_id for item in findings})

    def test_detects_redis_unauthenticated_access(self) -> None:
        with _ThreadedTCPServer(("127.0.0.1", 0), _MockRedisHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = int(server.server_address[1])
                engine = ActiveCheckEngine(timeout_seconds=1.0)
                findings = engine.run(
                    assets=[HostAsset(ip="127.0.0.1", open_ports=[port])],
                    services=[
                        ServiceFingerprint(
                            host_ip="127.0.0.1",
                            port=port,
                            protocol="tcp",
                            service_name="redis",
                            product="redis",
                        )
                    ],
                    fallback_ports=[port],
                )
            finally:
                server.shutdown()
                thread.join(timeout=1.0)

        self.assertIn("CFG-REDIS-UNAUTH-0001", {item.cve_id for item in findings})

    def test_flags_telnet_service_as_insecure(self) -> None:
        engine = ActiveCheckEngine(timeout_seconds=1.0)
        findings = engine.run(
            assets=[HostAsset(ip="127.0.0.1", open_ports=[23])],
            services=[
                ServiceFingerprint(
                    host_ip="127.0.0.1",
                    port=23,
                    protocol="tcp",
                    service_name="telnet",
                )
            ],
            fallback_ports=[23],
        )

        self.assertIn("CFG-TELNET-OPEN-0001", {item.cve_id for item in findings})

    def test_detects_snmp_public_community(self) -> None:
        server = _MockSnmpServer()
        try:
            engine = ActiveCheckEngine(timeout_seconds=1.0)
            findings = engine.run(
                assets=[HostAsset(ip="127.0.0.1", open_ports=[server.port])],
                services=[
                    ServiceFingerprint(
                        host_ip="127.0.0.1",
                        port=server.port,
                        protocol="udp",
                        service_name="snmp",
                    )
                ],
                fallback_ports=[server.port],
            )
        finally:
            server.close()

        self.assertIn("CFG-SNMP-DEFAULT-0001", {item.cve_id for item in findings})

    def test_weak_auth_findings_require_explicit_enablement(self) -> None:
        engine = ActiveCheckEngine(
            timeout_seconds=1.0,
            credential_probe_engine=_StubWeakCredentialProbeEngine(),
        )
        services = [
            ServiceFingerprint(
                host_ip="127.0.0.1",
                port=22,
                protocol="tcp",
                service_name="ssh",
                product="OpenSSH",
            )
        ]

        disabled_findings = engine.run(
            assets=[HostAsset(ip="127.0.0.1", open_ports=[22])],
            services=services,
            fallback_ports=[22],
            enable_auth_checks=False,
        )
        enabled_findings = engine.run(
            assets=[HostAsset(ip="127.0.0.1", open_ports=[22])],
            services=services,
            fallback_ports=[22],
            enable_auth_checks=True,
        )

        self.assertNotIn("CFG-SSH-WEAK-PASSWORD-0001", {item.cve_id for item in disabled_findings})
        self.assertIn("CFG-SSH-WEAK-PASSWORD-0001", {item.cve_id for item in enabled_findings})
