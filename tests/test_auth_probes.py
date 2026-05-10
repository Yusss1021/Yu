# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import socketserver
import threading
import unittest

from vuln_assessor.auth_probes import WeakCredentialHit, WeakCredentialProbeEngine


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class _WeakFtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write(b"220 weak ftp\r\n")
        current_user = ""
        while True:
            line = self.rfile.readline()
            if not line:
                return
            command = line.decode("utf-8", errors="ignore").strip()
            upper = command.upper()
            if upper.startswith("USER "):
                current_user = command[5:]
                self.wfile.write(b"331 password required\r\n")
                continue
            if upper.startswith("PASS "):
                password = command[5:]
                if current_user == "admin" and password == "admin":
                    self.wfile.write(b"230 login successful\r\n")
                    continue
                self.wfile.write(b"530 login incorrect\r\n")
                continue
            if upper.startswith("QUIT"):
                self.wfile.write(b"221 bye\r\n")
                return
            self.wfile.write(b"200 ok\r\n")


class TestWeakCredentialProbeEngine(unittest.TestCase):
    def test_probe_ftp_returns_common_weak_credential_hit(self) -> None:
        with _ThreadedTCPServer(("127.0.0.1", 0), _WeakFtpHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                engine = WeakCredentialProbeEngine(timeout_seconds=1.0)
                hit = engine.probe_ftp("127.0.0.1", int(server.server_address[1]))
            finally:
                server.shutdown()
                thread.join(timeout=1.0)

        self.assertIsNotNone(hit)
        self.assertEqual(hit, WeakCredentialHit(username="admin", password="admin"))

    def test_probe_ssh_uses_stub_connector(self) -> None:
        engine = WeakCredentialProbeEngine(
            timeout_seconds=1.0,
            ssh_probe=lambda _host, _port, username, password, _timeout: username == "root" and password == "toor",
        )

        hit = engine.probe_ssh("127.0.0.1", 22)

        self.assertEqual(hit, WeakCredentialHit(username="root", password="toor"))

    def test_probe_mysql_uses_stub_connector(self) -> None:
        engine = WeakCredentialProbeEngine(
            timeout_seconds=1.0,
            mysql_probe=lambda _host, _port, username, password, _timeout: username == "root" and password == "",
        )

        hit = engine.probe_mysql("127.0.0.1", 3306)

        self.assertEqual(hit, WeakCredentialHit(username="root", password=""))
