# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import builtins
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vuln_assessor.scanners.discovery import AssetDiscoveryEngine


class _PacketLayer:
    def __truediv__(self, other: object) -> "_PacketLayer":
        _ = other
        return self


class TestDiscoveryPlatform(unittest.TestCase):
    def test_ping_once_uses_windows_flags(self) -> None:
        engine = AssetDiscoveryEngine(timeout_seconds=2.0)

        with patch("vuln_assessor.scanners.discovery.shutil.which", return_value="ping"):
            with patch("vuln_assessor.scanners.discovery.os.name", "nt"):
                with patch(
                    "vuln_assessor.scanners.discovery.subprocess.run",
                    return_value=SimpleNamespace(returncode=0),
                ) as run:
                    self.assertTrue(engine._ping_once("192.168.10.8"))

        self.assertEqual(run.call_args.args[0], ["ping", "-n", "1", "-w", "2000", "192.168.10.8"])

    def test_ping_once_hides_windows_console(self) -> None:
        engine = AssetDiscoveryEngine(timeout_seconds=2.0)

        with patch("vuln_assessor.scanners.discovery.shutil.which", return_value="ping"):
            with patch("vuln_assessor.scanners.discovery.os.name", "nt"):
                with patch(
                    "vuln_assessor.scanners.discovery.subprocess.CREATE_NO_WINDOW",
                    0x08000000,
                    create=True,
                ):
                    with patch(
                        "vuln_assessor.scanners.discovery.subprocess.run",
                        return_value=SimpleNamespace(returncode=0),
                    ) as run:
                        self.assertTrue(engine._ping_once("192.168.10.8"))

        self.assertEqual(run.call_args.kwargs.get("creationflags"), 0x08000000)

    def test_syn_readiness_does_not_pre_reject_windows(self) -> None:
        engine = AssetDiscoveryEngine()

        with patch("vuln_assessor.scanners.discovery.os.name", "nt"):
            with patch.object(engine, "_load_scapy_all", return_value=object()):
                engine._ensure_syn_ready()

    def test_arp_sweep_adapter_error_degrades_gracefully(self) -> None:
        engine = AssetDiscoveryEngine()
        fake_scapy = SimpleNamespace(
            Ether=lambda **kwargs: _PacketLayer(),
            ARP=lambda **kwargs: _PacketLayer(),
            srp=lambda *args, **kwargs: (_ for _ in ()).throw(OSError("adapter failure")),
        )

        with patch.object(engine, "_load_scapy_all", return_value=fake_scapy):
            with patch("vuln_assessor.scanners.discovery.os.geteuid", return_value=0, create=True):
                result = engine._arp_sweep("127.0.0.1/32")

        self.assertEqual(result, {})

    def test_discover_accepts_single_and_pairwise_method_combinations(self) -> None:
        engine = AssetDiscoveryEngine()
        combinations = [
            ["icmp"],
            ["arp"],
            ["syn"],
            ["icmp", "arp"],
            ["icmp", "syn"],
            ["arp", "syn"],
        ]

        with patch.object(engine, "_icmp_sweep", return_value=[]):
            with patch.object(engine, "_arp_sweep", return_value={}):
                with patch.object(engine, "_ensure_syn_ready", side_effect=PermissionError("no raw socket")):
                    with patch.object(engine, "_syn_sweep", return_value={}):
                        for methods in combinations:
                            result = engine.discover("127.0.0.1/32", [22], methods)
                            self.assertEqual(result, [])

    def test_warn_falls_back_when_console_encoding_rejects_message(self) -> None:
        engine = AssetDiscoveryEngine()
        captured: list[str] = []
        call_count = {"value": 0}

        def fake_print(message: str) -> None:
            call_count["value"] += 1
            if call_count["value"] == 1:
                raise UnicodeEncodeError("gbk", "警告\ufffd", 0, 1, "illegal multibyte sequence")
            captured.append(message)

        with patch.object(builtins, "print", side_effect=fake_print):
            engine._warn("警告\ufffd")

        self.assertEqual(captured, ["警告\\ufffd"])
