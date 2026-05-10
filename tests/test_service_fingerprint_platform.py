# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vuln_assessor.scanners.service_fingerprint import ServiceFingerprintEngine


class TestServiceFingerprintPlatform(unittest.TestCase):
    def test_nmap_scan_hides_windows_console(self) -> None:
        engine = ServiceFingerprintEngine()
        xml_output = "<nmaprun><host><address addr='127.0.0.1' addrtype='ipv4'/><ports /></host></nmaprun>"

        with patch("vuln_assessor.scanners.service_fingerprint.os.name", "nt"):
            with patch(
                "vuln_assessor.scanners.service_fingerprint.subprocess.CREATE_NO_WINDOW",
                0x08000000,
                create=True,
            ):
                with patch(
                    "vuln_assessor.scanners.service_fingerprint.subprocess.run",
                    return_value=SimpleNamespace(returncode=0, stdout=xml_output),
                ) as run:
                    self.assertEqual(engine._scan_host_with_nmap("127.0.0.1", [80]), [])

        self.assertEqual(run.call_args.kwargs.get("creationflags"), 0x08000000)
