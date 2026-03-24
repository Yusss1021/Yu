# pyright: reportMissingImports=false, reportUnknownVariableType=false

import unittest

from vuln_assessor.config import parse_ports


class TestParsePorts(unittest.TestCase):
    def test_parse_ports_csv(self) -> None:
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_parse_ports_range(self) -> None:
        self.assertEqual(parse_ports("1-3"), [1, 2, 3])

    def test_parse_ports_invalid_zero(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_parse_ports_invalid_too_large(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("70000")

    def test_parse_ports_invalid_token(self) -> None:
        with self.assertRaises(ValueError):
            parse_ports("a")
