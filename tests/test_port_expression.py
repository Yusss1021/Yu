# pyright: reportMissingImports=false, reportUnknownVariableType=false

from __future__ import annotations

import unittest

from vuln_assessor.port_expression import append_port_expression, build_port_range_expression


class TestPortExpression(unittest.TestCase):
    def test_build_port_range_expression_supports_reversed_bounds(self) -> None:
        self.assertEqual(build_port_range_expression("1024", "1"), "1-1024")

    def test_append_port_expression_preserves_compact_range_tokens(self) -> None:
        self.assertEqual(append_port_expression("22,80", "1-1024"), "22,80,1-1024")

    def test_append_port_expression_avoids_duplicate_token(self) -> None:
        self.assertEqual(append_port_expression("22,80,1-1024", "1-1024"), "22,80,1-1024")
