# pyright: reportMissingImports=false

from __future__ import annotations

import json
import unittest
from pathlib import Path


class TestRuleInventory(unittest.TestCase):
    def test_rule_inventory_has_expected_scale_and_unique_keys(self) -> None:
        rule_path = (
            Path(__file__).resolve().parent.parent
            / "vuln_assessor"
            / "vuln"
            / "rules.json"
        )
        payload = json.loads(rule_path.read_text(encoding="utf-8"))

        self.assertIsInstance(payload, list)
        self.assertGreaterEqual(len(payload), 45)
        self.assertLessEqual(len(payload), 50)

        seen_keys: set[tuple[str, str, str, str, str]] = set()
        for item in payload:
            self.assertIsInstance(item, dict)
            key = (
                str(item.get("cve_id", "")),
                str(item.get("service", "")),
                str(item.get("product", "")),
                str(item.get("version_rule", "")),
                "" if item.get("port") is None else str(item.get("port")),
            )
            self.assertNotIn(key, seen_keys)
            seen_keys.add(key)

            self.assertIn(str(item.get("severity", "")).upper(), {"CRITICAL", "HIGH", "MEDIUM", "LOW"})

