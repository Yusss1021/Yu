# pyright: reportMissingImports=false, reportUnknownVariableType=false

import unittest

from vuln_assessor.vuln.matcher import HIGH_CONFIDENCE_THRESHOLD, MEDIUM_CONFIDENCE_THRESHOLD


def _to_tier(score: float) -> str:
    if score >= HIGH_CONFIDENCE_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_CONFIDENCE_THRESHOLD:
        return "MEDIUM"
    return "LOW"


class TestConfidenceTiers(unittest.TestCase):
    def test_confidence_tier_boundaries(self) -> None:
        self.assertEqual(_to_tier(7.5), "HIGH")
        self.assertEqual(_to_tier(7.49), "MEDIUM")
        self.assertEqual(_to_tier(5.0), "MEDIUM")
        self.assertEqual(_to_tier(4.99), "LOW")
