from __future__ import annotations

# pyright: reportMissingTypeArgument=false, reportUnknownParameterType=false

import json
import re
from pathlib import Path
from typing import cast

from ..models import ServiceFingerprint, VulnerabilityFinding


HIGH_CONFIDENCE_THRESHOLD = 7.5
MEDIUM_CONFIDENCE_THRESHOLD = 5.0
VERSION_MISSING_MAX_CONFIDENCE = 4.5


class VulnerabilityMatcher:
    rule_file_path: Path
    rules: list[dict[str, object]]

    def __init__(self, rule_file_path: Path) -> None:
        self.rule_file_path = rule_file_path
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, object]]:
        if not self.rule_file_path.exists():
            return []
        with self.rule_file_path.open("r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        if not isinstance(payload, list):
            return []
        return [cast(dict[str, object], item) for item in payload if isinstance(item, dict)]

    def match(self, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
        for service in services:
            for rule in self.rules:
                if not self._service_matches(service, rule):
                    continue
                version_rule = str(rule.get("version_rule", "*"))
                version_missing_with_non_wildcard_rule = self._is_version_missing_with_non_wildcard_rule(
                    service.version,
                    version_rule,
                )
                if not version_missing_with_non_wildcard_rule and not self._version_matches(service.version, version_rule):
                    continue
                match_confidence = self._calculate_match_confidence(service, rule, version_rule)
                confidence_tier = self._to_confidence_tier(match_confidence)
                manual_confirmation_needed = False
                confidence_reason = ""
                if version_missing_with_non_wildcard_rule:
                    match_confidence = min(match_confidence, VERSION_MISSING_MAX_CONFIDENCE)
                    confidence_tier = "LOW"
                    manual_confirmation_needed = True
                    confidence_reason = "version missing: matched by service/product/port only"
                findings.append(
                    VulnerabilityFinding(
                        host_ip=service.host_ip,
                        port=service.port,
                        service_name=service.service_name,
                        product=service.product,
                        version=service.version,
                        cve_id=str(rule.get("cve_id", "UNKNOWN")),
                        severity=str(rule.get("severity", "LOW")).upper(),
                        cvss=self._normalize_score(rule.get("cvss"), default=0.0),
                        description=str(rule.get("description", "")),
                        remediation=str(rule.get("remediation", "")),
                        exploit_maturity=self._normalize_score(
                            rule.get("exploit_maturity"),
                            default=self._default_exploit_maturity(str(rule.get("severity", "MEDIUM"))),
                        ),
                        match_confidence=match_confidence,
                        confidence_tier=confidence_tier,
                        manual_confirmation_needed=manual_confirmation_needed,
                        confidence_reason=confidence_reason,
                        asset_criticality=self._normalize_score(rule.get("asset_criticality"), default=5.0),
                    )
                )
        return sorted(findings, key=lambda item: item.cvss, reverse=True)

    def _service_matches(self, service: ServiceFingerprint, rule: dict) -> bool:
        rule_service = str(rule.get("service", "")).strip().lower()
        rule_product = str(rule.get("product", "")).strip().lower()
        detected_service = service.service_name.lower()
        detected_product = service.product.lower()

        if rule_service and rule_service not in detected_service:
            return False
        if rule_product and rule_product not in detected_product:
            return False
        if not rule_service and not rule_product:
            return False

        rule_port = rule.get("port")
        if rule_port is None:
            return True
        try:
            return int(rule_port) == int(service.port)
        except (TypeError, ValueError):
            return True

    def _version_matches(self, discovered_version: str, version_rule: str) -> bool:
        version_rule = version_rule.strip()
        if version_rule in {"", "*"}:
            return True

        discovered_tuple = self._to_version_tuple(discovered_version)
        if not discovered_tuple:
            return False

        compact_rule = version_rule.replace(" ", "")
        if "-" in compact_rule and not re.search(r"[<>]=?|==", compact_rule):
            start_raw, end_raw = compact_rule.split("-", 1)
            start_tuple = self._to_version_tuple(start_raw)
            end_tuple = self._to_version_tuple(end_raw)
            if start_tuple and self._compare_tuple(discovered_tuple, start_tuple) < 0:
                return False
            if end_tuple and self._compare_tuple(discovered_tuple, end_tuple) > 0:
                return False
            return True

        for condition in compact_rule.split(","):
            if not condition:
                continue
            matched = re.match(r"(<=|>=|<|>|==)([0-9][0-9.]*)", condition)
            if not matched:
                return False
            operator, version_raw = matched.groups()
            condition_tuple = self._to_version_tuple(version_raw)
            if not condition_tuple:
                return False
            comparison = self._compare_tuple(discovered_tuple, condition_tuple)
            if operator == "<" and not (comparison < 0):
                return False
            if operator == "<=" and not (comparison <= 0):
                return False
            if operator == ">" and not (comparison > 0):
                return False
            if operator == ">=" and not (comparison >= 0):
                return False
            if operator == "==" and not (comparison == 0):
                return False
        return True

    def _is_version_missing_with_non_wildcard_rule(self, discovered_version: str, version_rule: str) -> bool:
        return not discovered_version.strip() and version_rule.strip() not in {"", "*"}

    def _calculate_match_confidence(self, service: ServiceFingerprint, rule: dict, version_rule: str) -> float:
        score = 3.0
        detected_service = service.service_name.lower()
        detected_product = service.product.lower()

        rule_service = str(rule.get("service", "")).strip().lower()
        rule_product = str(rule.get("product", "")).strip().lower()

        if rule_service and rule_service in detected_service:
            score += 2.0
            if rule_service == detected_service:
                score += 1.0
        if rule_product and rule_product in detected_product:
            score += 2.0
            if rule_product == detected_product:
                score += 0.5
        if service.version:
            score += 1.0
        if version_rule.strip() not in {"", "*"} and service.version:
            score += 0.5
        if service.extra_info:
            score += 0.5
        return self._normalize_score(score, default=5.0)

    def _default_exploit_maturity(self, severity: str) -> float:
        severity = severity.upper()
        if severity == "CRITICAL":
            return 9.0
        if severity == "HIGH":
            return 8.0
        if severity == "MEDIUM":
            return 6.0
        if severity == "LOW":
            return 3.5
        return 5.0

    def _normalize_score(self, raw_value: object, default: float) -> float:
        if raw_value is None:
            return default
        try:
            if isinstance(raw_value, (int, float, str)):
                value = float(raw_value)
            else:
                return default
        except (TypeError, ValueError):
            return default
        return max(0.0, min(value, 10.0))

    def _to_version_tuple(self, raw_version: str) -> tuple[int, ...]:
        numbers = [int(item) for item in re.findall(r"\d+", raw_version)]
        return tuple(numbers[:4])

    def _compare_tuple(self, left: tuple[int, ...], right: tuple[int, ...]) -> int:
        max_length = max(len(left), len(right))
        normalized_left = left + (0,) * (max_length - len(left))
        normalized_right = right + (0,) * (max_length - len(right))
        if normalized_left == normalized_right:
            return 0
        return 1 if normalized_left > normalized_right else -1

    def _to_confidence_tier(self, match_confidence: float) -> str:
        if match_confidence >= HIGH_CONFIDENCE_THRESHOLD:
            return "HIGH"
        if match_confidence >= MEDIUM_CONFIDENCE_THRESHOLD:
            return "MEDIUM"
        return "LOW"
