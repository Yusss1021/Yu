from __future__ import annotations

import json
import urllib.request
from pathlib import Path


class VulnerabilityRuleManager:
    def __init__(self, rule_file_path: Path) -> None:
        self.rule_file_path = rule_file_path

    def load_rules(self) -> list[dict]:
        if not self.rule_file_path.exists():
            return []
        with self.rule_file_path.open("r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        if not isinstance(payload, list):
            return []
        normalized: list[dict] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            normalized_item = self._normalize_rule(item)
            if normalized_item:
                normalized.append(normalized_item)
        return normalized

    def import_from_file(self, input_file: Path, mode: str = "merge") -> dict:
        if not input_file.exists():
            raise FileNotFoundError(f"rule file not found: {input_file}")
        with input_file.open("r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        return self._merge_payload(payload, mode=mode, source=f"file:{input_file}")

    def update_from_url(self, source_url: str, mode: str = "merge", timeout_seconds: int = 20) -> dict:
        request = urllib.request.Request(source_url, headers={"User-Agent": "intra-vuln-assessor/0.1"})
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            content = response.read().decode("utf-8")
        payload = json.loads(content)
        return self._merge_payload(payload, mode=mode, source=f"url:{source_url}")

    def summary(self) -> dict:
        rules = self.load_rules()
        severity_count: dict[str, int] = {}
        for item in rules:
            severity = str(item.get("severity", "UNKNOWN"))
            severity_count[severity] = severity_count.get(severity, 0) + 1
        return {"total": len(rules), "severity_count": dict(sorted(severity_count.items()))}

    def _merge_payload(self, payload: object, mode: str, source: str) -> dict:
        if mode not in {"merge", "replace"}:
            raise ValueError("mode must be merge or replace")
        if not isinstance(payload, list):
            raise ValueError("input payload must be a JSON list")

        normalized: list[dict] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            normalized_item = self._normalize_rule(item)
            if normalized_item:
                normalized.append(normalized_item)

        incoming = self._dedupe_rules(normalized)
        existing = self.load_rules()
        if mode == "replace":
            final_rules = incoming
            added_count = len(final_rules)
            updated_count = 0
        else:
            final_rules, added_count, updated_count = self._merge_rules(existing, incoming)

        self._save_rules(final_rules)
        return {
            "source": source,
            "mode": mode,
            "incoming_count": len(payload),
            "valid_count": len(normalized),
            "stored_count": len(final_rules),
            "added_count": added_count,
            "updated_count": updated_count,
            "rule_file": str(self.rule_file_path),
        }

    def _merge_rules(self, existing: list[dict], incoming: list[dict]) -> tuple[list[dict], int, int]:
        merged = {self._rule_key(item): item for item in existing}
        added_count = 0
        updated_count = 0
        for item in incoming:
            key = self._rule_key(item)
            if key in merged:
                updated_count += 1
            else:
                added_count += 1
            merged[key] = item
        final_rules = sorted(merged.values(), key=lambda item: (item["cve_id"], item["service"], item["product"]))
        return final_rules, added_count, updated_count

    def _dedupe_rules(self, rules: list[dict]) -> list[dict]:
        mapping = {self._rule_key(item): item for item in rules}
        return sorted(mapping.values(), key=lambda item: (item["cve_id"], item["service"], item["product"]))

    def _rule_key(self, rule: dict) -> tuple[str, str, str, str, str]:
        port_text = "" if rule.get("port") is None else str(rule.get("port"))
        return (
            str(rule.get("cve_id", "")),
            str(rule.get("service", "")),
            str(rule.get("product", "")),
            str(rule.get("version_rule", "")),
            port_text,
        )

    def _normalize_rule(self, rule: dict) -> dict | None:
        cve_id = str(rule.get("cve_id", "")).strip().upper()
        service = str(rule.get("service", "")).strip().lower()
        product = str(rule.get("product", "")).strip().lower()
        if not cve_id:
            return None
        if not service and not product:
            return None

        severity = str(rule.get("severity", "MEDIUM")).strip().upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            severity = "MEDIUM"

        try:
            cvss = float(rule.get("cvss", 0.0))
        except (TypeError, ValueError):
            cvss = 0.0
        cvss = max(0.0, min(cvss, 10.0))

        port = rule.get("port")
        if port is not None:
            try:
                port = int(port)
            except (TypeError, ValueError):
                port = None

        exploit_maturity = self._score_or_default(rule.get("exploit_maturity"), self._severity_to_exploit(severity))
        asset_criticality = self._score_or_default(rule.get("asset_criticality"), 5.0)

        return {
            "cve_id": cve_id,
            "service": service,
            "product": product,
            "version_rule": str(rule.get("version_rule", "*")).strip() or "*",
            "port": port,
            "severity": severity,
            "cvss": round(cvss, 1),
            "description": str(rule.get("description", "")).strip(),
            "remediation": str(rule.get("remediation", "")).strip(),
            "exploit_maturity": exploit_maturity,
            "asset_criticality": asset_criticality,
        }

    def _severity_to_exploit(self, severity: str) -> float:
        mapping = {"CRITICAL": 9.0, "HIGH": 8.0, "MEDIUM": 6.0, "LOW": 3.5}
        return mapping.get(severity.upper(), 5.0)

    def _score_or_default(self, raw_value: object, default: float) -> float:
        try:
            score = float(raw_value)
        except (TypeError, ValueError):
            score = default
        return max(0.0, min(round(score, 2), 10.0))

    def _save_rules(self, rules: list[dict]) -> None:
        self.rule_file_path.parent.mkdir(parents=True, exist_ok=True)
        with self.rule_file_path.open("w", encoding="utf-8") as file_obj:
            json.dump(rules, file_obj, indent=2, ensure_ascii=False)
            file_obj.write("\n")
