from __future__ import annotations

from dataclasses import asdict

from ..models import RiskFinding, VulnerabilityFinding


def _confirmation_recommendation_from_tier(tier: str) -> str:
    normalized = (tier or "").strip().upper()
    if normalized == "LOW":
        return "必须手动确认"
    if normalized == "HIGH":
        return "无需手动确认"
    return "建议手动确认"

SERVICE_CRITICALITY_BASE = {
    "mysql": 9.0,
    "postgresql": 9.0,
    "redis": 8.5,
    "microsoft-ds": 9.0,
    "ms-wbt-server": 8.5,
    "ssh": 8.0,
    "ftp": 6.0,
    "http": 6.0,
    "https": 6.5,
    "http-proxy": 6.0,
}

PORT_EXPOSURE = {
    22: 8.0,
    80: 6.0,
    443: 6.5,
    445: 9.5,
    3306: 9.0,
    3389: 9.0,
    5432: 9.0,
    6379: 8.5,
}

DEFAULT_EXPLOIT_MATURITY = {
    "CRITICAL": 9.0,
    "HIGH": 8.0,
    "MEDIUM": 6.0,
    "LOW": 3.5,
}


class RiskEvaluator:
    def __init__(
        self,
        asset_criticality_map: dict[str, float] | None = None,
        default_asset_criticality: float = 5.0,
    ) -> None:
        self.asset_criticality_map = asset_criticality_map or {}
        self.default_asset_criticality = self._clamp(default_asset_criticality)

    def evaluate(self, vulnerabilities: list[VulnerabilityFinding]) -> list[RiskFinding]:
        risk_findings: list[RiskFinding] = []
        for vulnerability in vulnerabilities:
            asset_criticality = self._resolve_asset_criticality(vulnerability)
            exploit_maturity = self._resolve_exploit_maturity(vulnerability)
            match_confidence = self._clamp(vulnerability.match_confidence)
            score = self._calculate_score(
                vulnerability.cvss,
                asset_criticality,
                vulnerability.port,
                exploit_maturity,
                match_confidence,
            )
            level = self._to_level(score)
            payload = asdict(vulnerability)
            payload["asset_criticality"] = asset_criticality
            payload["exploit_maturity"] = exploit_maturity
            payload["match_confidence"] = match_confidence

            tier = str(payload.get("confidence_tier") or vulnerability.confidence_tier or "MEDIUM")
            tier_normalized = tier.strip().upper()
            if tier_normalized not in {"HIGH", "MEDIUM", "LOW"}:
                tier_normalized = "MEDIUM"
            payload.setdefault("risk_confidence_tier", tier_normalized)
            payload.setdefault("confirmation_recommendation", _confirmation_recommendation_from_tier(tier_normalized))
            if tier_normalized == "LOW":
                payload.setdefault("risk_note", "风险评分基于不完整指纹，需人工确认漏洞/版本")
            risk_findings.append(
                RiskFinding(
                    **payload,
                    risk_score=score,
                    risk_level=level,
                )
            )
        return sorted(risk_findings, key=lambda item: item.risk_score, reverse=True)

    def _calculate_score(
        self,
        cvss: float,
        asset_criticality: float,
        port: int,
        exploit_maturity: float,
        match_confidence: float,
    ) -> float:
        exposure = self._clamp(PORT_EXPOSURE.get(port, 5.0))
        score = (
            self._clamp(cvss) * 0.45
            + self._clamp(asset_criticality) * 0.20
            + exposure * 0.15
            + self._clamp(exploit_maturity) * 0.10
            + self._clamp(match_confidence) * 0.10
        )
        return round(min(score, 10.0), 2)

    def _resolve_asset_criticality(self, vulnerability: VulnerabilityFinding) -> float:
        if vulnerability.host_ip in self.asset_criticality_map:
            return self._clamp(self.asset_criticality_map[vulnerability.host_ip])
        if vulnerability.asset_criticality != 5.0:
            return self._clamp(vulnerability.asset_criticality)
        return self._clamp(
            SERVICE_CRITICALITY_BASE.get(vulnerability.service_name.lower(), self.default_asset_criticality)
        )

    def _resolve_exploit_maturity(self, vulnerability: VulnerabilityFinding) -> float:
        if vulnerability.exploit_maturity != 5.0:
            return self._clamp(vulnerability.exploit_maturity)
        return self._clamp(DEFAULT_EXPLOIT_MATURITY.get(vulnerability.severity.upper(), 5.0))

    def _to_level(self, score: float) -> str:
        if score >= 8.0:
            return "HIGH"
        if score >= 5.0:
            return "MEDIUM"
        return "LOW"

    def _clamp(self, value: float) -> float:
        return max(0.0, min(float(value), 10.0))
