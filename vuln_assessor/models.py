from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HostAsset:
    ip: str
    mac: str = ""
    discovered_by: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)


@dataclass
class ServiceFingerprint:
    host_ip: str
    port: int
    protocol: str
    service_name: str
    product: str = ""
    version: str = ""
    extra_info: str = ""
    fingerprint_method: str = ""
    fingerprint_confidence: float = 0.0


@dataclass
class VulnerabilityFinding:
    host_ip: str
    port: int
    service_name: str
    product: str
    version: str
    cve_id: str
    severity: str
    cvss: float
    description: str
    remediation: str
    exploit_maturity: float = 5.0
    match_confidence: float = 5.0
    confidence_tier: str = "MEDIUM"
    manual_confirmation_needed: bool = False
    confidence_reason: str = ""
    asset_criticality: float = 5.0


@dataclass
class RiskFinding(VulnerabilityFinding):
    risk_score: float = 0.0
    risk_level: str = "LOW"

    risk_confidence_tier: str = ""
    risk_note: str = ""
    confirmation_recommendation: str = ""

    def __post_init__(self) -> None:
        tier = (self.risk_confidence_tier or self.confidence_tier or "MEDIUM").strip().upper()
        if tier not in {"HIGH", "MEDIUM", "LOW"}:
            tier = "MEDIUM"
        self.risk_confidence_tier = tier

        if not self.confirmation_recommendation:
            if tier == "LOW":
                self.confirmation_recommendation = "必须手动确认"
            elif tier == "HIGH":
                self.confirmation_recommendation = "无需手动确认"
            else:
                self.confirmation_recommendation = "建议手动确认"

        if tier == "LOW" and not self.risk_note:
            self.risk_note = "风险评分基于不完整指纹，需人工确认漏洞/版本"
