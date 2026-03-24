from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

from .config import RULE_FILE_PATH
from .models import HostAsset, RiskFinding, ServiceFingerprint, VulnerabilityFinding
from .report import HtmlReportGenerator
from .risk import RiskEvaluator
from .scanners import AssetDiscoveryEngine
from .scanners.service_fingerprint import ServiceFingerprintEngine
from .storage import ScanRepository
from .vuln import VulnerabilityMatcher


class _ServiceFingerprintEngine(Protocol):
    def fingerprint(self, assets: list[HostAsset], fallback_ports: list[int]) -> list[ServiceFingerprint]:
        ...


class _VulnerabilityMatcher(Protocol):
    def match(self, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        ...


class _RiskEvaluator(Protocol):
    def evaluate(self, vulnerabilities: list[VulnerabilityFinding]) -> list[RiskFinding]:
        ...


class _ReportGenerator(Protocol):
    def generate(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        risks: list[RiskFinding],
        output_dir: Path,
        scan_name: str = "",
    ) -> str:
        ...


class _ScanRepository(Protocol):
    def save_scan(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        started_at: str,
        finished_at: str,
        duration_seconds: float,
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        risks: list[RiskFinding],
        report_path: str,
    ) -> int:
        ...


class ScanOrchestrator:
    def __init__(
        self,
        repository: ScanRepository,
        asset_criticality_map: dict[str, float] | None = None,
        default_asset_criticality: float = 5.0,
    ) -> None:
        self.repository: _ScanRepository = cast(_ScanRepository, repository)
        self.discovery_engine: AssetDiscoveryEngine = AssetDiscoveryEngine()
        self.service_engine: _ServiceFingerprintEngine = cast(_ServiceFingerprintEngine, ServiceFingerprintEngine())
        self.matcher: _VulnerabilityMatcher = cast(_VulnerabilityMatcher, VulnerabilityMatcher(RULE_FILE_PATH))
        self.risk_evaluator: _RiskEvaluator = cast(
            _RiskEvaluator,
            RiskEvaluator(
            asset_criticality_map=asset_criticality_map,
            default_asset_criticality=default_asset_criticality,
            ),
        )
        self.report_generator: _ReportGenerator = cast(_ReportGenerator, HtmlReportGenerator())

    def run_scan(
        self,
        target_cidr: str,
        methods: list[str],
        ports: list[int],
        output_dir: Path,
        scan_name: str = "",
    ) -> dict[str, object]:
        started_at = datetime.now()
        assets: list[HostAsset] = self.discovery_engine.discover(target_cidr, ports, methods)
        services: list[ServiceFingerprint] = self.service_engine.fingerprint(assets, ports)

        ports_from_services: dict[str, set[int]] = {}
        for item in services:
            if not item.host_ip:
                continue
            if item.port <= 0:
                continue
            ports_from_services.setdefault(item.host_ip, set()).add(int(item.port))

        for asset in assets:
            existing_ports = {int(port) for port in asset.open_ports if int(port) > 0}
            merged = existing_ports | ports_from_services.get(asset.ip, set())
            asset.open_ports = sorted(merged)

        vulnerabilities = self.matcher.match(services)
        risks = self.risk_evaluator.evaluate(vulnerabilities)

        report_path = self.report_generator.generate(
            target=target_cidr,
            methods=methods,
            ports=ports,
            assets=assets,
            services=services,
            risks=risks,
            output_dir=output_dir,
            scan_name=scan_name,
        )

        finished_at = datetime.now()
        duration_seconds = round((finished_at - started_at).total_seconds(), 3)
        scan_id = self.repository.save_scan(
            target=target_cidr,
            methods=methods,
            ports=ports,
            started_at=started_at.strftime("%Y-%m-%d %H:%M:%S"),
            finished_at=finished_at.strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=duration_seconds,
            assets=assets,
            services=services,
            risks=risks,
            report_path=report_path,
        )

        summary: dict[str, object] = self._build_summary(risks)
        summary = {
            **summary,
            "scan_id": scan_id,
            "target": target_cidr,
            "methods": methods,
            "ports": ports,
            "duration_seconds": duration_seconds,
            "total_hosts": len(assets),
            "total_services": len(services),
            "report_path": report_path,
        }
        return summary

    def _build_summary(self, risks: list[RiskFinding]) -> dict[str, object]:
        high_count = sum(1 for risk in risks if risk.risk_level == "HIGH")
        medium_count = sum(1 for risk in risks if risk.risk_level == "MEDIUM")
        low_count = sum(1 for risk in risks if risk.risk_level == "LOW")
        summary: dict[str, object] = {
            "total_risks": len(risks),
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
        }
        return summary
