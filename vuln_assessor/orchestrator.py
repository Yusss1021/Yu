from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

from .active_checks import ActiveCheckEngine
from .config import RULE_FILE_PATH
from .models import HostAsset, RiskFinding, ServiceFingerprint, VulnerabilityFinding
from .report import HtmlReportGenerator
from .risk import RiskEvaluator
from .scanners import AssetDiscoveryEngine
from .scanners.service_fingerprint import ServiceFingerprintEngine
from .storage import ScanRepository
from .vuln import VulnerabilityMatcher


class _ServiceFingerprintEngine(Protocol):
    def fingerprint(
        self,
        assets: list[HostAsset],
        fallback_ports: list[int],
        nmap_arguments: list[str] | None = None,
        require_nmap: bool = False,
    ) -> list[ServiceFingerprint]:
        ...


class _VulnerabilityMatcher(Protocol):
    def match(self, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        ...


class _RiskEvaluator(Protocol):
    def evaluate(self, vulnerabilities: list[VulnerabilityFinding]) -> list[RiskFinding]:
        ...


class _ActiveCheckEngine(Protocol):
    def run(
        self,
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        fallback_ports: list[int],
        enable_auth_checks: bool = False,
    ) -> list[VulnerabilityFinding]:
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
        asset_profile_label: str = "未使用",
        report_type: str = "analysis",
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
        self.active_check_engine: _ActiveCheckEngine = cast(_ActiveCheckEngine, ActiveCheckEngine())
        self.risk_evaluator: _RiskEvaluator = cast(
            _RiskEvaluator,
            RiskEvaluator(
                asset_criticality_map=asset_criticality_map,
                default_asset_criticality=default_asset_criticality,
            ),
        )
        self.report_generator: _ReportGenerator = cast(_ReportGenerator, HtmlReportGenerator())

    def discover_assets(
        self,
        target_cidr: str,
        methods: list[str],
        ports: list[int],
    ) -> list[HostAsset]:
        return self.discovery_engine.discover(target_cidr, ports, methods)

    def identify_services(
        self,
        assets: list[HostAsset],
        ports: list[int],
        nmap_arguments: list[str] | None = None,
        require_nmap: bool = False,
    ) -> list[ServiceFingerprint]:
        services = self.service_engine.fingerprint(
            assets,
            ports,
            nmap_arguments=nmap_arguments,
            require_nmap=require_nmap,
        )
        self._merge_open_ports_from_services(assets, services)
        return services

    def match_vulnerabilities(self, services: list[ServiceFingerprint]) -> list[VulnerabilityFinding]:
        return self.matcher.match(services)

    def run_active_checks(
        self,
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
        ports: list[int],
        enable_auth_checks: bool = False,
    ) -> list[VulnerabilityFinding]:
        return self.active_check_engine.run(
            assets=assets,
            services=services,
            fallback_ports=ports,
            enable_auth_checks=enable_auth_checks,
        )

    def evaluate_risks(self, vulnerabilities: list[VulnerabilityFinding]) -> list[RiskFinding]:
        return self.risk_evaluator.evaluate(vulnerabilities)

    def analyze_assets(
        self,
        target_cidr: str,
        methods: list[str],
        ports: list[int],
        assets: list[HostAsset],
        output_dir: Path,
        scan_name: str = "",
        nmap_arguments: list[str] | None = None,
        require_nmap: bool = False,
        enable_active_checks: bool = True,
        enable_auth_checks: bool = False,
        asset_profile_label: str = "未使用",
    ) -> dict[str, object]:
        started_at = datetime.now()
        normalized_assets = self._clone_assets(assets)
        services = self.identify_services(
            normalized_assets,
            ports,
            nmap_arguments=nmap_arguments,
            require_nmap=require_nmap,
        )
        matched_vulnerabilities = self.match_vulnerabilities(services)
        active_findings = []
        if enable_active_checks:
            active_findings = self.run_active_checks(
                normalized_assets,
                services,
                ports,
                enable_auth_checks=enable_auth_checks,
            )
        vulnerabilities = self._merge_vulnerabilities(matched_vulnerabilities, active_findings)
        risks = self.evaluate_risks(vulnerabilities)

        report_path = self.report_generator.generate(
            target=target_cidr,
            methods=methods,
            ports=ports,
            assets=normalized_assets,
            services=services,
            risks=risks,
            output_dir=output_dir,
            scan_name=scan_name,
            asset_profile_label=asset_profile_label,
            report_type="analysis",
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
            assets=normalized_assets,
            services=services,
            risks=risks,
            report_path=report_path,
            scan_type="analysis",
        )

        summary: dict[str, object] = self._build_summary(risks)
        summary = {
            **summary,
            "scan_id": scan_id,
            "target": target_cidr,
            "methods": methods,
            "ports": ports,
            "duration_seconds": duration_seconds,
            "total_hosts": len(normalized_assets),
            "total_services": len(services),
            "report_path": report_path,
            "scan_type": "analysis",
        }
        return summary

    def run_scan(
        self,
        target_cidr: str,
        methods: list[str],
        ports: list[int],
        output_dir: Path,
        scan_name: str = "",
        nmap_arguments: list[str] | None = None,
        require_nmap: bool = False,
        enable_active_checks: bool = True,
        enable_auth_checks: bool = False,
        asset_profile_label: str = "未使用",
    ) -> dict[str, object]:
        assets = self.discover_assets(target_cidr=target_cidr, methods=methods, ports=ports)
        return self.analyze_assets(
            target_cidr=target_cidr,
            methods=methods,
            ports=ports,
            assets=assets,
            output_dir=output_dir,
            scan_name=scan_name,
            nmap_arguments=nmap_arguments,
            require_nmap=require_nmap,
            enable_active_checks=enable_active_checks,
            enable_auth_checks=enable_auth_checks,
            asset_profile_label=asset_profile_label,
        )

    def generate_asset_report(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        assets: list[HostAsset],
        output_dir: Path,
        scan_name: str = "",
        asset_profile_label: str = "未使用",
    ) -> str:
        normalized_assets = self._clone_assets(assets)
        return self.report_generator.generate(
            target=target,
            methods=methods,
            ports=ports,
            assets=normalized_assets,
            services=[],
            risks=[],
            output_dir=output_dir,
            scan_name=scan_name,
            asset_profile_label=asset_profile_label,
            report_type="asset_discovery",
        )

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

    def _clone_assets(self, assets: list[HostAsset]) -> list[HostAsset]:
        return [
            HostAsset(
                ip=item.ip,
                mac=item.mac,
                discovered_by=list(item.discovered_by),
                open_ports=list(item.open_ports),
                asset_criticality=float(item.asset_criticality),
            )
            for item in assets
        ]

    def _merge_open_ports_from_services(
        self,
        assets: list[HostAsset],
        services: list[ServiceFingerprint],
    ) -> None:
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

    def _merge_vulnerabilities(
        self,
        matched: list[VulnerabilityFinding],
        active: list[VulnerabilityFinding],
    ) -> list[VulnerabilityFinding]:
        unique: dict[tuple[str, int, str], VulnerabilityFinding] = {}
        for item in [*matched, *active]:
            unique[(item.host_ip, int(item.port), item.cve_id)] = item
        return sorted(unique.values(), key=lambda item: (item.host_ip, item.port, item.cve_id))
