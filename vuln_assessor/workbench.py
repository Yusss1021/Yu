from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import DEFAULT_DB_PATH, DEFAULT_DISCOVERY_DIR, DEFAULT_REPORT_DIR, RULE_FILE_PATH
from .desktop_profiles import resolve_discovery_methods, resolve_nmap_arguments
from .models import HostAsset
from .orchestrator import ScanOrchestrator
from .report_lifecycle import delete_discovery_snapshots, delete_report_artifacts
from .risk import load_asset_profile
from .storage import ScanRepository
from .vuln import VulnerabilityRuleManager


@dataclass(slots=True)
class DiscoverySnapshot:
    snapshot_id: str
    snapshot_name: str
    target: str
    methods: list[str]
    ports: list[int]
    created_at: str
    file_path: Path
    assets: list[HostAsset]
    report_path: str = ""
    report_type: str = "asset_discovery"
    scan_id: int | None = None
    asset_profile_path: str = ""

    @property
    def asset_count(self) -> int:
        return len(self.assets)


class ScanWorkbench:
    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        report_dir: Path = DEFAULT_REPORT_DIR,
        discovery_dir: Path = DEFAULT_DISCOVERY_DIR,
        rules_file: Path = RULE_FILE_PATH,
    ) -> None:
        self.db_path = Path(db_path)
        self.report_dir = Path(report_dir)
        self.discovery_dir = Path(discovery_dir)
        self.rules_file = Path(rules_file)

    def discover_assets(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        snapshot_name: str = "",
        asset_profile_path: Path | None = None,
    ) -> DiscoverySnapshot:
        asset_map, default_asset = load_asset_profile(asset_profile_path)
        repository = ScanRepository(self.db_path)
        repository.initialize()
        orchestrator = ScanOrchestrator(repository)
        assets = orchestrator.discover_assets(target_cidr=target, methods=methods, ports=ports)
        self._apply_asset_profile(assets, asset_map, default_asset)
        snapshot = self._save_discovery_snapshot(
            target=target,
            methods=methods,
            ports=ports,
            assets=assets,
            snapshot_name=snapshot_name,
            asset_profile_path=str(asset_profile_path) if asset_profile_path else "",
        )
        report_path = orchestrator.generate_asset_report(
            target=target,
            methods=methods,
            ports=ports,
            assets=assets,
            output_dir=self.report_dir,
            scan_name=snapshot.snapshot_name,
            asset_profile_label=self._asset_profile_label(asset_profile_path),
        )
        scan_id = repository.save_scan(
            target=target,
            methods=methods,
            ports=ports,
            started_at=snapshot.created_at,
            finished_at=snapshot.created_at,
            duration_seconds=0.0,
            assets=assets,
            services=[],
            risks=[],
            report_path=report_path,
            scan_type="asset_discovery",
        )
        updated_snapshot = DiscoverySnapshot(
            snapshot_id=snapshot.snapshot_id,
            snapshot_name=snapshot.snapshot_name,
            target=snapshot.target,
            methods=list(snapshot.methods),
            ports=list(snapshot.ports),
            created_at=snapshot.created_at,
            file_path=snapshot.file_path,
            assets=[self._host_asset_from_dict(self._host_asset_to_dict(item)) for item in snapshot.assets],
            report_path=report_path,
            report_type="asset_discovery",
            scan_id=scan_id,
            asset_profile_path=snapshot.asset_profile_path,
        )
        self._write_discovery_snapshot(updated_snapshot)
        return updated_snapshot

    def analyze_snapshot(
        self,
        snapshot_path: Path,
        scan_name: str = "",
        output_dir: Path | None = None,
        asset_profile_path: Path | None = None,
        enable_active_checks: bool = True,
        enable_auth_checks: bool = False,
    ) -> dict[str, object]:
        snapshot = self.load_discovery_snapshot(snapshot_path)
        asset_map, default_asset = load_asset_profile(asset_profile_path)
        repository = ScanRepository(self.db_path)
        repository.initialize()
        orchestrator = ScanOrchestrator(
            repository,
            asset_criticality_map=asset_map,
            default_asset_criticality=default_asset,
        )
        return orchestrator.analyze_assets(
            target_cidr=snapshot.target,
            methods=snapshot.methods,
            ports=snapshot.ports,
            assets=snapshot.assets,
            output_dir=output_dir or self.report_dir,
            scan_name=scan_name or snapshot.snapshot_name,
            enable_active_checks=enable_active_checks,
            enable_auth_checks=enable_auth_checks,
            asset_profile_label=self._asset_profile_label(asset_profile_path),
        )

    def analyze_target(
        self,
        target: str,
        ports: list[int],
        nmap_profile: str = "standard",
        extra_nmap_args: list[str] | None = None,
        scan_name: str = "",
        output_dir: Path | None = None,
        asset_profile_path: Path | None = None,
        enable_active_checks: bool = True,
        enable_auth_checks: bool = False,
    ) -> dict[str, object]:
        asset_map, default_asset = load_asset_profile(asset_profile_path)
        repository = ScanRepository(self.db_path)
        repository.initialize()
        orchestrator = ScanOrchestrator(
            repository,
            asset_criticality_map=asset_map,
            default_asset_criticality=default_asset,
        )
        nmap_arguments = resolve_nmap_arguments(nmap_profile)
        if extra_nmap_args:
            nmap_arguments.extend(extra_nmap_args)
        return orchestrator.run_scan(
            target_cidr=target,
            methods=resolve_discovery_methods("progressive", None),
            ports=ports,
            output_dir=output_dir or self.report_dir,
            scan_name=scan_name,
            nmap_arguments=nmap_arguments,
            require_nmap=True,
            enable_active_checks=enable_active_checks,
            enable_auth_checks=enable_auth_checks,
            asset_profile_label=self._asset_profile_label(asset_profile_path),
        )

    def list_discovery_snapshots(self, limit: int = 30) -> list[dict[str, Any]]:
        self.discovery_dir.mkdir(parents=True, exist_ok=True)
        rows: list[dict[str, Any]] = []
        for path in sorted(self.discovery_dir.glob("*.json"), reverse=True):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            assets = payload.get("assets", [])
            asset_count = len(assets) if isinstance(assets, list) else 0
            rows.append(
                {
                    "snapshot_id": str(payload.get("snapshot_id", path.stem)),
                    "snapshot_name": str(payload.get("snapshot_name", path.stem)),
                    "target": str(payload.get("target", "")),
                    "methods": ",".join(self._to_text_list(payload.get("methods"))),
                    "ports": ",".join(str(item) for item in self._to_int_list(payload.get("ports"))),
                    "created_at": str(payload.get("created_at", "")),
                    "asset_count": asset_count,
                    "file_path": str(path),
                    "report_path": str(payload.get("report_path", "")),
                    "report_type": str(payload.get("report_type", "asset_discovery")),
                    "scan_id": self._to_int(payload.get("scan_id")),
                    "asset_profile_path": str(payload.get("asset_profile_path", "")),
                }
            )
            if len(rows) >= limit:
                break
        return rows

    def load_discovery_snapshot(self, snapshot_path: Path) -> DiscoverySnapshot:
        path = Path(snapshot_path)
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("发现结果文件格式错误")
        raw_assets = payload.get("assets", [])
        if not isinstance(raw_assets, list):
            raise ValueError("发现结果资产列表格式错误")
        assets = [self._host_asset_from_dict(item) for item in raw_assets if isinstance(item, dict)]
        return DiscoverySnapshot(
            snapshot_id=str(payload.get("snapshot_id", path.stem)),
            snapshot_name=str(payload.get("snapshot_name", path.stem)),
            target=str(payload.get("target", "")),
            methods=self._to_text_list(payload.get("methods")),
            ports=self._to_int_list(payload.get("ports")),
            created_at=str(payload.get("created_at", "")),
            file_path=path,
            assets=assets,
            report_path=str(payload.get("report_path", "")),
            report_type=str(payload.get("report_type", "asset_discovery") or "asset_discovery"),
            scan_id=self._to_int(payload.get("scan_id")),
            asset_profile_path=str(payload.get("asset_profile_path", "")),
        )

    def get_rule_manager(self) -> VulnerabilityRuleManager:
        return VulnerabilityRuleManager(self.rules_file)

    def compare_reports(self, base_scan_id: int, new_scan_id: int) -> dict[str, Any]:
        repository = ScanRepository(self.db_path)
        repository.initialize()
        return repository.compare_scan_outputs(base_scan_id=base_scan_id, new_scan_id=new_scan_id)

    def list_scans(self, limit: int = 50, scan_type: str | None = None) -> list[dict[str, Any]]:
        repository = ScanRepository(self.db_path)
        repository.initialize()
        return repository.list_scans(limit=limit, scan_type=scan_type)

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        repository = ScanRepository(self.db_path)
        repository.initialize()
        return repository.get_scan(scan_id)

    def get_services(self, scan_id: int) -> list[dict[str, Any]]:
        repository = ScanRepository(self.db_path)
        repository.initialize()
        return repository.get_services(scan_id)

    def get_vulnerabilities(self, scan_id: int) -> list[dict[str, Any]]:
        repository = ScanRepository(self.db_path)
        repository.initialize()
        return repository.get_vulnerabilities(scan_id)

    def delete_scan(self, scan_id: int) -> dict[str, Any]:
        repository = ScanRepository(self.db_path)
        repository.initialize()
        scan = repository.delete_scan(scan_id)
        if scan is None:
            raise ValueError(f"扫描记录不存在: {scan_id}")

        deleted_paths = delete_report_artifacts(str(scan.get("report_path", "")), self.report_dir)
        deleted_paths.extend(delete_discovery_snapshots(scan_id, self.discovery_dir))
        return {
            "scan_id": scan_id,
            "scan_type": str(scan.get("scan_type", "analysis")),
            "report_path": str(scan.get("report_path", "")),
            "deleted_paths": deleted_paths,
        }

    def _save_discovery_snapshot(
        self,
        target: str,
        methods: list[str],
        ports: list[int],
        assets: list[HostAsset],
        snapshot_name: str,
        asset_profile_path: str,
    ) -> DiscoverySnapshot:
        self.discovery_dir.mkdir(parents=True, exist_ok=True)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        snapshot_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        normalized_name = self._normalize_name(snapshot_name, fallback=f"assets_{snapshot_id}")
        file_path = self._ensure_unique_snapshot_path(normalized_name)
        stored_snapshot_name = file_path.stem
        snapshot = DiscoverySnapshot(
            snapshot_id=snapshot_id,
            snapshot_name=stored_snapshot_name,
            target=target,
            methods=list(methods),
            ports=list(ports),
            created_at=created_at,
            file_path=file_path,
            assets=[self._host_asset_from_dict(self._host_asset_to_dict(item)) for item in assets],
            asset_profile_path=asset_profile_path,
        )
        self._write_discovery_snapshot(snapshot)
        return snapshot

    def _write_discovery_snapshot(self, snapshot: DiscoverySnapshot) -> None:
        payload = {
            "snapshot_id": snapshot.snapshot_id,
            "snapshot_name": snapshot.snapshot_name,
            "target": snapshot.target,
            "methods": list(snapshot.methods),
            "ports": list(snapshot.ports),
            "created_at": snapshot.created_at,
            "assets": [self._host_asset_to_dict(item) for item in snapshot.assets],
            "report_path": snapshot.report_path,
            "report_type": snapshot.report_type,
            "scan_id": snapshot.scan_id,
            "asset_profile_path": snapshot.asset_profile_path,
        }
        snapshot.file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _host_asset_to_dict(self, asset: HostAsset) -> dict[str, Any]:
        return {
            "ip": asset.ip,
            "mac": asset.mac,
            "discovered_by": list(asset.discovered_by),
            "open_ports": list(asset.open_ports),
            "asset_criticality": float(asset.asset_criticality),
        }

    def _host_asset_from_dict(self, payload: dict[str, Any]) -> HostAsset:
        return HostAsset(
            ip=str(payload.get("ip", "")),
            mac=str(payload.get("mac", "")),
            discovered_by=self._to_text_list(payload.get("discovered_by")),
            open_ports=self._to_int_list(payload.get("open_ports")),
            asset_criticality=self._to_float(payload.get("asset_criticality"), fallback=5.0),
        )

    def _apply_asset_profile(
        self,
        assets: list[HostAsset],
        asset_map: dict[str, float],
        default_asset: float,
    ) -> None:
        for asset in assets:
            asset.asset_criticality = float(asset_map.get(asset.ip, default_asset))

    def _asset_profile_label(self, profile_path: Path | None) -> str:
        if profile_path is None:
            return "未使用"
        return profile_path.name

    def _normalize_name(self, raw_name: str, fallback: str) -> str:
        candidate = re.sub(r"[^0-9A-Za-z_.-]+", "_", raw_name.strip())
        candidate = candidate.strip("._-")
        return candidate if candidate else fallback

    def _ensure_unique_snapshot_path(self, normalized_name: str) -> Path:
        candidate = self.discovery_dir / f"{normalized_name}.json"
        if not candidate.exists():
            return candidate
        index = 2
        while True:
            next_candidate = self.discovery_dir / f"{normalized_name}_{index}.json"
            if not next_candidate.exists():
                return next_candidate
            index += 1

    def _to_text_list(self, raw_value: object) -> list[str]:
        if not isinstance(raw_value, list):
            return []
        return [str(item).strip() for item in raw_value if str(item).strip()]

    def _to_int_list(self, raw_value: object) -> list[int]:
        if not isinstance(raw_value, list):
            return []
        result: list[int] = []
        for item in raw_value:
            try:
                value = int(item)
            except (TypeError, ValueError):
                continue
            if value > 0:
                result.append(value)
        return result

    def _to_int(self, raw_value: object) -> int | None:
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            return None
        return value if value > 0 else None

    def _to_float(self, raw_value: object, fallback: float) -> float:
        try:
            return float(raw_value)
        except (TypeError, ValueError):
            return fallback
