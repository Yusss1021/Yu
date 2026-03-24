from __future__ import annotations

# pyright: reportMissingTypeArgument=false, reportUnknownParameterType=false

import sqlite3
from pathlib import Path
from typing import Any

from ..models import HostAsset, RiskFinding, ServiceFingerprint


class ScanRepository:
    db_path: Path

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def initialize(self) -> None:
        with self._connect() as conn:
            _ = conn.execute("PRAGMA journal_mode=WAL")
            _ = conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    methods TEXT NOT NULL,
                    ports TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    total_hosts INTEGER NOT NULL,
                    total_services INTEGER NOT NULL,
                    total_risks INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    report_path TEXT NOT NULL
                )
                """
            )
            _ = conn.execute(
                """
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    mac TEXT,
                    discovered_by TEXT,
                    open_ports TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            _ = conn.execute(
                """
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    host_ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    product TEXT,
                    version TEXT,
                    extra_info TEXT,
                    fingerprint_method TEXT,
                    fingerprint_confidence REAL NOT NULL DEFAULT 0.0,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            _ = conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    host_ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    service_name TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    cvss REAL NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    exploit_maturity REAL NOT NULL DEFAULT 5.0,
                    match_confidence REAL NOT NULL DEFAULT 5.0,
                    confidence_tier TEXT NOT NULL DEFAULT 'MEDIUM',
                    manual_confirmation_needed INTEGER NOT NULL DEFAULT 0,
                    confidence_reason TEXT NOT NULL DEFAULT '',
                    asset_criticality REAL NOT NULL DEFAULT 5.0,
                    description TEXT,
                    remediation TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )

            self._ensure_column(conn, "services", "fingerprint_method", "TEXT")
            self._ensure_column(conn, "services", "fingerprint_confidence", "REAL NOT NULL DEFAULT 0.0")

            self._ensure_column(conn, "vulnerabilities", "exploit_maturity", "REAL NOT NULL DEFAULT 5.0")
            self._ensure_column(conn, "vulnerabilities", "match_confidence", "REAL NOT NULL DEFAULT 5.0")
            self._ensure_column(conn, "vulnerabilities", "confidence_tier", "TEXT NOT NULL DEFAULT 'MEDIUM'")
            self._ensure_column(conn, "vulnerabilities", "manual_confirmation_needed", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "vulnerabilities", "confidence_reason", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(conn, "vulnerabilities", "asset_criticality", "REAL NOT NULL DEFAULT 5.0")

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
        high_count = sum(1 for item in risks if item.risk_level == "HIGH")
        medium_count = sum(1 for item in risks if item.risk_level == "MEDIUM")
        low_count = sum(1 for item in risks if item.risk_level == "LOW")

        with self._connect() as conn:
            cursor = conn.cursor()
            _ = cursor.execute(
                """
                INSERT INTO scans (
                    target, methods, ports, started_at, finished_at, duration_seconds,
                    total_hosts, total_services, total_risks, high_count, medium_count, low_count, report_path
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target,
                    ",".join(methods),
                    ",".join(str(port) for port in ports),
                    started_at,
                    finished_at,
                    duration_seconds,
                    len(assets),
                    len(services),
                    len(risks),
                    high_count,
                    medium_count,
                    low_count,
                    report_path,
                ),
            )
            scan_id = int(cursor.lastrowid or 0)

            for asset in assets:
                _ = cursor.execute(
                    """
                    INSERT INTO assets (scan_id, ip, mac, discovered_by, open_ports)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        asset.ip,
                        asset.mac,
                        ",".join(asset.discovered_by),
                        ",".join(str(port) for port in asset.open_ports),
                    ),
                )

            for service in services:
                _ = cursor.execute(
                    """
                    INSERT INTO services (
                        scan_id, host_ip, port, protocol, service_name, product, version, extra_info,
                        fingerprint_method, fingerprint_confidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        service.host_ip,
                        int(service.port),
                        service.protocol,
                        service.service_name,
                        service.product,
                        service.version,
                        service.extra_info,
                        service.fingerprint_method,
                        float(service.fingerprint_confidence),
                    ),
                )

            for risk in risks:
                _ = cursor.execute(
                    """
                    INSERT INTO vulnerabilities (
                        scan_id, host_ip, port, service_name, cve_id, severity, cvss, risk_score, risk_level,
                        exploit_maturity, match_confidence, confidence_tier, manual_confirmation_needed,
                        confidence_reason, asset_criticality, description, remediation
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        risk.host_ip,
                        int(risk.port),
                        risk.service_name,
                        risk.cve_id,
                        risk.severity,
                        float(risk.cvss),
                        float(risk.risk_score),
                        risk.risk_level,
                        float(risk.exploit_maturity),
                        float(risk.match_confidence),
                        self._normalize_confidence_tier(str(risk.confidence_tier)),
                        1 if bool(risk.manual_confirmation_needed) else 0,
                        str(risk.confidence_reason or ""),
                        float(risk.asset_criticality),
                        risk.description,
                        risk.remediation,
                    ),
                )

            conn.commit()
        return scan_id

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT id, target, started_at, total_hosts, total_services, total_risks, high_count, medium_count, low_count, report_path
                FROM scans
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT id, target, methods, ports, started_at, finished_at, duration_seconds,
                       total_hosts, total_services, total_risks, high_count, medium_count, low_count, report_path
                FROM scans
                WHERE id = ?
                """,
                (scan_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_assets(self, scan_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT ip, mac, discovered_by, open_ports
                FROM assets
                WHERE scan_id = ?
                ORDER BY ip
                """,
                (scan_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_services(self, scan_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT host_ip, port, protocol, service_name, product, version, extra_info,
                       fingerprint_method, fingerprint_confidence
                FROM services
                WHERE scan_id = ?
                ORDER BY host_ip, port
                """,
                (scan_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_vulnerabilities(self, scan_id: int) -> list[dict[str, Any]]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT host_ip, port, service_name, cve_id, severity, cvss, risk_score, risk_level,
                       exploit_maturity, match_confidence, confidence_tier, manual_confirmation_needed,
                       confidence_reason, asset_criticality, description, remediation
                FROM vulnerabilities
                WHERE scan_id = ?
                ORDER BY risk_score DESC, cvss DESC, host_ip, port
                """,
                (scan_id,),
            ).fetchall()

        result: list[dict[str, Any]] = []
        for row in rows:
            row_dict = dict(row)
            row_dict["port"] = self._to_int(row_dict.get("port"))
            row_dict["cvss"] = self._to_float(row_dict.get("cvss"))
            row_dict["risk_score"] = self._to_float(row_dict.get("risk_score"))
            row_dict["exploit_maturity"] = self._to_float(row_dict.get("exploit_maturity"))
            row_dict["match_confidence"] = self._to_float(row_dict.get("match_confidence"))
            row_dict["confidence_tier"] = self._normalize_confidence_tier(str(row_dict.get("confidence_tier", "MEDIUM")))
            row_dict["manual_confirmation_needed"] = self._to_bool(row_dict.get("manual_confirmation_needed", 0))
            row_dict["confidence_reason"] = str(row_dict.get("confidence_reason", "") or "")
            row_dict["asset_criticality"] = self._to_float(row_dict.get("asset_criticality"), default=5.0)
            result.append(row_dict)
        return result

    def compare_scans(self, base_scan_id: int, new_scan_id: int) -> dict[str, Any]:
        comparison = self.compare_scan_outputs(base_scan_id=base_scan_id, new_scan_id=new_scan_id)
        return {
            "base_scan_id": comparison["base_scan_id"],
            "new_scan_id": comparison["new_scan_id"],
            "newly_found": [(item["host_ip"], item["port"], item["cve_id"]) for item in comparison["vulnerability_new"]],
            "resolved": [(item["host_ip"], item["port"], item["cve_id"]) for item in comparison["vulnerability_resolved"]],
            "persisted": [(item["host_ip"], item["port"], item["cve_id"]) for item in comparison["vulnerability_persisted"]],
        }

    def compare_scan_outputs(self, base_scan_id: int, new_scan_id: int) -> dict[str, Any]:
        if self.get_scan(base_scan_id) is None:
            raise ValueError(f"基线扫描 ID 不存在: {base_scan_id}")
        if self.get_scan(new_scan_id) is None:
            raise ValueError(f"新扫描 ID 不存在: {new_scan_id}")

        base_services = self._service_set(base_scan_id)
        new_services = self._service_set(new_scan_id)

        service_new = [self._service_tuple_to_dict(item) for item in sorted(new_services - base_services)]
        service_resolved = [self._service_tuple_to_dict(item) for item in sorted(base_services - new_services)]
        service_persisted = [self._service_tuple_to_dict(item) for item in sorted(base_services & new_services)]

        base_vulnerabilities = self._vulnerability_map(base_scan_id)
        new_vulnerabilities = self._vulnerability_map(new_scan_id)
        base_keys = set(base_vulnerabilities.keys())
        new_keys = set(new_vulnerabilities.keys())

        vulnerability_new = [new_vulnerabilities[key] for key in sorted(new_keys - base_keys)]
        vulnerability_resolved = [base_vulnerabilities[key] for key in sorted(base_keys - new_keys)]
        vulnerability_persisted = [new_vulnerabilities[key] for key in sorted(base_keys & new_keys)]

        vulnerability_changed: list[dict[str, Any]] = []
        for key in sorted(base_keys & new_keys):
            base_item = base_vulnerabilities[key]
            new_item = new_vulnerabilities[key]
            if (
                base_item["risk_score"] != new_item["risk_score"]
                or base_item["risk_level"] != new_item["risk_level"]
                or base_item["match_confidence"] != new_item["match_confidence"]
                or base_item["confidence_tier"] != new_item["confidence_tier"]
                or base_item["manual_confirmation_needed"] != new_item["manual_confirmation_needed"]
                or base_item["asset_criticality"] != new_item["asset_criticality"]
                or base_item["exploit_maturity"] != new_item["exploit_maturity"]
            ):
                vulnerability_changed.append(
                    {
                        "host_ip": new_item["host_ip"],
                        "port": new_item["port"],
                        "cve_id": new_item["cve_id"],
                        "base_risk_score": base_item["risk_score"],
                        "new_risk_score": new_item["risk_score"],
                        "base_risk_level": base_item["risk_level"],
                        "new_risk_level": new_item["risk_level"],
                        "base_match_confidence": base_item["match_confidence"],
                        "new_match_confidence": new_item["match_confidence"],
                        "base_confidence_tier": base_item["confidence_tier"],
                        "new_confidence_tier": new_item["confidence_tier"],
                        "base_manual_confirmation_needed": base_item["manual_confirmation_needed"],
                        "new_manual_confirmation_needed": new_item["manual_confirmation_needed"],
                        "base_asset_criticality": base_item["asset_criticality"],
                        "new_asset_criticality": new_item["asset_criticality"],
                        "base_exploit_maturity": base_item["exploit_maturity"],
                        "new_exploit_maturity": new_item["exploit_maturity"],
                    }
                )

        return {
            "base_scan_id": base_scan_id,
            "new_scan_id": new_scan_id,
            "service_new": service_new,
            "service_resolved": service_resolved,
            "service_persisted": service_persisted,
            "vulnerability_new": vulnerability_new,
            "vulnerability_resolved": vulnerability_resolved,
            "vulnerability_persisted": vulnerability_persisted,
            "vulnerability_changed": vulnerability_changed,
        }

    def _service_set(self, scan_id: int) -> set[tuple[str, int, str, str, str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT host_ip, port, protocol, service_name, product, version
                FROM services
                WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchall()
        return {
            (str(host_ip), int(port), str(protocol), str(service_name), str(product or ""), str(version or ""))
            for host_ip, port, protocol, service_name, product, version in rows
        }

    def _service_tuple_to_dict(self, payload: tuple[str, int, str, str, str, str]) -> dict[str, Any]:
        host_ip, port, protocol, service_name, product, version = payload
        return {
            "host_ip": host_ip,
            "port": int(port),
            "protocol": protocol,
            "service_name": service_name,
            "product": product,
            "version": version,
        }

    def _vulnerability_map(self, scan_id: int) -> dict[tuple[str, int, str], dict[str, Any]]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT host_ip, port, service_name, cve_id, severity, cvss, risk_score, risk_level,
                       exploit_maturity, match_confidence, confidence_tier, manual_confirmation_needed,
                       confidence_reason, asset_criticality, description, remediation
                FROM vulnerabilities
                WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchall()

        result: dict[tuple[str, int, str], dict[str, Any]] = {}
        for row in rows:
            row_dict = dict(row)
            key = (str(row_dict["host_ip"]), int(row_dict["port"]), str(row_dict["cve_id"]))
            row_dict["port"] = self._to_int(row_dict.get("port"))
            row_dict["cvss"] = self._to_float(row_dict.get("cvss"))
            row_dict["risk_score"] = self._to_float(row_dict.get("risk_score"))
            row_dict["exploit_maturity"] = self._to_float(row_dict.get("exploit_maturity"))
            row_dict["match_confidence"] = self._to_float(row_dict.get("match_confidence"))
            row_dict["confidence_tier"] = self._normalize_confidence_tier(str(row_dict.get("confidence_tier", "MEDIUM")))
            row_dict["manual_confirmation_needed"] = self._to_bool(row_dict.get("manual_confirmation_needed", 0))
            row_dict["confidence_reason"] = str(row_dict.get("confidence_reason", "") or "")
            row_dict["asset_criticality"] = self._to_float(row_dict.get("asset_criticality"), default=5.0)
            result[key] = row_dict
        return result

    def _to_int(self, value: object, default: int = 0) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return default
        return default

    def _to_float(self, value: object, default: float = 0.0) -> float:
        if isinstance(value, bool):
            return float(int(value))
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return default
        return default

    def _to_bool(self, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(int(value))
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "y"}:
                return True
            if lowered in {"0", "false", "no", "n", ""}:
                return False
        return False

    def _normalize_confidence_tier(self, tier: str) -> str:
        normalized = tier.strip().upper()
        if normalized in {"HIGH", "MEDIUM", "LOW"}:
            return normalized
        return "MEDIUM"

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
        existing_columns = {str(row[1]) for row in rows}
        if column in existing_columns:
            return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA busy_timeout=30000")
        return conn
