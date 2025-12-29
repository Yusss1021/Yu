"""
Repository layer for data access.
"""

from datetime import datetime
from typing import List, Optional

from ..core.models import (
    Host,
    HostRiskResult,
    RiskLevel,
    Scan,
    ScanStatus,
    Service,
    ServiceVuln,
    PortState,
    Severity,
    VerificationResult,
    Vulnerability,
)
from .database import get_db


class ScanRepository:
    """Repository for Scan entities."""

    def __init__(self, db=None):
        self.db = db or get_db()

    def create(self, scan: Scan) -> int:
        """Create a new scan and return its ID."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO scans (started_at, finished_at, target_range, status, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan.started_at.isoformat() if scan.started_at else datetime.now().isoformat(),
                    scan.finished_at.isoformat() if scan.finished_at else None,
                    scan.target_range,
                    scan.status.value,
                    scan.notes,
                ),
            )
            return cursor.lastrowid

    def update_status(self, scan_id: int, status: ScanStatus, finished_at: datetime = None) -> None:
        """Update scan status."""
        with self.db.transaction() as cursor:
            if finished_at:
                cursor.execute(
                    "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
                    (status.value, finished_at.isoformat(), scan_id),
                )
            else:
                cursor.execute(
                    "UPDATE scans SET status = ? WHERE id = ?",
                    (status.value, scan_id),
                )

    def get_by_id(self, scan_id: int) -> Optional[Scan]:
        """Get a scan by ID."""
        row = self.db.fetchone("SELECT * FROM scans WHERE id = ?", (scan_id,))
        if row:
            return self._row_to_scan(row)
        return None

    def get(self, scan_id: int) -> Optional[Scan]:
        """Alias for get_by_id."""
        return self.get_by_id(scan_id)

    def update(self, scan: Scan) -> None:
        """Update a scan."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                UPDATE scans SET started_at = ?, finished_at = ?, target_range = ?, status = ?, notes = ?
                WHERE id = ?
                """,
                (
                    scan.started_at.isoformat() if scan.started_at else None,
                    scan.finished_at.isoformat() if scan.finished_at else None,
                    scan.target_range,
                    scan.status.value,
                    scan.notes,
                    scan.id,
                ),
            )

    def get_all(self, limit: int = 100) -> List[Scan]:
        """Get all scans."""
        rows = self.db.fetchall(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        return [self._row_to_scan(row) for row in rows]

    def list_all(self, limit: int = 100) -> List[Scan]:
        """Alias for get_all."""
        return self.get_all(limit)

    def _row_to_scan(self, row) -> Scan:
        return Scan(
            id=row["id"],
            target_range=row["target_range"],
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
            status=ScanStatus(row["status"]),
            notes=row["notes"],
        )


class HostRepository:
    """Repository for Host entities."""

    def __init__(self, db=None):
        self.db = db or get_db()

    def create(self, host: Host) -> int:
        """Create a new host and return its ID."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO hosts (scan_id, ip, mac, hostname, os_guess)
                VALUES (?, ?, ?, ?, ?)
                """,
                (host.scan_id, host.ip, host.mac, host.hostname, host.os_guess),
            )
            return cursor.lastrowid

    def create_many(self, hosts: List[Host]) -> List[int]:
        """Create multiple hosts and return their IDs."""
        ids = []
        with self.db.transaction() as cursor:
            for host in hosts:
                cursor.execute(
                    """
                    INSERT INTO hosts (scan_id, ip, mac, hostname, os_guess)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (host.scan_id, host.ip, host.mac, host.hostname, host.os_guess),
                )
                ids.append(cursor.lastrowid)
        return ids

    def get_by_scan(self, scan_id: int) -> List[Host]:
        """Get all hosts for a scan."""
        rows = self.db.fetchall(
            "SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)
        )
        return [self._row_to_host(row) for row in rows]

    def get_by_ip(self, scan_id: int, ip: str) -> Optional[Host]:
        """Get a host by scan ID and IP."""
        row = self.db.fetchone(
            "SELECT * FROM hosts WHERE scan_id = ? AND ip = ?", (scan_id, ip)
        )
        if row:
            return self._row_to_host(row)
        return None

    def _row_to_host(self, row) -> Host:
        return Host(
            id=row["id"],
            scan_id=row["scan_id"],
            ip=row["ip"],
            mac=row["mac"],
            hostname=row["hostname"],
            os_guess=row["os_guess"],
        )


class ServiceRepository:
    """Repository for Service entities."""

    def __init__(self, db=None):
        self.db = db or get_db()

    def create(self, service: Service) -> int:
        """Create a new service and return its ID."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO services (host_id, port, proto, service_name, product, version, cpe, state, banner)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    service.host_id,
                    service.port,
                    service.proto,
                    service.service_name,
                    service.product,
                    service.version,
                    service.cpe,
                    service.state.value,
                    service.banner,
                ),
            )
            return cursor.lastrowid

    def create_many(self, services: List[Service]) -> List[int]:
        """Create multiple services and return their IDs."""
        ids = []
        with self.db.transaction() as cursor:
            for svc in services:
                cursor.execute(
                    """
                    INSERT INTO services (host_id, port, proto, service_name, product, version, cpe, state, banner)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        svc.host_id,
                        svc.port,
                        svc.proto,
                        svc.service_name,
                        svc.product,
                        svc.version,
                        svc.cpe,
                        svc.state.value,
                        svc.banner,
                    ),
                )
                ids.append(cursor.lastrowid)
        return ids

    def get_by_host(self, host_id: int) -> List[Service]:
        """Get all services for a host."""
        rows = self.db.fetchall(
            "SELECT * FROM services WHERE host_id = ?", (host_id,)
        )
        return [self._row_to_service(row) for row in rows]

    def get_by_scan(self, scan_id: int) -> List[Service]:
        """Get all services for a scan (bulk fetch to avoid N+1)."""
        rows = self.db.fetchall(
            """
            SELECT s.* FROM services s
            JOIN hosts h ON s.host_id = h.id
            WHERE h.scan_id = ?
            """,
            (scan_id,),
        )
        return [self._row_to_service(row) for row in rows]

    def _row_to_service(self, row) -> Service:
        return Service(
            id=row["id"],
            host_id=row["host_id"],
            host_ip="",  # Not stored directly
            port=row["port"],
            proto=row["proto"],
            service_name=row["service_name"],
            product=row["product"],
            version=row["version"],
            cpe=row["cpe"],
            state=PortState(row["state"]),
            banner=row["banner"],
        )


class VulnerabilityRepository:
    """Repository for Vulnerability entities."""

    def __init__(self, db=None):
        self.db = db or get_db()

    def create(self, vuln: Vulnerability) -> int:
        """Create a new vulnerability and return its ID."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO vulnerabilities (cve_id, description, cvss_base, cvss_vector, severity, published_at, last_modified, affected_cpe, solution)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vuln.cve_id,
                    vuln.description,
                    vuln.cvss_base,
                    vuln.cvss_vector,
                    vuln.severity.value if vuln.severity else None,
                    vuln.published_at.isoformat() if vuln.published_at else None,
                    vuln.last_modified.isoformat() if vuln.last_modified else None,
                    vuln.affected_cpe,
                    vuln.solution,
                ),
            )
            return cursor.lastrowid

    def upsert(self, vuln: Vulnerability) -> int:
        """Insert or update a vulnerability."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO vulnerabilities (cve_id, description, cvss_base, cvss_vector, severity, published_at, last_modified, affected_cpe, solution)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    description = excluded.description,
                    cvss_base = excluded.cvss_base,
                    cvss_vector = excluded.cvss_vector,
                    severity = excluded.severity,
                    published_at = excluded.published_at,
                    last_modified = excluded.last_modified,
                    affected_cpe = excluded.affected_cpe,
                    solution = excluded.solution
                """,
                (
                    vuln.cve_id,
                    vuln.description,
                    vuln.cvss_base,
                    vuln.cvss_vector,
                    vuln.severity.value if vuln.severity else None,
                    vuln.published_at.isoformat() if vuln.published_at else None,
                    vuln.last_modified.isoformat() if vuln.last_modified else None,
                    vuln.affected_cpe,
                    vuln.solution,
                ),
            )
            return cursor.lastrowid

    def get_by_cve(self, cve_id: str) -> Optional[Vulnerability]:
        """Get a vulnerability by CVE ID."""
        row = self.db.fetchone(
            "SELECT * FROM vulnerabilities WHERE cve_id = ?", (cve_id,)
        )
        if row:
            return self._row_to_vuln(row)
        return None

    def get_by_cve_id(self, cve_id: str) -> Optional[Vulnerability]:
        """Alias for get_by_cve."""
        return self.get_by_cve(cve_id)

    def get_by_service(self, service_id: int) -> List[Vulnerability]:
        """Get vulnerabilities associated with a service."""
        rows = self.db.fetchall(
            """
            SELECT v.* FROM vulnerabilities v
            JOIN service_vulns sv ON v.id = sv.vuln_id
            WHERE sv.service_id = ?
            """,
            (service_id,),
        )
        return [self._row_to_vuln(row) for row in rows]

    def get_by_scan(self, scan_id: int) -> List[Vulnerability]:
        """Get all vulnerabilities for a scan (bulk fetch)."""
        rows = self.db.fetchall(
            """
            SELECT DISTINCT v.* FROM vulnerabilities v
            JOIN service_vulns sv ON v.id = sv.vuln_id
            JOIN services s ON s.id = sv.service_id
            JOIN hosts h ON h.id = s.host_id
            WHERE h.scan_id = ?
            """,
            (scan_id,),
        )
        return [self._row_to_vuln(row) for row in rows]

    def search_by_cpe(self, cpe: str) -> List[Vulnerability]:
        """Search vulnerabilities by CPE pattern."""
        rows = self.db.fetchall(
            "SELECT * FROM vulnerabilities WHERE affected_cpe LIKE ?",
            (f"%{cpe}%",),
        )
        return [self._row_to_vuln(row) for row in rows]

    def _row_to_vuln(self, row) -> Vulnerability:
        return Vulnerability(
            id=row["id"],
            cve_id=row["cve_id"],
            description=row["description"],
            cvss_base=row["cvss_base"] or 0.0,
            cvss_vector=row["cvss_vector"],
            severity=Severity(row["severity"]) if row["severity"] else Severity.LOW,
            published_at=datetime.fromisoformat(row["published_at"]) if row["published_at"] else None,
            last_modified=datetime.fromisoformat(row["last_modified"]) if row["last_modified"] else None,
            affected_cpe=row["affected_cpe"],
            solution=row["solution"],
        )


class RiskResultRepository:
    """Repository for HostRiskResult entities."""

    def __init__(self, db=None):
        self.db = db or get_db()

    def create(self, result: HostRiskResult) -> int:
        """Create a risk result."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO scan_results (scan_id, host_id, risk_score, risk_level, summary, vuln_count, critical_count, high_count, medium_count, low_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.host_id,
                    result.risk_score,
                    result.risk_level.value,
                    result.summary,
                    result.vuln_count,
                    result.critical_count,
                    result.high_count,
                    result.medium_count,
                    result.low_count,
                ),
            )
            return cursor.lastrowid

    def get_by_scan(self, scan_id: int) -> List[HostRiskResult]:
        """Get all risk results for a scan."""
        rows = self.db.fetchall(
            "SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,)
        )
        return [self._row_to_result(row) for row in rows]

    def _row_to_result(self, row) -> HostRiskResult:
        return HostRiskResult(
            id=row["id"],
            scan_id=row["scan_id"],
            host_id=row["host_id"],
            risk_score=row["risk_score"],
            risk_level=RiskLevel(row["risk_level"]),
            summary=row["summary"],
            vuln_count=row["vuln_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
        )


class VerificationResultRepository:
    """Repository for VerificationResult entities."""

    def __init__(self, db=None):
        self.db = db or get_db()

    def create(self, result: VerificationResult) -> int:
        """Create a verification result."""
        with self.db.transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO verification_results
                (scan_id, host_id, service_id, verifier, name, severity, cve_id, description, evidence, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.host_id,
                    result.service_id,
                    result.verifier,
                    result.name,
                    result.severity.value if result.severity else None,
                    result.cve_id,
                    result.description,
                    result.evidence,
                    result.detected_at.isoformat() if result.detected_at else None,
                ),
            )
            return cursor.lastrowid

    def create_many(self, results: List[VerificationResult]) -> List[int]:
        """Create multiple verification results."""
        ids = []
        with self.db.transaction() as cursor:
            for result in results:
                cursor.execute(
                    """
                    INSERT INTO verification_results
                    (scan_id, host_id, service_id, verifier, name, severity, cve_id, description, evidence, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scan_id,
                        result.host_id,
                        result.service_id,
                        result.verifier,
                        result.name,
                        result.severity.value if result.severity else None,
                        result.cve_id,
                        result.description,
                        result.evidence,
                        result.detected_at.isoformat() if result.detected_at else None,
                    ),
                )
                ids.append(cursor.lastrowid)
        return ids

    def get_by_scan(self, scan_id: int) -> List[VerificationResult]:
        """Get all verification results for a scan."""
        rows = self.db.fetchall(
            "SELECT * FROM verification_results WHERE scan_id = ?", (scan_id,)
        )
        return [self._row_to_result(row) for row in rows]

    def get_by_host(self, host_id: int) -> List[VerificationResult]:
        """Get verification results for a host."""
        rows = self.db.fetchall(
            "SELECT * FROM verification_results WHERE host_id = ?", (host_id,)
        )
        return [self._row_to_result(row) for row in rows]

    def _row_to_result(self, row) -> VerificationResult:
        return VerificationResult(
            id=row["id"],
            scan_id=row["scan_id"],
            host_id=row["host_id"],
            service_id=row["service_id"],
            verifier=row["verifier"],
            name=row["name"],
            severity=Severity(row["severity"]) if row["severity"] else Severity.LOW,
            cve_id=row["cve_id"],
            description=row["description"],
            evidence=row["evidence"],
            detected_at=datetime.fromisoformat(row["detected_at"]) if row["detected_at"] else None,
        )
