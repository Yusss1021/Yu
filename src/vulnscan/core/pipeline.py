"""
Scan pipeline orchestration.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

from .base import ScanContext
from .models import (
    Host,
    HostRiskResult,
    Scan,
    ScanResult,
    ScanStatus,
    Service,
    VerificationResult,
    Vulnerability,
)
from .scoring import RiskScorer
from ..config import get_config
from ..nvd.cache import CVECache
from ..nvd.client import NVDClient
from ..nvd.matcher import VulnerabilityMatcher, MatchResult
from ..reporting.generator import ReportGenerator
from ..scanners.discovery.icmp import ICMPScanner
from ..scanners.discovery.arp import ARPScanner
from ..scanners.discovery.syn import SYNScanner
from ..scanners.service.nmap import NmapScanner
from ..storage.database import Database
from ..storage.repository import (
    HostRepository,
    RiskResultRepository,
    ScanRepository,
    ServiceRepository,
    VerificationResultRepository,
    VulnerabilityRepository,
)

logger = logging.getLogger(__name__)


@dataclass
class PipelineResult:
    """Result of a complete scan pipeline execution."""
    scan: Scan
    hosts: List[Host] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    risk_results: List[HostRiskResult] = field(default_factory=list)
    verification_results: List[VerificationResult] = field(default_factory=list)
    matches: List[MatchResult] = field(default_factory=list)
    report_path: Optional[Path] = None
    errors: List[str] = field(default_factory=list)


class ScanPipelineRunner:
    """
    Orchestrates the complete vulnerability scanning workflow.
    """

    def __init__(
        self,
        db: Database = None,
        nvd_client: NVDClient = None,
        progress_callback: Callable[[str, int], None] = None,
    ):
        config = get_config()
        self.db = db or Database(config.database.path)
        self.nvd_client = nvd_client or NVDClient()
        self.cve_cache = CVECache()
        self.progress_callback = progress_callback

        self.scan_repo = ScanRepository(self.db)
        self.host_repo = HostRepository(self.db)
        self.service_repo = ServiceRepository(self.db)
        self.vuln_repo = VulnerabilityRepository(self.db)
        self.risk_repo = RiskResultRepository(self.db)
        self.verification_repo = VerificationResultRepository(self.db)

    def _report_progress(self, stage: str, percent: int):
        """Report progress to callback if available."""
        if self.progress_callback:
            self.progress_callback(stage, percent)

    def run(
        self,
        target_range: str,
        discovery_method: str = "icmp",
        port_range: str = "1-1024",
        service_scan: bool = True,
        verify_services: bool = False,
        vuln_match: bool = True,
        generate_report: bool = True,
        report_path: Optional[Path] = None,
        language: str = "zh_CN",
    ) -> PipelineResult:
        """
        Execute the complete scanning pipeline.

        Args:
            target_range: Target IP range (CIDR, range, or single IP)
            discovery_method: Host discovery method (icmp, arp, syn, all)
            port_range: Port range for SYN scanning
            service_scan: Whether to run service identification
            verify_services: Whether to run active verification
            vuln_match: Whether to match vulnerabilities
            generate_report: Whether to generate HTML report
            report_path: Optional custom report path
            language: Report language (zh_CN or en_US)

        Returns:
            PipelineResult with all discovered data
        """
        result = PipelineResult(scan=Scan(target_range=target_range))

        # Create scan record
        scan = Scan(
            target_range=target_range,
            started_at=datetime.now(),
            status=ScanStatus.RUNNING,
        )
        scan.id = self.scan_repo.create(scan)
        result.scan = scan

        try:
            # Stage 1: Host Discovery (0-30%)
            self._report_progress("host_discovery", 0)
            hosts = self._discover_hosts(target_range, discovery_method, port_range)
            result.hosts = hosts

            for host in hosts:
                host.scan_id = scan.id
                host.id = self.host_repo.create(host)

            self._report_progress("host_discovery", 30)
            logger.info(f"Discovered {len(hosts)} hosts")

            # Stage 2: Service Identification (30-60%)
            if service_scan and hosts:
                self._report_progress("service_scan", 30)
                services = self._scan_services(hosts)
                result.services = services

                for svc in services:
                    host = next((h for h in hosts if h.ip == svc.host_ip), None)
                    if host:
                        svc.host_id = host.id
                        svc.id = self.service_repo.create(svc)

                self._report_progress("service_scan", 55)
                logger.info(f"Identified {len(services)} services")

            # Stage 3: Active Verification (55-65%)
            if verify_services and result.services:
                self._report_progress("verification", 55)
                verification_results = self._verify_services(result.services)
                for vr in verification_results:
                    vr.scan_id = scan.id
                self.verification_repo.create_many(verification_results)
                result.verification_results = verification_results
                self._report_progress("verification", 65)
                logger.info(f"Verified {len(verification_results)} issues")

            # Stage 4: Vulnerability Matching (65-80%)
            if vuln_match and result.services:
                self._report_progress("vuln_match", 65)
                matches, vulns = self._match_vulnerabilities(result.services)
                result.matches = matches
                result.vulnerabilities = vulns

                for vuln in vulns:
                    existing = self.vuln_repo.get_by_cve_id(vuln.cve_id)
                    if not existing:
                        vuln.id = self.vuln_repo.create(vuln)
                    else:
                        vuln.id = existing.id

                self._report_progress("vuln_match", 80)
                logger.info(f"Matched {len(vulns)} vulnerabilities")

            # Stage 5: Risk Scoring (80-90%)
            self._report_progress("risk_scoring", 80)
            if result.hosts:
                scorer = RiskScorer()
                risk_results = scorer.score_hosts(
                    result.hosts, result.services, result.matches
                )
                result.risk_results = risk_results

                for rr in risk_results:
                    rr.scan_id = scan.id
                    rr.id = self.risk_repo.create(rr)

            self._report_progress("risk_scoring", 90)

            # Stage 6: Report Generation (90-100%)
            if generate_report:
                self._report_progress("report_gen", 90)
                report_generator = ReportGenerator(language=language)

                if not report_path:
                    config = get_config()
                    report_dir = Path(config.database.path).parent / "reports"
                    report_dir.mkdir(parents=True, exist_ok=True)
                    report_path = report_dir / f"scan_{scan.id}_{datetime.now():%Y%m%d_%H%M%S}.html"

                report_generator.generate(
                    scan=scan,
                    hosts=result.hosts,
                    services=result.services,
                    vulnerabilities=result.vulnerabilities,
                    risk_results=result.risk_results,
                    output_path=report_path,
                )
                result.report_path = report_path
                logger.info(f"Report generated: {report_path}")

            # Update scan status
            scan.status = ScanStatus.COMPLETED
            scan.finished_at = datetime.now()
            self.scan_repo.update(scan)

            self._report_progress("complete", 100)

        except Exception as e:
            logger.error(f"Pipeline error: {e}")
            result.errors.append(str(e))
            scan.status = ScanStatus.FAILED
            scan.finished_at = datetime.now()
            self.scan_repo.update(scan)
            raise

        return result

    def _discover_hosts(
        self, target_range: str, method: str, port_range: str
    ) -> List[Host]:
        """Run host discovery using specified method."""
        context = ScanContext(target_range=target_range, scan_id=0)
        all_hosts = {}

        if method in ("icmp", "all"):
            try:
                scanner = ICMPScanner()
                result = scanner.scan(context)
                for host in result.hosts:
                    all_hosts[host.ip] = host
            except Exception as e:
                logger.warning(f"ICMP scan failed: {e}")

        if method in ("arp", "all"):
            try:
                scanner = ARPScanner()
                result = scanner.scan(context)
                for host in result.hosts:
                    if host.ip not in all_hosts:
                        all_hosts[host.ip] = host
                    elif host.mac:
                        all_hosts[host.ip].mac = host.mac
            except Exception as e:
                logger.warning(f"ARP scan failed: {e}")

        if method in ("syn", "all"):
            try:
                scanner = SYNScanner(port_range=port_range)
                context.options["port_range"] = port_range
                result = scanner.scan(context)
                for host in result.hosts:
                    if host.ip not in all_hosts:
                        all_hosts[host.ip] = host
            except Exception as e:
                logger.warning(f"SYN scan failed: {e}")

        return list(all_hosts.values())

    def _scan_services(self, hosts: List[Host]) -> List[Service]:
        """Run service identification on discovered hosts."""
        context = ScanContext(target_range="", scan_id=0, discovered_hosts=hosts)

        try:
            scanner = NmapScanner()
            result = scanner.scan(context)
            return result.services
        except Exception as e:
            logger.error(f"Service scan failed: {e}")
            return []

    def _match_vulnerabilities(
        self, services: List[Service]
    ) -> tuple[List[MatchResult], List[Vulnerability]]:
        """Match services against vulnerability database."""
        matcher = VulnerabilityMatcher(client=self.nvd_client, cache=self.cve_cache)

        matches = matcher.match_services(services)

        seen_vulns = {}
        for match in matches:
            vuln = match.vulnerability
            if vuln.cve_id not in seen_vulns:
                seen_vulns[vuln.cve_id] = vuln

        return matches, list(seen_vulns.values())

    def _verify_services(self, services: List[Service]) -> List[VerificationResult]:
        """Run active verification against discovered services."""
        from ..verifiers import NseVulnVerifier, WeakPasswordVerifier, TlsAuditVerifier

        verifiers = [
            NseVulnVerifier(),
            WeakPasswordVerifier(),
            TlsAuditVerifier(),
        ]

        results: List[VerificationResult] = []
        for verifier in verifiers:
            try:
                results.extend(verifier.verify(services))
            except Exception as e:
                logger.warning(f"Verification {verifier.name} failed: {e}")

        return results
