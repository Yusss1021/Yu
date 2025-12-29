"""
Vulnerability Matcher - Match services to known CVEs.
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..core.models import Service, ServiceVuln, Vulnerability
from .cache import CVECache
from .client import NVDClient

logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """Result of a vulnerability match."""
    vulnerability: Vulnerability
    service: Service
    match_type: str  # cpe_exact, cpe_partial, keyword
    confidence: float  # 0.0 - 1.0


class VulnerabilityMatcher:
    """
    Matches services to known vulnerabilities.

    Uses multiple strategies:
    1. CPE exact match
    2. CPE partial match (vendor/product)
    3. Keyword search (product name + version)
    """

    def __init__(self, client: NVDClient = None, cache: CVECache = None):
        """
        Initialize matcher.

        Args:
            client: NVD API client
            cache: CVE cache
        """
        self.client = client or NVDClient()
        self.cache = cache or CVECache()

    def match_service(self, service: Service) -> List[MatchResult]:
        """
        Find vulnerabilities matching a service.

        Args:
            service: Service to match

        Returns:
            List of MatchResult objects
        """
        results = []

        # Strategy 1: CPE exact match
        if service.cpe:
            cpe_results = self._match_by_cpe(service, service.cpe)
            results.extend(cpe_results)

        # Strategy 2: Build CPE from product/version
        if not results and service.product:
            guessed_cpe = self._guess_cpe(service)
            if guessed_cpe:
                cpe_results = self._match_by_cpe(service, guessed_cpe, partial=True)
                results.extend(cpe_results)

        # Strategy 3: Keyword search
        if not results and service.product:
            keyword_results = self._match_by_keyword(service)
            results.extend(keyword_results)

        return results

    def match_services(self, services: List[Service]) -> List[MatchResult]:
        """
        Find vulnerabilities for multiple services.

        Args:
            services: List of services to match

        Returns:
            List of MatchResult objects
        """
        all_results = []

        for service in services:
            results = self.match_service(service)
            all_results.extend(results)

        return all_results

    def _match_by_cpe(
        self,
        service: Service,
        cpe: str,
        partial: bool = False,
    ) -> List[MatchResult]:
        """
        Match service by CPE.

        Args:
            service: Service being matched
            cpe: CPE string to search
            partial: Whether this is a partial/guessed CPE

        Returns:
            List of MatchResult objects
        """
        results = []

        # Check cache first
        vulns = self.cache.get_by_cpe(cpe)

        # If not in cache, query API
        if not vulns:
            vulns = self.client.search_by_cpe(cpe)
            self.cache.put_many(vulns)

        for vuln in vulns:
            # Check version if available
            if service.version and vuln.affected_cpe:
                if not self._version_matches(service.version, vuln.affected_cpe):
                    continue

            match_type = "cpe_partial" if partial else "cpe_exact"
            confidence = 0.7 if partial else 0.95

            results.append(MatchResult(
                vulnerability=vuln,
                service=service,
                match_type=match_type,
                confidence=confidence,
            ))

        return results

    def _match_by_keyword(self, service: Service) -> List[MatchResult]:
        """
        Match service by keyword search.

        Args:
            service: Service to match

        Returns:
            List of MatchResult objects
        """
        results = []

        # Build search keyword
        keyword = service.product
        if service.version:
            keyword = f"{service.product} {service.version}"

        # Search NVD
        vulns = self.client.search_by_keyword(keyword)

        for vuln in vulns:
            # Filter by version if possible
            if service.version and vuln.description:
                if not self._description_mentions_version(
                    vuln.description, service.version
                ):
                    continue

            results.append(MatchResult(
                vulnerability=vuln,
                service=service,
                match_type="keyword",
                confidence=0.5,  # Lower confidence for keyword matches
            ))

        return results

    def _guess_cpe(self, service: Service) -> Optional[str]:
        """
        Attempt to construct a CPE from service information.

        Args:
            service: Service with product information

        Returns:
            Guessed CPE string or None
        """
        if not service.product:
            return None

        # Normalize product name
        vendor = self._normalize_vendor(service.product)
        product = self._normalize_product(service.product)

        if not vendor or not product:
            return None

        # Build CPE 2.3 format
        version = service.version or "*"
        version = self._normalize_version(version)

        cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        return cpe

    def _normalize_vendor(self, product: str) -> Optional[str]:
        """
        Guess vendor from product name.

        Args:
            product: Product name

        Returns:
            Normalized vendor name
        """
        product_lower = product.lower()

        # Common mappings
        vendor_map = {
            "openssh": "openbsd",
            "openssl": "openssl",
            "apache": "apache",
            "nginx": "nginx",
            "mysql": "oracle",
            "mariadb": "mariadb",
            "postgresql": "postgresql",
            "mongodb": "mongodb",
            "redis": "redis",
            "vsftpd": "vsftpd_project",
            "proftpd": "proftpd",
            "bind": "isc",
            "postfix": "postfix",
            "exim": "exim",
            "samba": "samba",
            "squid": "squid-cache",
            "tomcat": "apache",
            "jetty": "eclipse",
            "iis": "microsoft",
            "exchange": "microsoft",
        }

        for key, vendor in vendor_map.items():
            if key in product_lower:
                return vendor

        # Default: use first word
        words = re.split(r"[\s\-_/]", product_lower)
        return words[0] if words else None

    def _normalize_product(self, product: str) -> Optional[str]:
        """
        Normalize product name for CPE.

        Args:
            product: Raw product name

        Returns:
            Normalized product name
        """
        # Remove common suffixes/prefixes
        product = product.lower()
        product = re.sub(r"\s+", "_", product)
        product = re.sub(r"[^\w_]", "", product)
        return product if product else None

    def _normalize_version(self, version: str) -> str:
        """
        Normalize version string for CPE.

        Args:
            version: Raw version string

        Returns:
            Normalized version
        """
        # Extract version number
        match = re.search(r"(\d+(?:\.\d+)*)", version)
        if match:
            return match.group(1)
        return version.replace(" ", "_")

    def _version_matches(self, service_version: str, affected_cpe: str) -> bool:
        """
        Check if service version is in affected range.

        Args:
            service_version: Service version string
            affected_cpe: CPE string with version info

        Returns:
            True if version might be affected
        """
        # Simple check: version appears in CPE
        normalized = self._normalize_version(service_version)

        # If CPE has wildcard, it might match
        if ":*:" in affected_cpe:
            return True

        return normalized in affected_cpe

    def _description_mentions_version(self, description: str, version: str) -> bool:
        """
        Check if CVE description mentions the version.

        Args:
            description: CVE description
            version: Version string

        Returns:
            True if version is mentioned
        """
        normalized = self._normalize_version(version)

        # Check for version in description
        if normalized in description:
            return True

        # Check for version range patterns
        version_pattern = r"before\s+(\d+(?:\.\d+)*)|through\s+(\d+(?:\.\d+)*)"
        matches = re.findall(version_pattern, description, re.IGNORECASE)

        for match in matches:
            for v in match:
                if v and self._compare_versions(normalized, v) <= 0:
                    return True

        return False

    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.

        Args:
            v1: First version
            v2: Second version

        Returns:
            -1 if v1 < v2, 0 if equal, 1 if v1 > v2
        """
        def parse_version(v):
            return [int(x) for x in re.split(r"[._-]", v) if x.isdigit()]

        parts1 = parse_version(v1)
        parts2 = parse_version(v2)

        # Pad shorter version
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))

        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1

        return 0


def create_service_vulns(matches: List[MatchResult]) -> List[ServiceVuln]:
    """
    Convert MatchResults to ServiceVuln objects.

    Args:
        matches: List of match results

    Returns:
        List of ServiceVuln objects
    """
    vulns = []

    for match in matches:
        if match.service.id and match.vulnerability.id:
            vulns.append(ServiceVuln(
                service_id=match.service.id,
                vuln_id=match.vulnerability.id,
                match_type=match.match_type,
                confidence=match.confidence,
            ))

    return vulns
