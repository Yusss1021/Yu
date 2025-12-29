"""
NVD API Client - Interface to NIST National Vulnerability Database API 2.0.
"""

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import requests

from ..config import get_config
from ..core.models import Severity, Vulnerability

logger = logging.getLogger(__name__)


class RateLimiter:
    """Token bucket rate limiter for API requests."""

    def __init__(self, rate: float):
        """
        Initialize rate limiter.

        Args:
            rate: Maximum requests per second
        """
        self.rate = rate
        self.interval = 1.0 / rate
        self.last_request = 0.0

    def wait(self) -> None:
        """Wait until next request is allowed."""
        now = time.time()
        elapsed = now - self.last_request
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last_request = time.time()


class NVDClient:
    """
    Client for NVD API 2.0.

    Provides methods to search CVEs by:
    - CPE name
    - Keyword
    - CVE ID
    - Date range
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str = None, rate_limit: float = None):
        """
        Initialize NVD client.

        Args:
            api_key: NVD API key (optional, increases rate limit)
            rate_limit: Requests per second
        """
        config = get_config()
        self.api_key = api_key or config.nvd.api_key
        rate = rate_limit or config.nvd.rate_limit

        # With API key, rate limit is 50 req/30s = ~1.67/s
        # Without, it's 5 req/30s = ~0.17/s
        if self.api_key and rate_limit is None:
            rate = 1.5
        elif not self.api_key and rate_limit is None:
            rate = 0.15

        self.rate_limiter = RateLimiter(rate)
        self.session = requests.Session()

        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

    def search_by_cpe(
        self,
        cpe_name: str,
        results_per_page: int = 100,
        start_index: int = 0,
    ) -> List[Vulnerability]:
        """
        Search CVEs affecting a specific CPE.

        Args:
            cpe_name: CPE 2.3 formatted string
            results_per_page: Number of results per page (max 2000)
            start_index: Starting index for pagination

        Returns:
            List of Vulnerability objects
        """
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }

        return self._search(params)

    def search_by_keyword(
        self,
        keyword: str,
        exact_match: bool = False,
        results_per_page: int = 100,
    ) -> List[Vulnerability]:
        """
        Search CVEs by keyword.

        Args:
            keyword: Search keyword
            exact_match: Whether to match exactly
            results_per_page: Number of results

        Returns:
            List of Vulnerability objects
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        }

        if exact_match:
            params["keywordExactMatch"] = ""

        return self._search(params)

    def get_cve(self, cve_id: str) -> Optional[Vulnerability]:
        """
        Get a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            Vulnerability object or None
        """
        params = {"cveId": cve_id}
        results = self._search(params)
        return results[0] if results else None

    def search_by_date_range(
        self,
        pub_start: datetime = None,
        pub_end: datetime = None,
        mod_start: datetime = None,
        mod_end: datetime = None,
        results_per_page: int = 100,
    ) -> List[Vulnerability]:
        """
        Search CVEs by publication or modification date.

        Args:
            pub_start: Publication date start
            pub_end: Publication date end
            mod_start: Modification date start
            mod_end: Modification date end
            results_per_page: Number of results

        Returns:
            List of Vulnerability objects
        """
        params = {"resultsPerPage": results_per_page}

        if pub_start:
            params["pubStartDate"] = pub_start.isoformat()
        if pub_end:
            params["pubEndDate"] = pub_end.isoformat()
        if mod_start:
            params["lastModStartDate"] = mod_start.isoformat()
        if mod_end:
            params["lastModEndDate"] = mod_end.isoformat()

        return self._search(params)

    def search_by_severity(
        self,
        severity: str,
        cvss_version: str = "V3",
        results_per_page: int = 100,
    ) -> List[Vulnerability]:
        """
        Search CVEs by CVSS severity.

        Args:
            severity: CRITICAL, HIGH, MEDIUM, or LOW
            cvss_version: V2 or V3
            results_per_page: Number of results

        Returns:
            List of Vulnerability objects
        """
        params = {
            f"cvssV3Severity": severity.upper(),
            "resultsPerPage": results_per_page,
        }

        return self._search(params)

    def _search(self, params: Dict[str, Any]) -> List[Vulnerability]:
        """
        Execute API search request.

        Args:
            params: Query parameters

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities = []

        # Rate limiting
        self.rate_limiter.wait()

        try:
            url = f"{self.BASE_URL}?{urlencode(params)}"
            logger.debug(f"NVD API request: {url}")

            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()
            total_results = data.get("totalResults", 0)

            logger.info(f"NVD API returned {total_results} results")

            # Parse vulnerabilities
            for item in data.get("vulnerabilities", []):
                vuln = self._parse_cve(item)
                if vuln:
                    vulnerabilities.append(vuln)

        except requests.exceptions.RequestException as e:
            logger.error(f"NVD API request failed: {e}")
        except (KeyError, ValueError) as e:
            logger.error(f"NVD API response parse error: {e}")

        return vulnerabilities

    def _parse_cve(self, item: dict) -> Optional[Vulnerability]:
        """
        Parse a CVE item from NVD API response.

        Args:
            item: CVE item dictionary

        Returns:
            Vulnerability object or None
        """
        try:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")

            # Get description (English preferred)
            description = ""
            descriptions = cve.get("descriptions", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Get CVSS metrics
            cvss_base = 0.0
            cvss_vector = ""
            severity = Severity.LOW

            metrics = cve.get("metrics", {})

            # Try CVSS 3.1 first, then 3.0, then 2.0
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]["cvssData"]
                cvss_base = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity_str = cvss_data.get("baseSeverity", "LOW")
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0]["cvssData"]
                cvss_base = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity_str = cvss_data.get("baseSeverity", "LOW")
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]["cvssData"]
                cvss_base = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity_str = self._cvss2_to_severity(cvss_base)
            else:
                severity_str = "LOW"

            # Convert severity string to enum
            severity = Severity[severity_str.upper()] if severity_str else Severity.LOW

            # Get dates
            published = cve.get("published")
            last_modified = cve.get("lastModified")

            published_at = None
            if published:
                published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))

            last_modified_at = None
            if last_modified:
                last_modified_at = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))

            # Get affected CPEs
            affected_cpes = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        if cpe_match.get("vulnerable"):
                            affected_cpes.append(cpe_match.get("criteria", ""))

            return Vulnerability(
                cve_id=cve_id,
                description=description[:2000] if description else None,  # Truncate
                cvss_base=cvss_base,
                cvss_vector=cvss_vector,
                severity=severity,
                published_at=published_at,
                last_modified=last_modified_at,
                affected_cpe=",".join(affected_cpes[:10]) if affected_cpes else None,
            )

        except Exception as e:
            logger.warning(f"Failed to parse CVE: {e}")
            return None

    def _cvss2_to_severity(self, score: float) -> str:
        """Convert CVSS 2.0 score to severity string."""
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"
