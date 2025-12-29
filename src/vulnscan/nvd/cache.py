"""
CVE Cache - Local caching of NVD vulnerability data.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from ..config import get_config
from ..core.models import Severity, Vulnerability
from ..storage.repository import VulnerabilityRepository

logger = logging.getLogger(__name__)


class CVECache:
    """
    Local cache for CVE data.

    Stores vulnerability data in SQLite database and/or JSON files
    to reduce API calls and improve performance.
    """

    def __init__(self, cache_dir: Path = None, ttl: int = None):
        """
        Initialize CVE cache.

        Args:
            cache_dir: Directory for JSON cache files
            ttl: Cache time-to-live in seconds
        """
        config = get_config()
        self.cache_dir = cache_dir or config.nvd.cache_dir
        self.ttl = ttl or config.nvd.cache_ttl

        # Ensure cache directory exists
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Repository for database storage
        self.repo = VulnerabilityRepository()

    def get(self, cve_id: str) -> Optional[Vulnerability]:
        """
        Get a CVE from cache.

        Args:
            cve_id: CVE identifier

        Returns:
            Vulnerability object or None if not cached
        """
        # Try database first
        vuln = self.repo.get_by_cve(cve_id)
        if vuln:
            return vuln

        # Try JSON file cache
        return self._get_from_file(cve_id)

    def get_by_cpe(self, cpe: str) -> List[Vulnerability]:
        """
        Get CVEs affecting a CPE from cache.

        Args:
            cpe: CPE string

        Returns:
            List of matching vulnerabilities
        """
        # Search in database
        return self.repo.search_by_cpe(cpe)

    def put(self, vuln: Vulnerability) -> None:
        """
        Store a CVE in cache.

        Args:
            vuln: Vulnerability to cache
        """
        # Store in database
        self.repo.upsert(vuln)

        # Optionally store in JSON file
        self._save_to_file(vuln)

    def put_many(self, vulns: List[Vulnerability]) -> None:
        """
        Store multiple CVEs in cache.

        Args:
            vulns: List of vulnerabilities to cache
        """
        for vuln in vulns:
            self.put(vuln)

    def bulk_put(self, vulns: List[Vulnerability], batch_size: int = 1000) -> int:
        """
        Bulk store CVEs with optimized batch commits.

        Args:
            vulns: List of vulnerabilities to cache
            batch_size: Number of records per commit

        Returns:
            Number of CVEs stored
        """
        count = 0
        for i in range(0, len(vulns), batch_size):
            batch = vulns[i:i + batch_size]
            for vuln in batch:
                self.repo.upsert(vuln)
            count += len(batch)
        return count

    def is_fresh(self, cpe: str) -> bool:
        """
        Check if cache for a CPE is fresh (within TTL).

        Args:
            cpe: CPE string

        Returns:
            True if cache is fresh
        """
        meta_file = self._get_meta_path(cpe)
        if not meta_file.exists():
            return False

        try:
            with open(meta_file, "r") as f:
                meta = json.load(f)

            last_updated = datetime.fromisoformat(meta.get("last_updated", ""))
            age = (datetime.now() - last_updated).total_seconds()
            return age < self.ttl

        except (json.JSONDecodeError, ValueError):
            return False

    def update_meta(self, cpe: str, result_count: int) -> None:
        """
        Update cache metadata for a CPE.

        Args:
            cpe: CPE string
            result_count: Number of results cached
        """
        meta_file = self._get_meta_path(cpe)
        meta = {
            "cpe": cpe,
            "last_updated": datetime.now().isoformat(),
            "result_count": result_count,
        }

        with open(meta_file, "w") as f:
            json.dump(meta, f)

    def clear(self) -> None:
        """Clear all cached data."""
        # Clear JSON files
        for file in self.cache_dir.glob("*.json"):
            file.unlink()

        logger.info("CVE cache cleared")

    def _get_from_file(self, cve_id: str) -> Optional[Vulnerability]:
        """Load a CVE from JSON file cache."""
        file_path = self._get_cve_path(cve_id)
        if not file_path.exists():
            return None

        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            return Vulnerability(
                cve_id=data["cve_id"],
                description=data.get("description"),
                cvss_base=data.get("cvss_base", 0.0),
                cvss_vector=data.get("cvss_vector"),
                severity=Severity[data.get("severity", "LOW")],
                affected_cpe=data.get("affected_cpe"),
            )

        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to load cached CVE {cve_id}: {e}")
            return None

    def _save_to_file(self, vuln: Vulnerability) -> None:
        """Save a CVE to JSON file cache."""
        file_path = self._get_cve_path(vuln.cve_id)

        data = {
            "cve_id": vuln.cve_id,
            "description": vuln.description,
            "cvss_base": vuln.cvss_base,
            "cvss_vector": vuln.cvss_vector,
            "severity": vuln.severity.value if vuln.severity else "LOW",
            "affected_cpe": vuln.affected_cpe,
            "cached_at": datetime.now().isoformat(),
        }

        try:
            with open(file_path, "w") as f:
                json.dump(data, f)
        except IOError as e:
            logger.warning(f"Failed to cache CVE {vuln.cve_id}: {e}")

    def _get_cve_path(self, cve_id: str) -> Path:
        """Get file path for a CVE cache file."""
        # Normalize CVE ID for filename
        safe_id = cve_id.replace("-", "_").replace(":", "_")
        return self.cache_dir / f"{safe_id}.json"

    def _get_meta_path(self, cpe: str) -> Path:
        """Get file path for CPE metadata cache."""
        # Hash CPE for filename (CPEs can be long)
        import hashlib

        cpe_hash = hashlib.md5(cpe.encode()).hexdigest()[:16]
        return self.cache_dir / f"meta_{cpe_hash}.json"


class BulkCVELoader:
    """
    Utility for bulk loading CVE data from NVD.

    Useful for initial cache population or periodic updates.
    """

    def __init__(self, client, cache: CVECache):
        """
        Initialize bulk loader.

        Args:
            client: NVDClient instance
            cache: CVECache instance
        """
        self.client = client
        self.cache = cache

    def load_by_cpe(self, cpe: str, force: bool = False) -> int:
        """
        Load all CVEs for a CPE into cache.

        Args:
            cpe: CPE string
            force: Force refresh even if cache is fresh

        Returns:
            Number of CVEs loaded
        """
        if not force and self.cache.is_fresh(cpe):
            logger.debug(f"Cache for {cpe} is fresh, skipping")
            return 0

        logger.info(f"Loading CVEs for CPE: {cpe}")

        vulns = self.client.search_by_cpe(cpe)
        self.cache.put_many(vulns)
        self.cache.update_meta(cpe, len(vulns))

        logger.info(f"Loaded {len(vulns)} CVEs for {cpe}")
        return len(vulns)

    def load_recent(self, days: int = 30) -> int:
        """
        Load recently published CVEs.

        Args:
            days: Number of days back to fetch

        Returns:
            Number of CVEs loaded
        """
        end = datetime.now()
        start = end - timedelta(days=days)

        logger.info(f"Loading CVEs published in last {days} days")

        vulns = self.client.search_by_date_range(pub_start=start, pub_end=end)
        self.cache.put_many(vulns)

        logger.info(f"Loaded {len(vulns)} recent CVEs")
        return len(vulns)
