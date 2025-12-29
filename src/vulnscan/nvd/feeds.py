"""
NVD Data Feeds - Offline bulk import from NVD JSON feeds.

Supports hybrid mode: offline bulk import + online incremental updates.
"""

import gzip
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Generator, Iterator, List, Optional, Tuple

import requests

from ..config import get_config
from ..core.models import Severity, Vulnerability

logger = logging.getLogger(__name__)


class FeedType(Enum):
    YEARLY = "yearly"
    MODIFIED = "modified"
    RECENT = "recent"


@dataclass
class FeedMeta:
    feed_type: FeedType
    year: Optional[int]
    url: str
    local_path: Path
    sha256: Optional[str] = None
    size: int = 0
    last_modified: Optional[datetime] = None
    cve_count: int = 0


@dataclass
class DownloadProgress:
    feed: FeedMeta
    bytes_downloaded: int
    total_bytes: int
    is_complete: bool


@dataclass
class ParseProgress:
    feed: FeedMeta
    cves_parsed: int
    total_cves: int
    is_complete: bool


@dataclass
class SyncState:
    last_full_sync: Optional[datetime]
    last_incremental_sync: Optional[datetime]
    total_cve_count: int
    feeds_imported: List[int]
    is_initialized: bool


@dataclass
class SyncResult:
    mode: str
    started_at: datetime
    finished_at: datetime
    cves_added: int = 0
    cves_updated: int = 0
    cves_total: int = 0
    feeds_processed: List[int] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def success(self) -> bool:
        return len(self.errors) == 0


class FeedDownloader:
    """
    Downloads NVD Data Feed files with checkpointing support.
    """

    NVD_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
    CURRENT_YEAR = datetime.now().year
    AVAILABLE_YEARS = range(2002, CURRENT_YEAR + 1)

    def __init__(
        self,
        cache_dir: Path = None,
        progress_callback: Callable[[DownloadProgress], None] = None,
    ):
        config = get_config()
        self.cache_dir = cache_dir or config.nvd.cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.progress_callback = progress_callback
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "VulnScanner/1.0"

    def get_feed_url(self, year: int) -> str:
        return f"{self.NVD_FEED_BASE}/nvdcve-1.1-{year}.json.gz"

    def get_meta_url(self, year: int) -> str:
        return f"{self.NVD_FEED_BASE}/nvdcve-1.1-{year}.meta"

    def download_feed(self, year: int, force: bool = False) -> FeedMeta:
        if year not in self.AVAILABLE_YEARS:
            raise ValueError(f"Year {year} not available (2002-{self.CURRENT_YEAR})")

        url = self.get_feed_url(year)
        local_path = self.cache_dir / f"nvdcve-1.1-{year}.json.gz"

        feed = FeedMeta(
            feed_type=FeedType.YEARLY,
            year=year,
            url=url,
            local_path=local_path,
        )

        # Check if already downloaded
        if local_path.exists() and not force:
            feed.size = local_path.stat().st_size
            logger.info(f"Feed {year} already exists ({feed.size} bytes)")
            return feed

        # Fetch metadata for size info
        try:
            meta = self._fetch_meta(year)
            if meta:
                feed.sha256, feed.size, feed.last_modified = meta
        except Exception as e:
            logger.warning(f"Could not fetch meta for {year}: {e}")

        # Download with resume support
        self._download_with_resume(url, local_path, feed.size)
        feed.size = local_path.stat().st_size

        logger.info(f"Downloaded feed {year}: {feed.size} bytes")
        return feed

    def download_feeds(
        self,
        years: List[int] = None,
        force: bool = False,
    ) -> Generator[FeedMeta, None, None]:
        if years is None:
            years = list(self.AVAILABLE_YEARS)

        for year in years:
            try:
                feed = self.download_feed(year, force)
                yield feed
            except Exception as e:
                logger.error(f"Failed to download feed {year}: {e}")

    def verify_feed(self, feed: FeedMeta) -> bool:
        if not feed.sha256 or not feed.local_path.exists():
            return False

        sha256_hash = hashlib.sha256()
        with open(feed.local_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)

        calculated = sha256_hash.hexdigest().upper()
        return calculated == feed.sha256.upper()

    def get_local_feeds(self) -> List[FeedMeta]:
        feeds = []
        for path in self.cache_dir.glob("nvdcve-1.1-*.json.gz"):
            match = re.search(r"nvdcve-1\.1-(\d{4})\.json\.gz", path.name)
            if match:
                year = int(match.group(1))
                feeds.append(FeedMeta(
                    feed_type=FeedType.YEARLY,
                    year=year,
                    url=self.get_feed_url(year),
                    local_path=path,
                    size=path.stat().st_size,
                ))
        return sorted(feeds, key=lambda f: f.year or 0)

    def _fetch_meta(self, year: int) -> Optional[Tuple[str, int, datetime]]:
        url = self.get_meta_url(year)
        response = self.session.get(url, timeout=30)
        response.raise_for_status()

        sha256 = None
        size = 0
        last_modified = None

        for line in response.text.strip().split("\n"):
            if line.startswith("sha256:"):
                sha256 = line.split(":", 1)[1].strip()
            elif line.startswith("gzSize:"):
                size = int(line.split(":", 1)[1].strip())
            elif line.startswith("lastModifiedDate:"):
                date_str = line.split(":", 1)[1].strip()
                try:
                    last_modified = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

        return sha256, size, last_modified

    def _download_with_resume(
        self,
        url: str,
        dest_path: Path,
        expected_size: int,
    ) -> None:
        headers = {}
        mode = "wb"
        downloaded = 0

        # Check for partial download
        if dest_path.exists():
            downloaded = dest_path.stat().st_size
            if expected_size and downloaded < expected_size:
                headers["Range"] = f"bytes={downloaded}-"
                mode = "ab"
                logger.info(f"Resuming download from {downloaded} bytes")
            elif downloaded == expected_size:
                return  # Already complete

        response = self.session.get(url, headers=headers, stream=True, timeout=60)
        response.raise_for_status()

        total_size = expected_size or int(response.headers.get("content-length", 0))

        with open(dest_path, mode) as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)

                    if self.progress_callback:
                        progress = DownloadProgress(
                            feed=FeedMeta(FeedType.YEARLY, None, url, dest_path),
                            bytes_downloaded=downloaded,
                            total_bytes=total_size,
                            is_complete=downloaded >= total_size if total_size else False,
                        )
                        self.progress_callback(progress)


class FeedParser:
    """
    Memory-efficient parser for NVD feed files.
    Uses standard json with gzip decompression for simplicity.
    """

    def __init__(
        self,
        progress_callback: Callable[[ParseProgress], None] = None,
        batch_size: int = 1000,
    ):
        self.progress_callback = progress_callback
        self.batch_size = batch_size

    def parse_feed(
        self,
        feed_path: Path,
    ) -> Generator[List[Vulnerability], None, None]:
        batch = []

        for vuln in self.parse_feed_streaming(feed_path):
            batch.append(vuln)
            if len(batch) >= self.batch_size:
                yield batch
                batch = []

        if batch:
            yield batch

    def parse_feed_streaming(
        self,
        feed_path: Path,
    ) -> Iterator[Vulnerability]:
        logger.info(f"Parsing feed: {feed_path}")

        with gzip.open(feed_path, "rt", encoding="utf-8") as f:
            data = json.load(f)

        cve_items = data.get("CVE_Items", [])
        total = len(cve_items)

        logger.info(f"Found {total} CVE items in feed")

        feed_meta = FeedMeta(
            feed_type=FeedType.YEARLY,
            year=None,
            url="",
            local_path=feed_path,
            cve_count=total,
        )

        for idx, item in enumerate(cve_items):
            vuln = self.transform_cve_item(item)
            if vuln:
                yield vuln

            if self.progress_callback and (idx + 1) % 1000 == 0:
                self.progress_callback(ParseProgress(
                    feed=feed_meta,
                    cves_parsed=idx + 1,
                    total_cves=total,
                    is_complete=False,
                ))

        if self.progress_callback:
            self.progress_callback(ParseProgress(
                feed=feed_meta,
                cves_parsed=total,
                total_cves=total,
                is_complete=True,
            ))

    def transform_cve_item(self, item: dict) -> Optional[Vulnerability]:
        try:
            cve = item.get("cve", {})
            cve_meta = cve.get("CVE_data_meta", {})
            cve_id = cve_meta.get("ID", "")

            if not cve_id:
                return None

            description = self._extract_description(cve)
            cvss_base, cvss_vector, severity = self._extract_cvss(item.get("impact", {}))
            affected_cpes = self._extract_cpes(item.get("configurations", {}))

            published_at = self._parse_date(item.get("publishedDate"))
            last_modified = self._parse_date(item.get("lastModifiedDate"))

            return Vulnerability(
                cve_id=cve_id,
                description=description[:2000] if description else None,
                cvss_base=cvss_base,
                cvss_vector=cvss_vector,
                severity=severity,
                published_at=published_at,
                last_modified=last_modified,
                affected_cpe=",".join(affected_cpes[:10]) if affected_cpes else None,
            )

        except Exception as e:
            logger.warning(f"Failed to parse CVE item: {e}")
            return None

    def _extract_description(self, cve_data: dict) -> str:
        desc_data = cve_data.get("description", {}).get("description_data", [])
        for desc in desc_data:
            if desc.get("lang") == "en":
                return desc.get("value", "")
        return desc_data[0].get("value", "") if desc_data else ""

    def _extract_cvss(self, impact: dict) -> Tuple[float, str, Severity]:
        # Try CVSS 3.x first
        if "baseMetricV3" in impact:
            cvss = impact["baseMetricV3"].get("cvssV3", {})
            score = cvss.get("baseScore", 0.0)
            vector = cvss.get("vectorString", "")
            sev_str = cvss.get("baseSeverity", "LOW")
        elif "baseMetricV2" in impact:
            cvss = impact["baseMetricV2"].get("cvssV2", {})
            score = cvss.get("baseScore", 0.0)
            vector = cvss.get("vectorString", "")
            sev_str = self._cvss2_to_severity(score)
        else:
            return 0.0, "", Severity.LOW

        try:
            severity = Severity[sev_str.upper()]
        except (KeyError, AttributeError):
            severity = Severity.LOW

        return score, vector, severity

    def _cvss2_to_severity(self, score: float) -> str:
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        return "LOW"

    def _extract_cpes(self, configurations: dict) -> List[str]:
        cpes = []
        nodes = configurations.get("nodes", [])

        for node in nodes:
            for cpe_match in node.get("cpe_match", []):
                if cpe_match.get("vulnerable"):
                    cpes.append(cpe_match.get("cpe23Uri", ""))

            # Handle nested children
            for child in node.get("children", []):
                for cpe_match in child.get("cpe_match", []):
                    if cpe_match.get("vulnerable"):
                        cpes.append(cpe_match.get("cpe23Uri", ""))

        return [c for c in cpes if c]

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            return None


class HybridSyncCoordinator:
    """
    Coordinates hybrid data synchronization between offline feeds and online API.
    """

    INCREMENTAL_DAYS = 7
    DEFAULT_YEARS = list(range(2020, datetime.now().year + 1))

    def __init__(
        self,
        db=None,
        client=None,
        downloader: FeedDownloader = None,
        parser: FeedParser = None,
    ):
        from ..storage.database import get_db
        from ..storage.repository import VulnerabilityRepository
        from .client import NVDClient

        self.db = db or get_db()
        self.vuln_repo = VulnerabilityRepository(db=self.db)
        self.client = client or NVDClient()
        self.downloader = downloader or FeedDownloader()
        self.parser = parser or FeedParser()

    def sync(
        self,
        mode: str = "auto",
        years: List[int] = None,
        force: bool = False,
        progress_callback: Callable = None,
    ) -> SyncResult:
        started_at = datetime.now()
        result = SyncResult(
            mode=mode,
            started_at=started_at,
            finished_at=started_at,
        )

        try:
            if mode == "auto":
                if self._needs_full_sync():
                    mode = "full"
                else:
                    mode = "incremental"
                result.mode = mode

            if mode == "full":
                result = self._sync_full(years or self.DEFAULT_YEARS, progress_callback, result)
            else:
                result = self._sync_incremental(progress_callback, result)

        except Exception as e:
            result.errors.append(str(e))
            logger.error(f"Sync failed: {e}")

        result.finished_at = datetime.now()
        return result

    def get_sync_state(self) -> SyncState:
        cursor = self.db.conn.execute(
            "SELECT last_full_sync, last_incremental_sync, total_cve_count, is_initialized "
            "FROM nvd_sync_state WHERE id = 1"
        )
        row = cursor.fetchone()

        if not row:
            return SyncState(
                last_full_sync=None,
                last_incremental_sync=None,
                total_cve_count=0,
                feeds_imported=[],
                is_initialized=False,
            )

        # Get imported years
        cursor = self.db.conn.execute("SELECT year FROM nvd_feed_imports ORDER BY year")
        years = [r[0] for r in cursor.fetchall()]

        return SyncState(
            last_full_sync=datetime.fromisoformat(row[0]) if row[0] else None,
            last_incremental_sync=datetime.fromisoformat(row[1]) if row[1] else None,
            total_cve_count=row[2],
            feeds_imported=years,
            is_initialized=bool(row[3]),
        )

    def _needs_full_sync(self) -> bool:
        state = self.get_sync_state()
        return not state.is_initialized

    def _sync_full(
        self,
        years: List[int],
        progress_callback: Callable,
        result: SyncResult,
    ) -> SyncResult:
        logger.info(f"Starting full sync for years: {years}")

        for year in years:
            try:
                # Download feed
                feed = self.downloader.download_feed(year, force=False)

                # Parse and import
                count = 0
                for batch in self.parser.parse_feed(feed.local_path):
                    for vuln in batch:
                        existing = self.vuln_repo.get_by_cve(vuln.cve_id)
                        if existing:
                            self.vuln_repo.update(vuln)
                            result.cves_updated += 1
                        else:
                            self.vuln_repo.create(vuln)
                            result.cves_added += 1
                        count += 1

                # Record import
                self._record_feed_import(year, count)
                result.feeds_processed.append(year)

                if progress_callback:
                    progress_callback(f"Imported {year}: {count} CVEs")

            except Exception as e:
                result.errors.append(f"Year {year}: {str(e)}")
                logger.error(f"Failed to sync year {year}: {e}")

        # Update sync state
        self._update_sync_state(full_sync=True)
        result.cves_total = self.vuln_repo.count()

        return result

    def _sync_incremental(
        self,
        progress_callback: Callable,
        result: SyncResult,
    ) -> SyncResult:
        logger.info("Starting incremental sync")

        end_date = datetime.now()
        start_date = end_date - timedelta(days=self.INCREMENTAL_DAYS)

        try:
            vulns = self.client.search_by_date_range(
                mod_start=start_date,
                mod_end=end_date,
                results_per_page=2000,
            )

            for vuln in vulns:
                existing = self.vuln_repo.get_by_cve(vuln.cve_id)
                if existing:
                    self.vuln_repo.update(vuln)
                    result.cves_updated += 1
                else:
                    self.vuln_repo.create(vuln)
                    result.cves_added += 1

            if progress_callback:
                progress_callback(f"Incremental: {result.cves_added} added, {result.cves_updated} updated")

        except Exception as e:
            result.errors.append(str(e))
            logger.error(f"Incremental sync failed: {e}")

        self._update_sync_state(full_sync=False)
        result.cves_total = self.vuln_repo.count()

        return result

    def _record_feed_import(self, year: int, cve_count: int) -> None:
        self.db.conn.execute(
            """
            INSERT INTO nvd_feed_imports (year, imported_at, cve_count)
            VALUES (?, ?, ?)
            ON CONFLICT(year) DO UPDATE SET
                imported_at = excluded.imported_at,
                cve_count = excluded.cve_count
            """,
            (year, datetime.now().isoformat(), cve_count)
        )
        self.db.conn.commit()

    def _update_sync_state(self, full_sync: bool) -> None:
        now = datetime.now().isoformat()
        count = self.vuln_repo.count()

        if full_sync:
            self.db.conn.execute(
                """
                INSERT INTO nvd_sync_state (id, last_full_sync, total_cve_count, is_initialized)
                VALUES (1, ?, ?, 1)
                ON CONFLICT(id) DO UPDATE SET
                    last_full_sync = excluded.last_full_sync,
                    total_cve_count = excluded.total_cve_count,
                    is_initialized = 1
                """,
                (now, count)
            )
        else:
            self.db.conn.execute(
                """
                INSERT INTO nvd_sync_state (id, last_incremental_sync, total_cve_count, is_initialized)
                VALUES (1, ?, ?, 1)
                ON CONFLICT(id) DO UPDATE SET
                    last_incremental_sync = excluded.last_incremental_sync,
                    total_cve_count = excluded.total_cve_count
                """,
                (now, count)
            )

        self.db.conn.commit()

    def get_cache_stats(self) -> Dict:
        cursor = self.db.conn.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
        )
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}

        total = self.vuln_repo.count()

        return {
            "total": total,
            "by_severity": by_severity,
        }
