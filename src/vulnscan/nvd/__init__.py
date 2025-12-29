"""
NVD module - NVD API client, caching, and vulnerability matching.
"""

from .client import NVDClient
from .cache import CVECache
from .matcher import VulnerabilityMatcher
from .feeds import FeedDownloader, FeedParser, HybridSyncCoordinator

__all__ = [
    "NVDClient",
    "CVECache",
    "VulnerabilityMatcher",
    "FeedDownloader",
    "FeedParser",
    "HybridSyncCoordinator",
]
