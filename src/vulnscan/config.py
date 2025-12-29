"""
Configuration management for VulnScan.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DatabaseConfig:
    path: Path = field(default_factory=lambda: Path("data/scanner.db"))


@dataclass
class NVDConfig:
    api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    feed_url: str = "https://nvd.nist.gov/feeds/json/cve/1.1"
    api_key: Optional[str] = None
    cache_dir: Path = field(default_factory=lambda: Path("data/nvd_cache"))
    rate_limit: float = 0.6  # requests per second (without API key)
    cache_ttl: int = 86400 * 7  # 7 days


@dataclass
class ScanConfig:
    timeout: float = 3.0
    max_threads: int = 100
    port_range: str = "1-1024"
    icmp_enabled: bool = True
    arp_enabled: bool = True
    syn_enabled: bool = True


@dataclass
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 5000
    debug: bool = False


@dataclass
class Config:
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    nvd: NVDConfig = field(default_factory=NVDConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    web: WebConfig = field(default_factory=WebConfig)
    language: str = "zh_CN"  # Default language

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        config = cls()

        if api_key := os.getenv("NVD_API_KEY"):
            config.nvd.api_key = api_key
            config.nvd.rate_limit = 5.0  # Higher rate with API key

        if db_path := os.getenv("VULNSCAN_DB_PATH"):
            config.database.path = Path(db_path)

        if lang := os.getenv("VULNSCAN_LANG"):
            config.language = lang

        return config


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def set_config(config: Config) -> None:
    """Set global configuration instance."""
    global _config
    _config = config
