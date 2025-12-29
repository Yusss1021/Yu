"""
Database schema definition and initialization.
"""

SCHEMA_SQL = """
-- Scan jobs table
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    target_range TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    notes TEXT
);

-- Discovered hosts table
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    os_guess TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Services/ports table
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT,
    product TEXT,
    version TEXT,
    cpe TEXT,
    state TEXT NOT NULL DEFAULT 'open',
    banner TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

-- Vulnerabilities table (NVD cache)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    description TEXT,
    cvss_base REAL DEFAULT 0.0,
    cvss_vector TEXT,
    severity TEXT,
    published_at TEXT,
    last_modified TEXT,
    affected_cpe TEXT,
    solution TEXT
);

-- Service-Vulnerability association table
CREATE TABLE IF NOT EXISTS service_vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER NOT NULL,
    vuln_id INTEGER NOT NULL,
    match_type TEXT NOT NULL DEFAULT 'cpe_exact',
    confidence REAL DEFAULT 1.0,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE CASCADE,
    FOREIGN KEY(vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- Risk assessment results table
CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0.0,
    risk_level TEXT NOT NULL DEFAULT 'Low',
    summary TEXT,
    vuln_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

-- NVD cache metadata table
CREATE TABLE IF NOT EXISTS nvd_cache_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cpe_pattern TEXT NOT NULL UNIQUE,
    last_updated TEXT NOT NULL,
    result_count INTEGER DEFAULT 0
);

-- NVD sync state (singleton)
CREATE TABLE IF NOT EXISTS nvd_sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_full_sync TEXT,
    last_incremental_sync TEXT,
    total_cve_count INTEGER DEFAULT 0,
    is_initialized INTEGER DEFAULT 0
);

-- NVD feed import records
CREATE TABLE IF NOT EXISTS nvd_feed_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    year INTEGER NOT NULL UNIQUE,
    imported_at TEXT NOT NULL,
    cve_count INTEGER DEFAULT 0,
    sha256 TEXT
);

-- Scheduled scans table
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    target_range TEXT NOT NULL,
    cron_expr TEXT NOT NULL,
    method TEXT DEFAULT 'icmp',
    ports TEXT DEFAULT '1-1024',
    is_enabled INTEGER DEFAULT 1,
    last_run TEXT,
    next_run TEXT,
    created_at TEXT NOT NULL
);

-- Config metadata table (for scheduler hot reload)
CREATE TABLE IF NOT EXISTS config_meta (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT
);

-- Active verification results table
CREATE TABLE IF NOT EXISTS verification_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    host_id INTEGER NOT NULL,
    service_id INTEGER,
    verifier TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT,
    cve_id TEXT,
    description TEXT,
    evidence TEXT,
    detected_at TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE SET NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_services_port ON services(port);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_service_vulns_service ON service_vulns(service_id);
CREATE INDEX IF NOT EXISTS idx_service_vulns_vuln ON service_vulns(vuln_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_scan ON scan_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_results_host ON scan_results(host_id);
CREATE INDEX IF NOT EXISTS idx_verification_scan ON verification_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_verification_host ON verification_results(host_id);
CREATE INDEX IF NOT EXISTS idx_verification_severity ON verification_results(severity);
"""

# Alias for database.py import
SCHEMA = SCHEMA_SQL


def init_database() -> None:
    """Initialize database schema."""
    from .database import get_db
    db = get_db()
    with db.transaction() as cursor:
        cursor.executescript(SCHEMA_SQL)


def drop_all_tables() -> None:
    """Drop all tables (for testing/reset)."""
    from .database import get_db
    db = get_db()
    tables = [
        "verification_results",
        "nvd_feed_imports",
        "nvd_sync_state",
        "nvd_cache_meta",
        "scan_results",
        "service_vulns",
        "services",
        "hosts",
        "vulnerabilities",
        "scans",
    ]
    with db.transaction() as cursor:
        for table in tables:
            cursor.execute(f"DROP TABLE IF EXISTS {table}")


def reset_database() -> None:
    """Reset database by dropping and recreating all tables."""
    drop_all_tables()
    init_database()
