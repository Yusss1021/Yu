"""
SQLite database connection management.
"""

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

from ..config import get_config
from .schema import SCHEMA


class Database:
    """Thread-safe SQLite database wrapper."""

    _instances: dict = {}
    _lock = threading.Lock()

    def __new__(cls, db_path: Path = None) -> "Database":
        """Support multiple database instances by path."""
        if db_path is None:
            db_path = get_config().database.path

        db_key = str(db_path)
        if db_key not in cls._instances:
            with cls._lock:
                if db_key not in cls._instances:
                    instance = super().__new__(cls)
                    instance._initialized = False
                    cls._instances[db_key] = instance
        return cls._instances[db_key]

    def __init__(self, db_path: Path = None):
        if getattr(self, "_initialized", False):
            return

        if db_path is None:
            db_path = get_config().database.path

        self._db_path = Path(db_path)
        self._local = threading.local()
        self._initialized = True

        # Ensure directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize schema
        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize database schema if needed."""
        with self.transaction() as cursor:
            cursor.executescript(SCHEMA)

    @property
    def connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, "connection") or self._local.connection is None:
            self._local.connection = self._create_connection()
        return self._local.connection

    def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection."""
        conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager for database transactions."""
        conn = self.connection
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    @contextmanager
    def cursor(self) -> Generator[sqlite3.Cursor, None, None]:
        """Context manager for read-only operations."""
        cursor = self.connection.cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a SQL statement."""
        return self.connection.execute(sql, params)

    def executemany(self, sql: str, params_list: list) -> sqlite3.Cursor:
        """Execute a SQL statement with multiple parameter sets."""
        return self.connection.executemany(sql, params_list)

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Execute and fetch one row."""
        cursor = self.execute(sql, params)
        return cursor.fetchone()

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        """Execute and fetch all rows."""
        cursor = self.execute(sql, params)
        return cursor.fetchall()

    def close(self) -> None:
        """Close the thread-local connection."""
        if hasattr(self._local, "connection") and self._local.connection:
            self._local.connection.close()
            self._local.connection = None


def get_db() -> Database:
    """Get the database singleton instance."""
    return Database()
