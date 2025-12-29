"""
Scheduled scan job definitions and repository.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


@dataclass
class ScheduledScan:
    id: Optional[int] = None
    name: str = ""
    target_range: str = ""
    cron_expr: str = ""
    method: str = "icmp"
    ports: str = "1-1024"
    is_enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: Optional[datetime] = None


class ScheduleRepository:
    """Repository for scheduled scan CRUD operations."""

    def __init__(self, db=None):
        if db is None:
            from ..storage.database import get_db
            db = get_db()
        self.db = db

    def create(self, schedule: ScheduledScan) -> ScheduledScan:
        cursor = self.db.connection.execute(
            """
            INSERT INTO scheduled_scans
            (name, target_range, cron_expr, method, ports, is_enabled, next_run, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                schedule.name,
                schedule.target_range,
                schedule.cron_expr,
                schedule.method,
                schedule.ports,
                1 if schedule.is_enabled else 0,
                schedule.next_run.isoformat() if schedule.next_run else None,
                datetime.now().isoformat(),
            ),
        )
        self.db.connection.commit()
        schedule.id = cursor.lastrowid
        return schedule

    def get(self, schedule_id: int) -> Optional[ScheduledScan]:
        cursor = self.db.connection.execute(
            "SELECT * FROM scheduled_scans WHERE id = ?", (schedule_id,)
        )
        row = cursor.fetchone()
        return self._row_to_schedule(row) if row else None

    def get_all(self) -> List[ScheduledScan]:
        cursor = self.db.connection.execute(
            "SELECT * FROM scheduled_scans ORDER BY created_at DESC"
        )
        return [self._row_to_schedule(row) for row in cursor.fetchall()]

    def get_enabled(self) -> List[ScheduledScan]:
        cursor = self.db.connection.execute(
            "SELECT * FROM scheduled_scans WHERE is_enabled = 1"
        )
        return [self._row_to_schedule(row) for row in cursor.fetchall()]

    def update(self, schedule: ScheduledScan) -> None:
        self.db.connection.execute(
            """
            UPDATE scheduled_scans SET
                name = ?, target_range = ?, cron_expr = ?,
                method = ?, ports = ?, is_enabled = ?,
                last_run = ?, next_run = ?
            WHERE id = ?
            """,
            (
                schedule.name,
                schedule.target_range,
                schedule.cron_expr,
                schedule.method,
                schedule.ports,
                1 if schedule.is_enabled else 0,
                schedule.last_run.isoformat() if schedule.last_run else None,
                schedule.next_run.isoformat() if schedule.next_run else None,
                schedule.id,
            ),
        )
        self.db.connection.commit()

    def delete(self, schedule_id: int) -> bool:
        cursor = self.db.connection.execute(
            "DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,)
        )
        self.db.connection.commit()
        return cursor.rowcount > 0

    def toggle(self, schedule_id: int) -> bool:
        cursor = self.db.connection.execute(
            "UPDATE scheduled_scans SET is_enabled = NOT is_enabled WHERE id = ?",
            (schedule_id,),
        )
        self.db.connection.commit()
        return cursor.rowcount > 0

    def _row_to_schedule(self, row) -> ScheduledScan:
        return ScheduledScan(
            id=row[0],
            name=row[1],
            target_range=row[2],
            cron_expr=row[3],
            method=row[4],
            ports=row[5],
            is_enabled=bool(row[6]),
            last_run=datetime.fromisoformat(row[7]) if row[7] else None,
            next_run=datetime.fromisoformat(row[8]) if row[8] else None,
            created_at=datetime.fromisoformat(row[9]) if row[9] else None,
        )

    def bump_schedule_version(self) -> None:
        """Increment schedule version to trigger scheduler reload."""
        now = datetime.now().isoformat()
        self.db.connection.execute(
            """
            INSERT INTO config_meta (key, value, updated_at)
            VALUES ('schedule_version', '1', ?)
            ON CONFLICT(key) DO UPDATE SET
                value = CAST(CAST(value AS INTEGER) + 1 AS TEXT),
                updated_at = excluded.updated_at
            """,
            (now,),
        )
        self.db.connection.commit()

    def get_schedule_version(self) -> int:
        """Get current schedule version."""
        cursor = self.db.connection.execute(
            "SELECT value FROM config_meta WHERE key = 'schedule_version'"
        )
        row = cursor.fetchone()
        return int(row[0]) if row else 0
