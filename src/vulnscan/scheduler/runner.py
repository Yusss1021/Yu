"""
Scheduler runner - APScheduler-based task execution.
"""

import logging
from datetime import datetime
from typing import Optional

from .jobs import ScheduledScan, ScheduleRepository

logger = logging.getLogger(__name__)


class SchedulerRunner:
    """Runs scheduled scans using APScheduler."""

    RELOAD_CHECK_INTERVAL = 30  # seconds

    def __init__(self, db=None):
        self.db = db
        self.repo = ScheduleRepository(db)
        self.scheduler = None
        self._running = False
        self._last_version = 0

    def start(self, blocking: bool = True) -> None:
        """Start the scheduler."""
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
            from apscheduler.schedulers.blocking import BlockingScheduler
            from apscheduler.triggers.cron import CronTrigger
            from apscheduler.triggers.interval import IntervalTrigger
        except ImportError:
            raise ImportError("apscheduler is required. Install with: pip install apscheduler")

        SchedulerClass = BlockingScheduler if blocking else BackgroundScheduler
        self.scheduler = SchedulerClass()

        # Store initial version
        self._last_version = self.repo.get_schedule_version()

        # Add reload checker job
        self.scheduler.add_job(
            self._check_reload,
            trigger=IntervalTrigger(seconds=self.RELOAD_CHECK_INTERVAL),
            id="_reload_checker",
            name="Reload Checker",
            replace_existing=True,
        )

        # Load all enabled schedules
        for schedule in self.repo.get_enabled():
            self._add_job(schedule)

        self._running = True
        logger.info("Scheduler started")

        if blocking:
            try:
                self.scheduler.start()
            except (KeyboardInterrupt, SystemExit):
                self.stop()
        else:
            self.scheduler.start()

    def _check_reload(self) -> None:
        """Check if schedule version changed and reload if needed."""
        current_version = self.repo.get_schedule_version()
        if current_version != self._last_version:
            logger.info(f"Schedule version changed: {self._last_version} -> {current_version}")
            self._last_version = current_version
            self.reload()

    def stop(self) -> None:
        """Stop the scheduler."""
        if self.scheduler and self._running:
            self.scheduler.shutdown()
            self._running = False
            logger.info("Scheduler stopped")

    def reload(self) -> None:
        """Reload all scheduled jobs (preserves reload checker)."""
        if not self.scheduler:
            return

        # Remove scan jobs only (preserve _reload_checker)
        for job in self.scheduler.get_jobs():
            if job.id != "_reload_checker":
                self.scheduler.remove_job(job.id)

        for schedule in self.repo.get_enabled():
            self._add_job(schedule)
        logger.info("Scheduler reloaded")

    def _add_job(self, schedule: ScheduledScan) -> None:
        """Add a scheduled scan job."""
        from apscheduler.triggers.cron import CronTrigger

        try:
            trigger = CronTrigger.from_crontab(schedule.cron_expr)
            self.scheduler.add_job(
                self._run_scan,
                trigger=trigger,
                args=[schedule.id],
                id=f"scan_{schedule.id}",
                name=schedule.name,
                replace_existing=True,
            )

            # Update next run time
            next_run = trigger.get_next_fire_time(None, datetime.now())
            schedule.next_run = next_run
            self.repo.update(schedule)

            logger.info(f"Scheduled job: {schedule.name} ({schedule.cron_expr})")
        except Exception as e:
            logger.error(f"Failed to schedule {schedule.name}: {e}")

    def _run_scan(self, schedule_id: int) -> None:
        """Execute a scheduled scan."""
        from apscheduler.triggers.cron import CronTrigger

        schedule = self.repo.get(schedule_id)
        if not schedule or not schedule.is_enabled:
            return

        logger.info(f"Running scheduled scan: {schedule.name}")

        try:
            from ..config import get_config
            from ..core.pipeline import ScanPipelineRunner
            from ..storage.database import Database

            config = get_config()
            db = Database(config.database.path)

            runner = ScanPipelineRunner(db=db)
            runner.run(
                target_range=schedule.target_range,
                discovery_method=schedule.method,
                port_range=schedule.ports,
            )

            # Update last_run and next_run
            schedule.last_run = datetime.now()
            trigger = CronTrigger.from_crontab(schedule.cron_expr)
            schedule.next_run = trigger.get_next_fire_time(None, datetime.now())
            self.repo.update(schedule)

            logger.info(f"Completed scheduled scan: {schedule.name}")

        except Exception as e:
            logger.error(f"Scheduled scan failed: {schedule.name} - {e}")


def get_next_run(cron_expr: str) -> Optional[datetime]:
    """Calculate next run time for a cron expression."""
    try:
        from apscheduler.triggers.cron import CronTrigger
        trigger = CronTrigger.from_crontab(cron_expr)
        return trigger.get_next_fire_time(None, datetime.now())
    except Exception:
        return None
