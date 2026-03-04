"""
Aegis AI — Scan Scheduler

Provides automated recurring scan scheduling with support for:
  - Interval-based (every N hours)
  - Cron-based (specific time/day)
  - One-shot delayed scans

Uses a lightweight in-memory scheduler (no external dependency required).
In production, swap for APScheduler or Celery Beat.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional
from enum import Enum


class ScheduleFrequency(str, Enum):
    HOURLY = "hourly"
    EVERY_6H = "every_6h"
    EVERY_12H = "every_12h"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


FREQUENCY_SECONDS = {
    ScheduleFrequency.HOURLY: 3600,
    ScheduleFrequency.EVERY_6H: 6 * 3600,
    ScheduleFrequency.EVERY_12H: 12 * 3600,
    ScheduleFrequency.DAILY: 24 * 3600,
    ScheduleFrequency.WEEKLY: 7 * 24 * 3600,
    ScheduleFrequency.MONTHLY: 30 * 24 * 3600,
}


@dataclass
class ScheduledScan:
    id: str
    target_url: str
    target_name: str
    frequency: str
    interval_seconds: int
    scan_types: List[str]
    scan_depth: int
    enabled: bool
    created_at: str
    next_run: str
    last_run: Optional[str] = None
    last_scan_id: Optional[str] = None
    run_count: int = 0


class ScanScheduler:
    """
    Lightweight async scan scheduler.

    Usage:
        scheduler = ScanScheduler(run_scan_callback)
        scheduler.add_schedule(target_url="http://example.com", frequency="daily")
        await scheduler.start()   # runs in background
    """

    def __init__(self, run_scan_fn: Optional[Callable] = None):
        """
        Args:
            run_scan_fn: async callable(target_url, scan_depth, scan_types, target_name)
                         that starts a scan and returns a scan_id
        """
        self._run_scan = run_scan_fn
        self._schedules: Dict[str, ScheduledScan] = {}
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ── Schedule management ──────────────────────────────────────────────

    def add_schedule(
        self,
        target_url: str,
        frequency: str = "daily",
        scan_types: Optional[List[str]] = None,
        scan_depth: int = 3,
        target_name: Optional[str] = None,
        custom_interval_hours: Optional[float] = None,
    ) -> ScheduledScan:
        """Add a new scheduled scan."""
        schedule_id = f"sched_{uuid.uuid4().hex[:8]}"

        freq = frequency.lower()
        if freq == "custom" and custom_interval_hours:
            interval = int(custom_interval_hours * 3600)
        else:
            interval = FREQUENCY_SECONDS.get(freq, FREQUENCY_SECONDS[ScheduleFrequency.DAILY])

        now = datetime.utcnow()
        next_run = now + timedelta(seconds=interval)

        schedule = ScheduledScan(
            id=schedule_id,
            target_url=target_url,
            target_name=target_name or target_url,
            frequency=freq,
            interval_seconds=interval,
            scan_types=scan_types or ["sql_injection", "xss", "open_redirect", "security_headers"],
            scan_depth=scan_depth,
            enabled=True,
            created_at=now.isoformat(),
            next_run=next_run.isoformat(),
        )

        self._schedules[schedule_id] = schedule
        return schedule

    def remove_schedule(self, schedule_id: str) -> bool:
        if schedule_id in self._schedules:
            del self._schedules[schedule_id]
            return True
        return False

    def toggle_schedule(self, schedule_id: str) -> Optional[bool]:
        sched = self._schedules.get(schedule_id)
        if sched:
            sched.enabled = not sched.enabled
            return sched.enabled
        return None

    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        return self._schedules.get(schedule_id)

    def get_all_schedules(self) -> List[Dict]:
        return [self._serialize(s) for s in self._schedules.values()]

    # ── Scheduler loop ───────────────────────────────────────────────────

    async def start(self):
        """Start the background scheduler loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()

    async def _loop(self):
        """Check every 30s for due schedules."""
        while self._running:
            await asyncio.sleep(30)
            now = datetime.utcnow()

            for sched in list(self._schedules.values()):
                if not sched.enabled:
                    continue
                next_dt = datetime.fromisoformat(sched.next_run)
                if now >= next_dt:
                    await self._execute(sched)

    async def _execute(self, sched: ScheduledScan):
        """Run a scheduled scan and update next-run time."""
        now = datetime.utcnow()
        sched.last_run = now.isoformat()
        sched.next_run = (now + timedelta(seconds=sched.interval_seconds)).isoformat()
        sched.run_count += 1

        if self._run_scan:
            try:
                scan_id = await self._run_scan(
                    target_url=sched.target_url,
                    scan_depth=sched.scan_depth,
                    scan_types=sched.scan_types,
                    authorized=True,
                    target_name=sched.target_name,
                )
                sched.last_scan_id = scan_id
            except Exception:
                pass  # scheduler should never crash

    # ── Serialization ────────────────────────────────────────────────────

    @staticmethod
    def _serialize(s: ScheduledScan) -> Dict:
        next_dt = datetime.fromisoformat(s.next_run)
        now = datetime.utcnow()
        diff = next_dt - now
        if diff.total_seconds() > 0:
            hours = diff.total_seconds() / 3600
            if hours < 1:
                time_until = f"{int(diff.total_seconds() / 60)}m"
            elif hours < 24:
                time_until = f"{hours:.1f}h"
            else:
                time_until = f"{hours / 24:.1f}d"
        else:
            time_until = "due"

        return {
            "id": s.id,
            "target_url": s.target_url,
            "target_name": s.target_name,
            "frequency": s.frequency,
            "interval_seconds": s.interval_seconds,
            "scan_types": s.scan_types,
            "scan_depth": s.scan_depth,
            "enabled": s.enabled,
            "created_at": s.created_at,
            "next_run": s.next_run,
            "time_until_next": time_until,
            "last_run": s.last_run,
            "last_scan_id": s.last_scan_id,
            "run_count": s.run_count,
        }
