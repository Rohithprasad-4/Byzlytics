"""Phase 11.2 — Background scheduler for automated daily reporting.

A daemon thread wakes every 60 seconds and checks whether the current
time matches the configured trigger (default 23:59). When triggered it:
  1. Recomputes today's daily_summary row.
  2. Builds the 7-section report context.
  3. Writes reports/output/security_report_YYYY-MM-DD.pdf.

The daemon flag ensures the thread terminates automatically when the
Flask process exits; it never blocks app shutdown.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime

logger = logging.getLogger(__name__)

_scheduler_thread: threading.Thread | None = None
_stop_event = threading.Event()


def _run_scheduler_loop(*, trigger_hour: int, trigger_minute: int, reports_dir: str, poll_seconds: int) -> None:
    last_triggered_date = None
    logger.info(
        "Report scheduler started (daily trigger at %02d:%02d).", trigger_hour, trigger_minute
    )

    while not _stop_event.is_set():
        now = datetime.now()
        if (
            now.hour == trigger_hour
            and now.minute == trigger_minute
            and last_triggered_date != now.date()
        ):
            try:
                _generate_daily_report(reports_dir)
                last_triggered_date = now.date()
            except Exception:
                logger.exception("Scheduled daily report generation failed.")

        _stop_event.wait(poll_seconds)


def _generate_daily_report(reports_dir: str) -> None:
    from backend import models
    from reports.report_builder import generate_report

    logger.info("Running scheduled daily report generation.")
    models.generate_daily_summary()
    _, filename = generate_report(output_dir=reports_dir)
    logger.info("Scheduled report generated: %s", filename)


def start_scheduler(
    *,
    trigger_time: str = "23:59",
    reports_dir: str = "reports/output",
    poll_seconds: int = 60,
) -> threading.Thread:
    """Start the daemon scheduler thread. Safe to call once per process."""
    global _scheduler_thread

    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        return _scheduler_thread

    hour_str, minute_str = trigger_time.split(":")
    _stop_event.clear()

    _scheduler_thread = threading.Thread(
        target=_run_scheduler_loop,
        kwargs={
            "trigger_hour": int(hour_str),
            "trigger_minute": int(minute_str),
            "reports_dir": reports_dir,
            "poll_seconds": poll_seconds,
        },
        daemon=True,
        name="securegate-report-scheduler",
    )
    _scheduler_thread.start()
    return _scheduler_thread


def stop_scheduler() -> None:
    _stop_event.set()
