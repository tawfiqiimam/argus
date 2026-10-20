"""Lightweight background scheduler (stdlib only, no Celery required).

Gives the VMS its "all-time assessment" behaviour:
  * daily full scan of every asset
  * periodic change-watch re-scan
  * daily nuclei template update
"""
from __future__ import annotations

import threading
import time
from datetime import datetime

from . import db, pipeline
from .config import Config
from .scanners.base import run, tool_available


class Scheduler:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_full_day = None
        self._last_templates_day = None
        self._last_watch = 0.0

    def start(self) -> None:
        # Always run the loop; whether it does anything is checked live each
        # tick against the DB setting, so the UI toggle takes effect instantly.
        self._thread = threading.Thread(target=self._loop, daemon=True, name="argus-sched")
        self._thread.start()

    def _enabled(self) -> bool:
        return bool(db.get_setting("automation_enabled",
                                   self.cfg.get("automation", "enabled", default=True)))

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(30):
            try:
                self._tick()
            except Exception:
                pass

    def _tick(self) -> None:
        if not self._enabled():
            return
        now = datetime.now()
        full_hour = int(self.cfg.get("automation", "full_scan_cron_hour", default=2))
        watch_min = int(self.cfg.get("automation", "change_watch_minutes", default=15))

        # Daily full scan
        if now.hour == full_hour and self._last_full_day != now.date():
            self._last_full_day = now.date()
            self._scan_all("owasp-full", reason="daily full scan")

        # Change-watch (quick probe) every N minutes
        if watch_min > 0 and (time.time() - self._last_watch) >= watch_min * 60:
            self._last_watch = time.time()
            self._scan_all("quick", reason="change-watch", quiet=True)

        # Daily template update
        if self.cfg.get("automation", "update_templates_daily", default=True):
            if now.hour == 1 and self._last_templates_day != now.date():
                self._last_templates_day = now.date()
                self._update_templates()

    def _scan_all(self, profile: str, reason: str, quiet: bool = False) -> None:
        for asset in db.list_assets():
            scan = db.create_scan(asset["id"], profile)
            if not quiet:
                db.log_event(f"scheduler: {reason}", scan["id"], asset["id"], "info", "sched")
            pipeline.enqueue(scan["id"], asset["id"])

    def _update_templates(self) -> None:
        bin_ = self.cfg.get("scanners", "nuclei", default="nuclei")
        if tool_available(bin_):
            run([bin_, "-update-templates"], timeout=600)
            db.log_event("scheduler: nuclei templates updated", level="info", kind="sched")
