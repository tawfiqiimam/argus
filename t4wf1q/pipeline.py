"""Scan orchestration pipeline.

Runs in a background worker thread. Each stage logs to the DB and publishes a
live event to the WebSocket bus so the dashboard updates in real time.

Stages:  RECON -> PROBE -> SCAN -> DEDUP/STORE -> SCORE -> ALERT/REPORT
"""
from __future__ import annotations

import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

from . import db, events
from .config import Config
from .scope import ScopeGuard, extract_host, looks_like_domain
from .scanners import recon, nuclei, nmap, httpchecks
from .scanners.base import ScanContext
from . import alerts, report
from .scoring import normalize_severity, meets_threshold

PROFILES = {
    "owasp-full": ["recon", "probe", "http", "nuclei", "nmap"],
    "web":        ["probe", "http", "nuclei"],
    "network":    ["nmap"],
    "recon":      ["recon", "probe"],
    "quick":      ["probe", "http"],
}

_queue: "Queue[tuple[str,str]]" = Queue()
_worker_started = False
_lock = threading.Lock()


def enqueue(scan_id: str, asset_id: str) -> None:
    _queue.put((scan_id, asset_id))


def start_worker(cfg: Config) -> None:
    global _worker_started
    with _lock:
        if _worker_started:
            return
        _worker_started = True
    t = threading.Thread(target=_worker_loop, args=(cfg,), daemon=True, name="t4wf1q-worker")
    t.start()


def _worker_loop(cfg: Config) -> None:
    while True:
        scan_id, asset_id = _queue.get()
        try:
            _run_scan(cfg, scan_id, asset_id)
        except Exception:
            tb = traceback.format_exc()
            db.update_scan(scan_id, status="failed", stage="error")
            db.log_event(f"scan crashed: {tb.splitlines()[-1]}", scan_id, asset_id, "error", "error")
            events.publish("scan_update", scan_id=scan_id, status="failed", stage="error")
        finally:
            _queue.task_done()


def _mk_log(scan_id: str, asset_id: str):
    def log(level: str, message: str):
        db.log_event(message, scan_id, asset_id, level, "log")
        events.publish("log", scan_id=scan_id, level=level, message=message)
    return log


def _set_stage(scan_id, stage, progress, log):
    db.update_scan(scan_id, stage=stage, progress=progress, status="running")
    events.publish("scan_update", scan_id=scan_id, stage=stage, progress=progress, status="running")
    log("info", f"stage: {stage}")


def _run_scan(cfg: Config, scan_id: str, asset_id: str) -> None:
    asset = db.get_asset(asset_id)
    if not asset:
        return
    scan = db.get_scan(scan_id)
    profile = scan["profile"] if scan else "owasp-full"
    stages = PROFILES.get(profile, PROFILES["owasp-full"])
    log = _mk_log(scan_id, asset_id)
    guard = ScopeGuard.from_config(cfg)
    scanners_cfg = cfg.get("scanners", default={})

    db.update_scan(scan_id, status="running", stage="start", progress=1,
                   started_at=db.now_iso())
    events.publish("scan_update", scan_id=scan_id, status="running", progress=1)
    log("info", f"=== Argus scan start · profile={profile} · target={asset['target']} ===")

    ctx = ScanContext(asset=asset, scan_id=scan_id, cfg=cfg, log=log,
                      scanners_cfg=scanners_cfg)

    root_host = extract_host(asset["target"])
    ctx.hosts = [root_host] if root_host else []
    ctx.targets = [asset["target"]]

    # ---- RECON (subdomain enum) ----
    if "recon" in stages and looks_like_domain(root_host):
        _set_stage(scan_id, "recon", 10, log)
        discovered = recon.enumerate_subdomains(ctx, root_host)
        in_scope = guard.in_scope_hosts(discovered)
        dropped = len(discovered) - len(in_scope)
        if dropped:
            log("warn", f"scope: {dropped} discovered host(s) out of scope, skipped")
        ctx.hosts = in_scope or [root_host]
        for h in ctx.hosts:
            db.upsert_subdomain(asset_id, h)

    # ---- PROBE (liveness + tech) ----
    live_urls: list[str] = []
    if "probe" in stages:
        _set_stage(scan_id, "probe", 25, log)
        records = recon.probe_hosts(ctx, ctx.hosts)
        for rec in records:
            if not rec.get("host"):
                continue
            db.upsert_subdomain(asset_id, rec["host"], alive=1 if rec.get("url") else 0,
                                status_code=rec.get("status"), title=rec.get("title"),
                                tech=rec.get("tech", []))
            if rec.get("url"):
                live_urls.append(rec["url"])
                events.publish("subdomain", scan_id=scan_id, asset_id=asset_id, **rec)
    if not live_urls:
        # fall back to the asset target itself
        t = asset["target"]
        live_urls = [t if "://" in t else f"https://{t}"]

    all_findings = []

    # ---- HTTP checks (always-available, pure python) ----
    if "http" in stages:
        _set_stage(scan_id, "http-checks", 45, log)
        all_findings += httpchecks.scan(ctx, live_urls)

    # ---- NUCLEI ----
    if "nuclei" in stages:
        _set_stage(scan_id, "nuclei", 65, log)
        all_findings += nuclei.scan(ctx, live_urls)

    # ---- NMAP ----
    if "nmap" in stages:
        _set_stage(scan_id, "nmap", 80, log)
        scan_hosts = sorted({extract_host(u) for u in live_urls if extract_host(u)})
        all_findings += nmap.scan(ctx, scan_hosts)

    # ---- DEDUP + STORE ----
    _set_stage(scan_id, "store", 90, log)
    new_count = 0
    sev_tally = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    alert_threshold = cfg.get("alerts", "min_severity", default="high")
    for f in all_findings:
        d = f.to_dict()
        d["severity"] = normalize_severity(d["severity"])
        sev_tally[d["severity"]] += 1
        stored, is_new = db.upsert_finding(asset_id, scan_id, d)
        if is_new:
            new_count += 1
            events.publish("finding", scan_id=scan_id, asset_id=asset_id,
                           id=stored["id"], title=stored["title"],
                           severity=stored["severity"], owasp=stored.get("owasp"),
                           host=stored.get("host"), location=stored.get("location"))
            if meets_threshold(d["severity"], alert_threshold):
                alerts.notify(cfg, asset, stored)

    # ---- SCORE + FINISH ----
    db.touch_asset_scan(asset_id)
    stats = {"total": len(all_findings), "new": new_count, **sev_tally}
    db.update_scan(scan_id, status="done", stage="done", progress=100,
                   finished_at=db.now_iso(), stats=stats)
    log("info", f"=== scan complete · {len(all_findings)} finding(s), {new_count} new ===")
    events.publish("scan_update", scan_id=scan_id, status="done", progress=100, stats=stats)

    # ---- AUTO REPORT ----
    try:
        path = report.generate(cfg, asset_id, scan_id)
        if path:
            log("info", f"report written: {path}")
            events.publish("report_ready", scan_id=scan_id, asset_id=asset_id, path=str(path))
    except Exception as e:
        log("warn", f"report generation failed: {e}")
