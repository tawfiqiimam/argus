"""Background install/uninstall jobs for the Tools page.

Each job shells out to scripts/install-tools.sh for exactly one tool and
streams its output to a log file under ~/.argus/jobs/. A single global lock
means only one apt/go/pip operation ever runs at a time — concurrent package
manager runs can corrupt each other's state, so a second request while one
is in flight is refused with a clear "already running" error rather than
queued silently.

Jobs live in memory only: this process's history, not a durable record. The
audit log (db.audit) is the durable record of who started what and when;
losing in-memory job detail on restart is an acceptable trade for not having
to migrate a schema for something this small.

Script exit codes, by convention (see install-tools.sh):
  0  done — the tool is now present (install) or gone (uninstall)
  1  failed — tried and didn't work; see the log tail for why
  2  refused — e.g. uninstalling a system package needs a human with sudo
"""
from __future__ import annotations

import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import db, events, tools

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "install-tools.sh"
JOBS_DIR = Path.home() / ".argus" / "jobs"
MAX_HISTORY = 200
TAIL_LINES = 200

_lock = threading.Lock()          # one tool job at a time, system-wide
_jobs: dict[str, dict] = {}
_order: list[str] = []            # insertion order, oldest first
_valid_keys = {k for k, *_ in tools.TOOLS}


class AlreadyRunning(Exception):
    pass


class UnknownTool(Exception):
    pass


def _record(job: dict) -> None:
    _jobs[job["id"]] = job
    _order.append(job["id"])
    while len(_order) > MAX_HISTORY:
        _jobs.pop(_order.pop(0), None)


def current() -> dict | None:
    """The job holding the lock right now, if any."""
    for jid in reversed(_order):
        j = _jobs.get(jid)
        if j and j["status"] == "running":
            return j
    return None


def get(job_id: str) -> dict | None:
    return _jobs.get(job_id)


def recent(limit: int = 50) -> list[dict]:
    return [_jobs[j] for j in reversed(_order[-limit:])]


def log_tail(job: dict, n: int = TAIL_LINES) -> str:
    try:
        lines = Path(job["log_path"]).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[-n:])


def _run(job: dict, args: list[str], ip: str | None) -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    log_path = Path(job["log_path"])
    try:
        with log_path.open("w") as logf:
            proc = subprocess.Popen(
                ["bash", str(SCRIPT), *args],
                stdout=logf, stderr=subprocess.STDOUT,
                env=None,  # inherit — the script computes its own PATH/HOME additions
            )
            job["pid"] = proc.pid
            events.publish("tool_job", **public_view(job))
            rc = proc.wait(timeout=1800)
    except subprocess.TimeoutExpired:
        proc.kill()
        rc = -1
        job["error"] = "timed out after 30 minutes"
    except Exception as exc:  # noqa: BLE001 — a job must always finish, never hang the lock
        rc = -1
        job["error"] = str(exc)
    finally:
        job["finished_at"] = time.time()
        job["rc"] = rc
        job["status"] = {0: "done", 2: "refused"}.get(rc, "failed")
        detail = f"{job['action']} {job['tool']} -> {job['status']} (rc={rc})"
        db.audit(f"tool.{job['action']}.finish", job["tool"], detail, ip)
        events.publish("tool_job", **public_view(job))
        _lock.release()


def public_view(job: dict) -> dict:
    """Trim to what the frontend needs — never the full log inline."""
    return {k: job[k] for k in ("id", "tool", "action", "status", "started_at", "finished_at")}


def _start(tool: str, action: str, args: list[str], ip: str | None) -> dict:
    if tool not in _valid_keys:
        raise UnknownTool(tool)
    if not _lock.acquire(blocking=False):
        running = current()
        raise AlreadyRunning((running or {}).get("tool", "another tool"))
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id, "tool": tool, "action": action, "status": "running",
        "pid": None, "started_at": time.time(), "finished_at": None, "rc": None,
        "log_path": str(JOBS_DIR / f"{job_id}.log"),
    }
    _record(job)
    db.audit(f"tool.{action}.start", tool, None, ip)
    threading.Thread(target=_run, args=(job, args, ip), daemon=True).start()
    return job


def start_install(tool: str, ip: str | None = None) -> dict:
    return _start(tool, "install", [tool], ip)


def start_uninstall(tool: str, ip: str | None = None) -> dict:
    return _start(tool, "uninstall", ["--uninstall", tool], ip)
