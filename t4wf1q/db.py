"""SQLite data layer. Zero external services required."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_LOCAL = threading.local()
_DB_PATH: Path | None = None
_INIT_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix: str = "") -> str:
    return (prefix + uuid.uuid4().hex[:12]) if prefix else uuid.uuid4().hex[:12]


SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id          TEXT PRIMARY KEY,
    name        TEXT,
    target      TEXT NOT NULL,        -- url or host or cidr
    kind        TEXT NOT NULL,        -- web | host | repo | program
    tags        TEXT DEFAULT '[]',
    created_at  TEXT NOT NULL,
    last_scan   TEXT
);

CREATE TABLE IF NOT EXISTS subdomains (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL,
    host        TEXT NOT NULL,
    alive       INTEGER DEFAULT 0,
    status_code INTEGER,
    title       TEXT,
    tech        TEXT DEFAULT '[]',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(asset_id, host)
);

CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL,
    profile     TEXT NOT NULL,
    status      TEXT NOT NULL,        -- queued|running|done|failed|cancelled
    stage       TEXT,
    progress    INTEGER DEFAULT 0,
    started_at  TEXT,
    finished_at TEXT,
    stats       TEXT DEFAULT '{}',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id           TEXT PRIMARY KEY,
    asset_id     TEXT NOT NULL,
    scan_id      TEXT,
    fingerprint  TEXT NOT NULL,       -- for dedup
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,
    cvss         REAL,
    owasp        TEXT,                 -- A01..A10
    host         TEXT,
    location     TEXT,                 -- url / port / path
    source       TEXT,                 -- scanner name
    description  TEXT,
    evidence     TEXT,
    remediation  TEXT,
    reference    TEXT DEFAULT '[]',
    status       TEXT DEFAULT 'open',  -- open|triaged|in_progress|fixed|verified|false_positive|accepted
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    seen_count   INTEGER DEFAULT 1,
    UNIQUE(asset_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS checklist (
    id          TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL,
    item_key    TEXT NOT NULL,        -- stable key from checklist catalog
    owasp       TEXT,
    title       TEXT NOT NULL,
    state       TEXT DEFAULT 'todo',  -- todo|pass|fail|na
    note        TEXT,
    updated_at  TEXT NOT NULL,
    UNIQUE(asset_id, item_key)
);

CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    scan_id     TEXT,
    asset_id    TEXT,
    level       TEXT DEFAULT 'info',
    kind        TEXT,
    message     TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_asset    ON scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_events_scan    ON events(scan_id);
"""


def init(db_path: Path) -> None:
    global _DB_PATH
    with _INIT_LOCK:
        _DB_PATH = Path(db_path)
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _connect() as c:
            c.executescript(SCHEMA)


def _connect() -> sqlite3.Connection:
    assert _DB_PATH is not None, "db.init() not called"
    conn = sqlite3.connect(_DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def conn():
    c = getattr(_LOCAL, "conn", None)
    if c is None:
        c = _connect()
        _LOCAL.conn = c
    yield c


def _rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


# --- assets ---------------------------------------------------------------
def add_asset(name: str, target: str, kind: str, tags: list[str] | None = None) -> dict:
    aid = new_id("as_")
    with conn() as c:
        c.execute(
            "INSERT INTO assets(id,name,target,kind,tags,created_at) VALUES(?,?,?,?,?,?)",
            (aid, name or target, target, kind, json.dumps(tags or []), now_iso()),
        )
    return get_asset(aid)


def get_asset(aid: str) -> dict | None:
    with conn() as c:
        cur = c.execute("SELECT * FROM assets WHERE id=?", (aid,))
        r = cur.fetchone()
        return dict(r) if r else None


def find_asset_by_target(target: str) -> dict | None:
    with conn() as c:
        cur = c.execute("SELECT * FROM assets WHERE target=?", (target,))
        r = cur.fetchone()
        return dict(r) if r else None


def list_assets() -> list[dict]:
    with conn() as c:
        return _rows(c.execute("SELECT * FROM assets ORDER BY created_at DESC"))


def delete_asset(aid: str) -> None:
    with conn() as c:
        for t in ("findings", "scans", "subdomains", "checklist"):
            c.execute(f"DELETE FROM {t} WHERE asset_id=?", (aid,))
        c.execute("DELETE FROM assets WHERE id=?", (aid,))


def touch_asset_scan(aid: str) -> None:
    with conn() as c:
        c.execute("UPDATE assets SET last_scan=? WHERE id=?", (now_iso(), aid))


# --- subdomains -----------------------------------------------------------
def upsert_subdomain(asset_id: str, host: str, **fields) -> None:
    ts = now_iso()
    with conn() as c:
        cur = c.execute(
            "SELECT id FROM subdomains WHERE asset_id=? AND host=?", (asset_id, host)
        )
        row = cur.fetchone()
        if row:
            sets, vals = [], []
            for k, v in fields.items():
                sets.append(f"{k}=?")
                vals.append(json.dumps(v) if isinstance(v, (list, dict)) else v)
            sets.append("last_seen=?")
            vals.extend([ts, row["id"]])
            c.execute(f"UPDATE subdomains SET {','.join(sets)} WHERE id=?", vals)
        else:
            c.execute(
                "INSERT INTO subdomains(id,asset_id,host,alive,status_code,title,tech,first_seen,last_seen)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    new_id("sd_"), asset_id, host,
                    int(fields.get("alive", 0)),
                    fields.get("status_code"),
                    fields.get("title"),
                    json.dumps(fields.get("tech", [])),
                    ts, ts,
                ),
            )


def list_subdomains(asset_id: str) -> list[dict]:
    with conn() as c:
        return _rows(
            c.execute(
                "SELECT * FROM subdomains WHERE asset_id=? ORDER BY alive DESC, host", (asset_id,)
            )
        )


# --- scans ----------------------------------------------------------------
def create_scan(asset_id: str, profile: str) -> dict:
    sid = new_id("sc_")
    with conn() as c:
        c.execute(
            "INSERT INTO scans(id,asset_id,profile,status,progress,created_at) VALUES(?,?,?,?,?,?)",
            (sid, asset_id, profile, "queued", 0, now_iso()),
        )
    return get_scan(sid)


def update_scan(sid: str, **fields) -> None:
    if not fields:
        return
    sets, vals = [], []
    for k, v in fields.items():
        sets.append(f"{k}=?")
        vals.append(json.dumps(v) if isinstance(v, (list, dict)) else v)
    vals.append(sid)
    with conn() as c:
        c.execute(f"UPDATE scans SET {','.join(sets)} WHERE id=?", vals)


def get_scan(sid: str) -> dict | None:
    with conn() as c:
        cur = c.execute("SELECT * FROM scans WHERE id=?", (sid,))
        r = cur.fetchone()
        return dict(r) if r else None


def list_scans(asset_id: str | None = None, limit: int = 50) -> list[dict]:
    with conn() as c:
        if asset_id:
            return _rows(
                c.execute(
                    "SELECT * FROM scans WHERE asset_id=? ORDER BY created_at DESC LIMIT ?",
                    (asset_id, limit),
                )
            )
        return _rows(c.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)))


# --- findings -------------------------------------------------------------
def upsert_finding(asset_id: str, scan_id: str, f: dict) -> tuple[dict, bool]:
    """Insert or dedup a finding. Returns (finding, is_new)."""
    ts = now_iso()
    fp = f["fingerprint"]
    with conn() as c:
        cur = c.execute(
            "SELECT * FROM findings WHERE asset_id=? AND fingerprint=?", (asset_id, fp)
        )
        row = cur.fetchone()
        if row:
            c.execute(
                "UPDATE findings SET last_seen=?, seen_count=seen_count+1, scan_id=?,"
                " severity=?, cvss=?, status=CASE WHEN status IN('fixed','verified')"
                " THEN 'open' ELSE status END WHERE id=?",
                (ts, scan_id, f["severity"], f.get("cvss"), row["id"]),
            )
            return get_finding(row["id"]), False
        fid = new_id("fi_")
        c.execute(
            "INSERT INTO findings(id,asset_id,scan_id,fingerprint,title,severity,cvss,owasp,"
            "host,location,source,description,evidence,remediation,reference,status,"
            "first_seen,last_seen,seen_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
            (
                fid, asset_id, scan_id, fp, f["title"], f["severity"], f.get("cvss"),
                f.get("owasp"), f.get("host"), f.get("location"), f.get("source"),
                f.get("description"), f.get("evidence"), f.get("remediation"),
                json.dumps(f.get("reference", [])), "open", ts, ts,
            ),
        )
        return get_finding(fid), True


def get_finding(fid: str) -> dict | None:
    with conn() as c:
        cur = c.execute("SELECT * FROM findings WHERE id=?", (fid,))
        r = cur.fetchone()
        return dict(r) if r else None


def list_findings(
    asset_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    owasp: str | None = None,
    limit: int = 500,
) -> list[dict]:
    q = "SELECT * FROM findings WHERE 1=1"
    args: list[Any] = []
    if asset_id:
        q += " AND asset_id=?"; args.append(asset_id)
    if severity:
        q += " AND severity=?"; args.append(severity)
    if status:
        q += " AND status=?"; args.append(status)
    if owasp:
        q += " AND owasp=?"; args.append(owasp)
    q += (
        " ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3"
        " WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, last_seen DESC LIMIT ?"
    )
    args.append(limit)
    with conn() as c:
        return _rows(c.execute(q, args))


def set_finding_status(fid: str, status: str) -> dict | None:
    with conn() as c:
        c.execute("UPDATE findings SET status=? WHERE id=?", (status, fid))
    return get_finding(fid)


def severity_counts(asset_id: str | None = None, open_only: bool = True) -> dict[str, int]:
    q = "SELECT severity, COUNT(*) n FROM findings WHERE 1=1"
    args: list[Any] = []
    if asset_id:
        q += " AND asset_id=?"; args.append(asset_id)
    if open_only:
        q += " AND status NOT IN ('fixed','verified','false_positive')"
    q += " GROUP BY severity"
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    with conn() as c:
        for r in c.execute(q, args):
            out[r["severity"]] = r["n"]
    return out


def owasp_counts(asset_id: str | None = None) -> dict[str, int]:
    q = "SELECT owasp, COUNT(*) n FROM findings WHERE owasp IS NOT NULL"
    args: list[Any] = []
    if asset_id:
        q += " AND asset_id=?"; args.append(asset_id)
    q += " AND status NOT IN ('fixed','verified','false_positive') GROUP BY owasp"
    out: dict[str, int] = {}
    with conn() as c:
        for r in c.execute(q, args):
            out[r["owasp"]] = r["n"]
    return out


# --- checklist ------------------------------------------------------------
def ensure_checklist(asset_id: str, catalog: list[dict]) -> None:
    ts = now_iso()
    with conn() as c:
        for item in catalog:
            c.execute(
                "INSERT OR IGNORE INTO checklist(id,asset_id,item_key,owasp,title,state,updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (new_id("cl_"), asset_id, item["key"], item["owasp"], item["title"], "todo", ts),
            )


def list_checklist(asset_id: str) -> list[dict]:
    with conn() as c:
        return _rows(
            c.execute("SELECT * FROM checklist WHERE asset_id=? ORDER BY owasp, item_key", (asset_id,))
        )


def set_checklist(asset_id: str, item_key: str, state: str, note: str | None = None) -> None:
    with conn() as c:
        c.execute(
            "UPDATE checklist SET state=?, note=COALESCE(?,note), updated_at=? WHERE asset_id=? AND item_key=?",
            (state, note, now_iso(), asset_id, item_key),
        )


# --- events ---------------------------------------------------------------
def log_event(message: str, scan_id: str | None = None, asset_id: str | None = None,
              level: str = "info", kind: str = "log") -> dict:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO events(ts,scan_id,asset_id,level,kind,message) VALUES(?,?,?,?,?,?)",
            (now_iso(), scan_id, asset_id, level, kind, message),
        )
        eid = cur.lastrowid
    return {"id": eid, "ts": now_iso(), "scan_id": scan_id, "asset_id": asset_id,
            "level": level, "kind": kind, "message": message}


def list_events(scan_id: str | None = None, limit: int = 200) -> list[dict]:
    with conn() as c:
        if scan_id:
            return _rows(
                c.execute("SELECT * FROM events WHERE scan_id=? ORDER BY id DESC LIMIT ?",
                          (scan_id, limit))
            )
        return _rows(c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)))
