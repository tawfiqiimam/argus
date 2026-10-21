"""FastAPI application: REST API + WebSocket live feed + dashboard."""
from __future__ import annotations

import asyncio
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, events, pipeline, report, tools
from .checklist import CATALOG, coverage
from .config import get_config
from .ratelimit import RateLimiter
from .scheduler import Scheduler
from .scope import ScopeGuard, extract_host
from .scoring import OWASP_TOP10, risk_score

cfg = get_config()
STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Argus VMS", version="1.1.0")
_scheduler: Scheduler | None = None
_limiter = RateLimiter(cfg.get("security", "rate_limit_per_min", default=600))


# ---------------------------------------------------------------- auth + limits
def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def require_key(request: Request,
                x_api_key: str | None = Header(default=None),
                key: str | None = Query(default=None)):
    # Rate limit first, so brute-forcing the key is throttled too.
    if not _limiter.allow(_client_ip(request) or "unknown"):
        raise HTTPException(status_code=429, detail="rate limit exceeded, slow down")
    provided = (x_api_key or key or "").encode()
    if not secrets.compare_digest(provided, cfg.api_key.encode()):
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    return True


# ---------------------------------------------------------------- lifecycle
@app.on_event("startup")
async def _startup():
    global _scheduler
    db.init(cfg.db_path)
    # Seed runtime-editable scope + settings from config on first boot.
    db.seed_scope(cfg.get("scope", "allow", default=[]), cfg.get("scope", "deny", default=[]))
    db.seed_setting("scope_enforce", cfg.get("scope", "enforce", default=True))
    db.seed_setting("allow_private", cfg.get("scope", "allow_private", default=False))
    db.seed_setting("allow_intrusive", False)      # SQLMap etc. stay off until enabled
    db.seed_setting("emergency_stop", False)
    db.seed_setting("automation_enabled", cfg.get("automation", "enabled", default=True))
    events.bind_loop(asyncio.get_running_loop())
    pipeline.start_worker(cfg)
    _scheduler = Scheduler(cfg)
    _scheduler.start()


def current_guard() -> ScopeGuard:
    """Scope guard built from the live DB rules (UI-editable)."""
    return ScopeGuard.from_db()


@app.on_event("shutdown")
async def _shutdown():
    if _scheduler:
        _scheduler.stop()


# ---------------------------------------------------------------- models
class AssetIn(BaseModel):
    target: str
    name: str | None = None
    kind: str = "web"
    tags: list[str] = []
    # UI-driven scope authorization: when a target is out of scope, the user
    # may authorize it here (an explicit assertion that they own / are allowed
    # to test it). Nothing is scanned without this.
    add_to_scope: bool = False
    authorized: bool = False


class ScanIn(BaseModel):
    profile: str = "owasp-full"


class StatusIn(BaseModel):
    status: str


class ChecklistIn(BaseModel):
    item_key: str
    state: str
    note: str | None = None


class ScopeIn(BaseModel):
    pattern: str


class ScopeAddIn(BaseModel):
    pattern: str
    kind: str = "allow"            # allow | deny
    authorized: bool = False       # required for allow rules
    note: str | None = None


class SettingIn(BaseModel):
    automation_enabled: bool | None = None
    scope_enforce: bool | None = None
    allow_private: bool | None = None
    allow_intrusive: bool | None = None
    intrusive_ack: bool = False    # must be true to enable allow_intrusive


# ---------------------------------------------------------------- meta
@app.get("/api/health")
def health():
    return {"ok": True, "app": "Argus", "tag": "T4WF1Q", "version": "1.1.0"}


@app.get("/api/config")
def api_config(_=Depends(require_key)):  # noqa: B008
    g = current_guard()
    return {
        "scope_enforced": g.enforce,
        "allow": g.allow,
        "deny": g.deny,
        "automation": {
            "enabled": bool(db.get_setting("automation_enabled", cfg.get("automation", "enabled", default=True))),
            "full_scan_cron_hour": cfg.get("automation", "full_scan_cron_hour", default=2),
            "change_watch_minutes": cfg.get("automation", "change_watch_minutes", default=15),
        },
        "owasp": OWASP_TOP10,
        "owasp_names": OWASP_TOP10,
    }


# ---------------------------------------------------------------- assets
@app.get("/api/assets")
def get_assets(_=Depends(require_key)):  # noqa: B008
    out = []
    for a in db.list_assets():
        counts = db.severity_counts(a["id"])
        a = dict(a)
        a["counts"] = counts
        a["risk"] = risk_score(counts)
        out.append(a)
    return out


@app.post("/api/assets")
def create_asset(body: AssetIn, request: Request, _=Depends(require_key)):  # noqa: B008
    guard = current_guard()
    # Store a wildcard as its root domain, so "*.x.com" and "x.com" are the same asset.
    if body.target.strip().startswith("*."):
        body.target = body.target.strip()[2:]
    host = extract_host(body.target)
    ok, reason = guard.check(body.target)
    # Authorize in one step from the UI, but never for a host the guard blocks
    # outright (metadata, private range without lab mode).
    if (not ok and body.add_to_scope and body.authorized
            and host and not guard.host_block_reason(host)):
        db.add_scope("allow", host, note="added from UI (user asserted authorization)")
        db.audit("scope.authorize", host, "allow rule added with user authorization", _client_ip(request))
        guard = current_guard()
        ok, reason = guard.check(body.target)
    if not ok:
        raise HTTPException(status_code=400, detail=f"out of scope: {reason}")
    existing = db.find_asset_by_target(body.target)
    if existing:
        return existing
    asset = db.add_asset(body.name or body.target, body.target, body.kind, body.tags)
    db.ensure_checklist(asset["id"], CATALOG)
    db.audit("asset.create", body.target, f"kind={body.kind}", _client_ip(request))
    return asset


@app.get("/api/assets/{aid}")
def asset_detail(aid: str, _=Depends(require_key)):  # noqa: B008
    a = db.get_asset(aid)
    if not a:
        raise HTTPException(404, "asset not found")
    a = dict(a)
    a["counts"] = db.severity_counts(aid)
    a["risk"] = risk_score(a["counts"])
    a["subdomains"] = db.list_subdomains(aid)
    a["scans"] = db.list_scans(aid, limit=10)
    return a


@app.delete("/api/assets/{aid}")
def remove_asset(aid: str, request: Request, _=Depends(require_key)):  # noqa: B008
    asset = db.get_asset(aid)
    db.delete_asset(aid)
    if asset:
        db.audit("asset.delete", asset["target"], None, _client_ip(request))
    return {"ok": True}


# ---------------------------------------------------------------- scans
def _queue_scan(asset: dict, profile: str, request: Request, action: str = "scan.start") -> dict:
    if db.get_setting("emergency_stop", False):
        raise HTTPException(423, "emergency stop is engaged; clear it before starting scans")
    if profile not in pipeline.PROFILES:
        raise HTTPException(400, f"unknown profile '{profile}'")
    ok, reason = current_guard().check(asset["target"])
    if not ok:
        raise HTTPException(400, f"out of scope: {reason}")
    scan = db.create_scan(asset["id"], profile)
    pipeline.enqueue(scan["id"], asset["id"])
    events.publish("scan_update", scan_id=scan["id"], status="queued", asset_id=asset["id"])
    db.audit(action, asset["target"], f"profile={profile} scan={scan['id']}", _client_ip(request))
    return scan


@app.post("/api/assets/{aid}/scan")
def start_scan(aid: str, body: ScanIn, request: Request, _=Depends(require_key)):  # noqa: B008
    asset = db.get_asset(aid)
    if not asset:
        raise HTTPException(404, "asset not found")
    return _queue_scan(asset, body.profile, request)


@app.get("/api/scans")
def scans(asset_id: str | None = None, _=Depends(require_key)):  # noqa: B008
    return db.list_scans(asset_id)


@app.get("/api/scans/{sid}")
def scan_detail(sid: str, _=Depends(require_key)):  # noqa: B008
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "scan not found")
    s = dict(s)
    s["events"] = db.list_events(sid, limit=300)
    return s


@app.post("/api/scans/{sid}/cancel")
def cancel_scan(sid: str, request: Request, _=Depends(require_key)):  # noqa: B008
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "scan not found")
    if s["status"] not in ("queued", "running"):
        raise HTTPException(409, f"scan is already {s['status']}")
    # A running scan stops at its next stage boundary; a queued one never starts.
    db.update_scan(sid, status="cancelled")
    events.publish("scan_update", scan_id=sid, status="cancelled", asset_id=s["asset_id"])
    db.audit("scan.cancel", sid, f"profile={s['profile']}", _client_ip(request))
    return db.get_scan(sid)


@app.post("/api/scans/{sid}/retry")
def retry_scan(sid: str, request: Request, _=Depends(require_key)):  # noqa: B008
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "scan not found")
    if s["status"] not in ("failed", "cancelled"):
        raise HTTPException(409, "only failed or cancelled scans can be retried")
    asset = db.get_asset(s["asset_id"])
    if not asset:
        raise HTTPException(404, "asset not found")
    return _queue_scan(asset, s["profile"], request, action="scan.retry")


@app.post("/api/emergency-stop")
def emergency_stop(request: Request, _=Depends(require_key)):  # noqa: B008
    """Stop everything: cancel queued and running scans, block new ones, disable automation."""
    db.set_setting("emergency_stop", True)
    db.set_setting("automation_enabled", False)
    stopped = 0
    for s in db.list_scans(limit=500):
        if s["status"] in ("queued", "running"):
            db.update_scan(s["id"], status="cancelled")
            events.publish("scan_update", scan_id=s["id"], status="cancelled", asset_id=s["asset_id"])
            stopped += 1
    events.publish("emergency_stop", engaged=True, cancelled=stopped)
    db.audit("emergency_stop", None, f"engaged; {stopped} scan(s) cancelled", _client_ip(request))
    return {"ok": True, "engaged": True, "cancelled": stopped}


@app.post("/api/emergency-stop/clear")
def emergency_clear(request: Request, _=Depends(require_key)):  # noqa: B008
    """Lift the emergency stop. Automation stays off until re-enabled in Settings."""
    db.set_setting("emergency_stop", False)
    db.audit("emergency_stop", None, "cleared", _client_ip(request))
    events.publish("emergency_stop", engaged=False)
    return {"ok": True, "engaged": False}


# ---------------------------------------------------------------- findings
@app.get("/api/findings")
def findings(asset_id: str | None = None, severity: str | None = None,
             status: str | None = None, owasp: str | None = None, _=Depends(require_key)):  # noqa: B008
    return db.list_findings(asset_id, severity, status, owasp)


@app.get("/api/findings/{fid}")
def finding_detail(fid: str, _=Depends(require_key)):  # noqa: B008
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@app.post("/api/findings/{fid}/status")
def finding_status(fid: str, body: StatusIn, request: Request, _=Depends(require_key)):  # noqa: B008
    try:
        f = db.set_finding_status(fid, body.status)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not f:
        raise HTTPException(404, "finding not found")
    db.audit("finding.status", fid, f"status={body.status}", _client_ip(request))
    events.publish("finding_update", id=fid, status=body.status)
    return f


# ---------------------------------------------------------------- dashboard stats
@app.get("/api/stats")
def stats(_=Depends(require_key)):  # noqa: B008
    counts = db.severity_counts()
    assets = db.list_assets()
    return {
        "counts": counts,
        "risk": risk_score(counts),
        "assets": len(assets),
        "scans": db.scan_status_counts(),
        "owasp": db.owasp_counts(),
        "recent_scans": db.list_scans(limit=8),
        "recent_findings": db.list_findings(limit=10),
    }


# ---------------------------------------------------------------- checklist
@app.get("/api/assets/{aid}/checklist")
def get_checklist(aid: str, _=Depends(require_key)):  # noqa: B008
    items = db.list_checklist(aid)
    if not items:
        db.ensure_checklist(aid, CATALOG)
        items = db.list_checklist(aid)
    return {"items": items, "coverage": coverage(items)}


@app.post("/api/assets/{aid}/checklist")
def update_checklist(aid: str, body: ChecklistIn, _=Depends(require_key)):  # noqa: B008
    db.set_checklist(aid, body.item_key, body.state, body.note)
    items = db.list_checklist(aid)
    return {"items": items, "coverage": coverage(items)}


# ---------------------------------------------------------------- scope
@app.get("/api/scope")
def get_scope(_=Depends(require_key)):  # noqa: B008
    g = current_guard()
    return {"enforce": g.enforce, "allow": g.allow, "deny": g.deny, "rules": db.list_scope()}


@app.post("/api/scope")
def scope_add(body: ScopeAddIn, request: Request, _=Depends(require_key)):  # noqa: B008
    pattern = (body.pattern or "").strip().lower()
    if not pattern:
        raise HTTPException(400, "empty pattern")
    if body.kind == "allow" and not body.authorized:
        raise HTTPException(400, "authorization required: confirm you own or are "
                                 "authorized to test this target before adding it to scope")
    note = body.note or ("authorized via UI" if body.kind == "allow" else "deny rule via UI")
    rule = db.add_scope(body.kind, pattern, note=note)
    db.audit("scope.add", pattern, f"kind={body.kind}", _client_ip(request))
    return {"ok": True, "rule": rule, "rules": db.list_scope()}


@app.delete("/api/scope/{rule_id}")
def scope_remove(rule_id: str, request: Request, _=Depends(require_key)):  # noqa: B008
    db.remove_scope(rule_id)
    db.audit("scope.remove", rule_id, None, _client_ip(request))
    return {"ok": True, "rules": db.list_scope()}


@app.post("/api/scope/check")
def scope_check(body: ScopeIn, _=Depends(require_key)):  # noqa: B008
    g = current_guard()
    ok, reason = g.check(body.pattern)
    return {"host": extract_host(body.pattern), "allowed": ok, "reason": reason}


# ---------------------------------------------------------------- settings
def _settings_view() -> dict:
    return {
        "automation_enabled": bool(db.get_setting("automation_enabled", True)),
        "scope_enforce": bool(db.get_setting("scope_enforce", True)),
        "allow_private": bool(db.get_setting("allow_private", False)),
        "allow_intrusive": bool(db.get_setting("allow_intrusive", False)),
        "emergency_stop": bool(db.get_setting("emergency_stop", False)),
        "rate_limit_per_min": _limiter.limit,
        "full_scan_cron_hour": cfg.get("automation", "full_scan_cron_hour", default=2),
        "change_watch_minutes": cfg.get("automation", "change_watch_minutes", default=15),
    }


@app.get("/api/settings")
def get_settings(_=Depends(require_key)):  # noqa: B008
    return _settings_view()


@app.post("/api/settings")
def update_settings(body: SettingIn, request: Request, _=Depends(require_key)):  # noqa: B008
    changed: list[str] = []
    if body.automation_enabled is not None:
        db.set_setting("automation_enabled", bool(body.automation_enabled))
        changed.append(f"automation_enabled={body.automation_enabled}")
    if body.scope_enforce is not None:
        db.set_setting("scope_enforce", bool(body.scope_enforce))
        changed.append(f"scope_enforce={body.scope_enforce}")
    if body.allow_private is not None:
        db.set_setting("allow_private", bool(body.allow_private))
        changed.append(f"allow_private={body.allow_private}")
    if body.allow_intrusive is not None:
        if body.allow_intrusive and not body.intrusive_ack:
            raise HTTPException(400, "enabling intrusive checks requires intrusive_ack=true: "
                                     "confirm you hold written authorization for every target")
        db.set_setting("allow_intrusive", bool(body.allow_intrusive))
        changed.append(f"allow_intrusive={body.allow_intrusive}")
    if changed:
        db.audit("settings.update", None, "; ".join(changed), _client_ip(request))
    return _settings_view()


# ---------------------------------------------------------------- audit
@app.get("/api/audit")
def audit_log(limit: int = 200, _=Depends(require_key)):  # noqa: B008
    return db.list_audit(max(1, min(limit, 1000)))


# ---------------------------------------------------------------- reports
@app.post("/api/assets/{aid}/report")
def make_report(aid: str, request: Request, _=Depends(require_key)):  # noqa: B008
    path = report.generate(cfg, aid)
    if not path:
        raise HTTPException(404, "asset not found")
    db.audit("report.generate", aid, Path(path).name, _client_ip(request))
    return {"path": str(path), "name": Path(path).name}


@app.get("/api/reports")
def list_reports(_=Depends(require_key)):  # noqa: B008
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(cfg.reports_dir.glob("Argus_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [{"name": p.name, "size": p.stat().st_size,
             "mtime": int(p.stat().st_mtime)} for p in files]


@app.get("/api/reports/{name}")
def get_report(name: str, _=Depends(require_key)):  # noqa: B008
    # prevent path traversal
    safe = Path(name).name
    path = cfg.reports_dir / safe
    if not path.exists():
        raise HTTPException(404, "report not found")
    return FileResponse(str(path))


# ---------------------------------------------------------------- export + tools
@app.get("/api/assets/{aid}/export/{fmt}")
def export_asset(aid: str, fmt: str, _=Depends(require_key)):  # noqa: B008
    if fmt not in ("json", "csv"):
        raise HTTPException(400, "format must be json or csv")
    path = report.export(cfg, aid, fmt)
    if not path:
        raise HTTPException(404, "asset not found")
    return FileResponse(str(path), filename=path.name)


@app.get("/api/tools")
def tools_status(_=Depends(require_key)):  # noqa: B008
    return tools.detect()


# ---------------------------------------------------------------- websocket
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    # key passed as query param since browsers can't set WS headers
    given = (websocket.query_params.get("key") or "").encode()
    if not secrets.compare_digest(given, cfg.api_key.encode()):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    q = await events.subscribe()
    try:
        await websocket.send_json({"kind": "hello", "app": "Argus", "tag": "T4WF1Q"})
        while True:
            msg = await q.get()
            await websocket.send_text(msg)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        events.unsubscribe(q)


# ---------------------------------------------------------------- UI
@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(str(STATIC / "index.html"))


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
