"""FastAPI application: REST API + WebSocket live feed + dashboard."""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, events, pipeline, report
from .config import get_config
from .scheduler import Scheduler
from .scope import ScopeGuard, extract_host
from .checklist import CATALOG, coverage
from .scoring import risk_score, OWASP_TOP10

cfg = get_config()
STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="Argus VMS", version="1.0.0")
_scheduler: Scheduler | None = None


# ---------------------------------------------------------------- auth
def require_key(x_api_key: str | None = Header(default=None),
                key: str | None = Query(default=None)):
    provided = x_api_key or key
    if provided != cfg.api_key:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    return True


# ---------------------------------------------------------------- lifecycle
@app.on_event("startup")
async def _startup():
    global _scheduler
    db.init(cfg.db_path)
    events.bind_loop(asyncio.get_running_loop())
    pipeline.start_worker(cfg)
    _scheduler = Scheduler(cfg)
    _scheduler.start()


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


# ---------------------------------------------------------------- meta
@app.get("/api/health")
def health():
    return {"ok": True, "app": "Argus", "tag": "T4WF1Q", "version": "1.0.0"}


@app.get("/api/config")
def api_config(_=require_key):  # noqa: B008
    g = ScopeGuard.from_config(cfg)
    return {
        "scope_enforced": g.enforce,
        "allow": g.allow,
        "deny": g.deny,
        "automation": cfg.get("automation", default={}),
        "owasp": OWASP_TOP10,
    }


# ---------------------------------------------------------------- assets
@app.get("/api/assets")
def get_assets(_=require_key):  # noqa: B008
    out = []
    for a in db.list_assets():
        counts = db.severity_counts(a["id"])
        a = dict(a)
        a["counts"] = counts
        a["risk"] = risk_score(counts)
        out.append(a)
    return out


@app.post("/api/assets")
def create_asset(body: AssetIn, _=require_key):  # noqa: B008
    guard = ScopeGuard.from_config(cfg)
    ok, reason = guard.check(body.target)
    if not ok:
        raise HTTPException(status_code=400, detail=f"out of scope: {reason}")
    existing = db.find_asset_by_target(body.target)
    if existing:
        return existing
    asset = db.add_asset(body.name or body.target, body.target, body.kind, body.tags)
    db.ensure_checklist(asset["id"], CATALOG)
    return asset


@app.get("/api/assets/{aid}")
def asset_detail(aid: str, _=require_key):  # noqa: B008
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
def remove_asset(aid: str, _=require_key):  # noqa: B008
    db.delete_asset(aid)
    return {"ok": True}


# ---------------------------------------------------------------- scans
@app.post("/api/assets/{aid}/scan")
def start_scan(aid: str, body: ScanIn, _=require_key):  # noqa: B008
    asset = db.get_asset(aid)
    if not asset:
        raise HTTPException(404, "asset not found")
    guard = ScopeGuard.from_config(cfg)
    ok, reason = guard.check(asset["target"])
    if not ok:
        raise HTTPException(400, f"out of scope: {reason}")
    scan = db.create_scan(aid, body.profile)
    pipeline.enqueue(scan["id"], aid)
    events.publish("scan_update", scan_id=scan["id"], status="queued", asset_id=aid)
    return scan


@app.get("/api/scans")
def scans(asset_id: str | None = None, _=require_key):  # noqa: B008
    return db.list_scans(asset_id)


@app.get("/api/scans/{sid}")
def scan_detail(sid: str, _=require_key):  # noqa: B008
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "scan not found")
    s = dict(s)
    s["events"] = db.list_events(sid, limit=300)
    return s


# ---------------------------------------------------------------- findings
@app.get("/api/findings")
def findings(asset_id: str | None = None, severity: str | None = None,
             status: str | None = None, owasp: str | None = None, _=require_key):  # noqa: B008
    return db.list_findings(asset_id, severity, status, owasp)


@app.get("/api/findings/{fid}")
def finding_detail(fid: str, _=require_key):  # noqa: B008
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "finding not found")
    return f


@app.post("/api/findings/{fid}/status")
def finding_status(fid: str, body: StatusIn, _=require_key):  # noqa: B008
    f = db.set_finding_status(fid, body.status)
    if not f:
        raise HTTPException(404, "finding not found")
    events.publish("finding_update", id=fid, status=body.status)
    return f


# ---------------------------------------------------------------- dashboard stats
@app.get("/api/stats")
def stats(_=require_key):  # noqa: B008
    counts = db.severity_counts()
    assets = db.list_assets()
    return {
        "counts": counts,
        "risk": risk_score(counts),
        "assets": len(assets),
        "owasp": db.owasp_counts(),
        "recent_scans": db.list_scans(limit=8),
        "recent_findings": db.list_findings(limit=10),
    }


# ---------------------------------------------------------------- checklist
@app.get("/api/assets/{aid}/checklist")
def get_checklist(aid: str, _=require_key):  # noqa: B008
    items = db.list_checklist(aid)
    if not items:
        db.ensure_checklist(aid, CATALOG)
        items = db.list_checklist(aid)
    return {"items": items, "coverage": coverage(items)}


@app.post("/api/assets/{aid}/checklist")
def update_checklist(aid: str, body: ChecklistIn, _=require_key):  # noqa: B008
    db.set_checklist(aid, body.item_key, body.state, body.note)
    items = db.list_checklist(aid)
    return {"items": items, "coverage": coverage(items)}


# ---------------------------------------------------------------- scope
@app.get("/api/scope")
def get_scope(_=require_key):  # noqa: B008
    g = ScopeGuard.from_config(cfg)
    return {"enforce": g.enforce, "allow": g.allow, "deny": g.deny}


@app.post("/api/scope/check")
def scope_check(body: ScopeIn, _=require_key):  # noqa: B008
    g = ScopeGuard.from_config(cfg)
    ok, reason = g.check(body.pattern)
    return {"host": extract_host(body.pattern), "allowed": ok, "reason": reason}


# ---------------------------------------------------------------- reports
@app.post("/api/assets/{aid}/report")
def make_report(aid: str, _=require_key):  # noqa: B008
    path = report.generate(cfg, aid)
    if not path:
        raise HTTPException(404, "asset not found")
    return {"path": str(path), "name": Path(path).name}


@app.get("/api/reports")
def list_reports(_=require_key):  # noqa: B008
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(cfg.reports_dir.glob("Argus_*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [{"name": p.name, "size": p.stat().st_size,
             "mtime": int(p.stat().st_mtime)} for p in files]


@app.get("/api/reports/{name}")
def get_report(name: str, _=require_key):  # noqa: B008
    # prevent path traversal
    safe = Path(name).name
    path = cfg.reports_dir / safe
    if not path.exists():
        raise HTTPException(404, "report not found")
    return FileResponse(str(path))


# ---------------------------------------------------------------- websocket
@app.websocket("/ws")
async def ws(websocket: WebSocket):
    # key passed as query param since browsers can't set WS headers
    if websocket.query_params.get("key") != cfg.api_key:
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
