"""Scan orchestration pipeline (runs in a background worker thread).

Stages always run in the fixed, safe order of STAGE_ORDER; a profile decides
which of them apply. Each stage is isolated: a failing tool is recorded as a
stage error and the scan continues with partial results. Between stages the
pipeline checks for a cancel request or an engaged emergency stop and ends the
scan as "cancelled" with whatever partial results it has. Progress and log
lines go to the database and the WebSocket bus.

Note: a stage that is already running (for example a long nuclei run) finishes
before the stop takes effect. Stop requests never kill a half-written report.
"""
from __future__ import annotations

import threading
import traceback
from queue import Queue
from urllib.parse import urlparse

from . import alerts, db, events, report, research
from .config import Config
from .scanners import (chain, code_extra, evidence, extra_tools, httpchecks, nmap, nuclei, paths,
                       recon, param_hints, recon_extra, takeover, web_extra, xss)
from .scanners.base import ScanContext
from .scope import ScopeGuard, extract_host, looks_like_domain
from .scoring import meets_threshold, normalize_severity

STAGE_ORDER = [
    "recon", "amass", "takeover", "probe", "whatweb", "discover", "jsluice", "params", "arjun",
    "http", "paths", "xss", "dalfox", "zap", "nuclei", "nikto", "testssl",
    "wpscan", "sqlmap", "nmap", "evidence",
    "gitleaks", "semgrep", "depcheck", "trivy",
]

# Stages that need something to point at: a single-tool run on a fresh asset
# runs "probe" first so there is at least a live URL to work with.
_NEEDS_PROBE = {"whatweb", "discover", "jsluice", "arjun", "params", "http", "paths", "xss",
                "dalfox", "zap", "nuclei", "nikto", "testssl", "wpscan", "sqlmap", "evidence"}

_API_PATHS = {"api", "config", "debug", "vcs", "secrets", "dev", "admin", "robots"}
_WP_PATHS = {"wp", "config", "debug", "backup", "vcs", "secrets", "robots"}

PROFILES = {
    "passive":    {"label": "Passive Reconnaissance", "stages": ["recon", "amass", "takeover"]},
    "recon":      {"label": "Recon only", "stages": ["recon", "amass", "probe", "takeover"]},
    "quick":      {"label": "Quick checks", "stages": ["probe", "http"]},
    "web":        {"label": "Web Application Assessment",
                   "stages": ["probe", "whatweb", "discover", "jsluice", "params", "arjun", "http",
                              "paths", "xss", "zap", "nuclei", "sqlmap", "evidence"]},
    "api":        {"label": "API Security Assessment",
                   "stages": ["probe", "discover", "jsluice", "params", "arjun", "http", "paths", "xss",
                              "zap", "nuclei", "sqlmap"],
                   "path_categories": _API_PATHS},
    "infra":      {"label": "Domain & Infrastructure Assessment",
                   "stages": ["recon", "amass", "probe", "takeover", "nmap", "testssl", "nikto"]},
    "wordpress":  {"label": "WordPress Assessment",
                   "stages": ["probe", "whatweb", "paths", "wpscan", "dalfox", "nuclei"],
                   "path_categories": _WP_PATHS, "force_wpscan": True},
    "code":       {"label": "Source Code Security Assessment",
                   "stages": ["gitleaks", "semgrep", "depcheck"]},
    "dependency": {"label": "Dependency & Container Assessment", "stages": ["depcheck", "trivy"]},
    "owasp-full": {"label": "OWASP Top 10 web + network",
                   "stages": ["recon", "amass", "probe", "takeover", "whatweb", "discover", "jsluice",
                              "params", "arjun", "http", "paths", "xss", "dalfox", "zap", "nuclei",
                              "nikto", "testssl", "sqlmap", "nmap", "evidence"]},
}
PROFILES["full"] = {"label": "Full Authorized Assessment", "stages": list(STAGE_ORDER)}

# ----- single-tool profiles: "tool:<stage>" runs exactly one stage (plus a probe when the
# stage needs a live URL). Lets a researcher point one scanner at one target on demand,
# without committing to a whole profile. Dynamic, so a new stage is picked up for free.
for _stage in STAGE_ORDER:
    _stages = (["probe", _stage] if _stage in _NEEDS_PROBE and _stage != "probe" else [_stage])
    PROFILES[f"tool:{_stage}"] = {"label": f"Single tool — {_stage}", "stages": _stages,
                                  "single_tool": _stage}
del _stage, _stages

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
    threading.Thread(target=_worker_loop, args=(cfg,), daemon=True, name="argus-worker").start()


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


def _set_stage(scan_id: str, stage: str, progress: int, log) -> None:
    # Status is deliberately not written here, so a concurrent cancel is not overwritten.
    db.update_scan(scan_id, stage=stage, progress=progress)
    events.publish("scan_update", scan_id=scan_id, stage=stage, progress=progress)
    log("info", f"stage: {stage}")


def _halt_reason(scan_id: str) -> str | None:
    """Why this scan must stop now, or None if it may continue."""
    if db.get_setting("emergency_stop", False):
        return "emergency stop engaged"
    s = db.get_scan(scan_id)
    if s and s.get("status") == "cancelled":
        return "cancelled by operator"
    return None


def _fallback(ctx: ScanContext) -> str:
    t = ctx.asset["target"]
    return t if "://" in t else f"https://{t}"


def _live(ctx: ScanContext, st: dict) -> list[str]:
    return st["live"] or [_fallback(ctx)]


# ---------------------------------------------------------------- stages
def _s_recon(ctx, st, guard, prof):
    root = st["root"]
    if not looks_like_domain(root):
        ctx.log("info", "recon: target is not a domain, subdomain enumeration skipped")
        return
    found = recon.enumerate_subdomains(ctx, root)
    ok_hosts = guard.in_scope_hosts(found)
    if len(ok_hosts) < len(found):
        ctx.log("warn", f"scope: {len(found) - len(ok_hosts)} discovered host(s) out of scope, skipped")
    st["hosts"] = ok_hosts or [root]
    for h in st["hosts"]:
        db.upsert_subdomain(ctx.asset["id"], h)


def _s_amass(ctx, st, guard, prof):
    root = st["root"]
    if not looks_like_domain(root):
        return
    found = extra_tools.amass_enum(ctx, root)
    ok_hosts = guard.in_scope_hosts(found)
    if len(ok_hosts) < len(found):
        ctx.log("warn", f"scope: {len(found) - len(ok_hosts)} amass host(s) out of scope, skipped")
    new_hosts = [h for h in ok_hosts if h not in st["hosts"]]
    for h in new_hosts:
        db.upsert_subdomain(ctx.asset["id"], h)
    st["hosts"] = list(dict.fromkeys(st["hosts"] + new_hosts))


def _s_takeover(ctx, st, guard, prof):
    hosts = st["hosts"] or [st["root"]]
    st["findings"] += takeover.scan(ctx, hosts, guard)


def _s_probe(ctx, st, guard, prof):
    live: list[str] = []
    for rec in recon.probe_hosts(ctx, st["hosts"] or [st["root"]]):
        host = rec.get("host")
        if not host:
            continue
        db.upsert_subdomain(ctx.asset["id"], host, alive=1 if rec.get("url") else 0,
                            status_code=rec.get("status"), title=rec.get("title"),
                            tech=rec.get("tech") or [])
        if rec.get("url"):
            live.append(rec["url"])
            st["tech"][host] = rec.get("tech") or []
            events.publish("subdomain", scan_id=ctx.scan_id, asset_id=ctx.asset["id"], **rec)
    if live:
        st["live"] = list(dict.fromkeys(live))


def _s_whatweb(ctx, st, guard, prof):
    for host, techs in recon_extra.whatweb(ctx, _live(ctx, st)[:40]).items():
        st["tech"][host] = list(dict.fromkeys(st["tech"].get(host, []) + techs))


def _s_discover(ctx, st, guard, prof):
    found = recon_extra.discover_urls(ctx, st["hosts"] or [st["root"]])
    ok = [u for u in found if guard.check(u)[0]][:300]
    st["discovered"] = ok
    st["live"] = list(dict.fromkeys(_live(ctx, st) + ok))


def _s_jsluice(ctx, st, guard, prof):
    # Chain: feed every discovered .js file into jsluice; what it finds becomes new
    # discovered URLs, so params/xss/dalfox/nuclei downstream test them too.
    js_candidates = [u for u in _live(ctx, st) + st["discovered"] if u.split("?")[0].endswith(".js")]
    found = recon_extra.jsluice_scan(ctx, js_candidates)
    ok = [u for u in found if guard.check(u)[0]]
    if ok:
        ctx.log("info", f"chain: jsluice found {len(ok)} endpoint(s) → added to the attack surface")
        st["discovered"] = list(dict.fromkeys(st["discovered"] + ok))


def _s_params(ctx, st, guard, prof):
    # Passive: parameter NAMES only. No request is sent for these leads.
    urls = list(dict.fromkeys(_live(ctx, st) + st["discovered"]))
    leads = param_hints.leads_for_urls(urls)
    st["leads"] = leads        # shared with later stages (dalfox, sqlmap) for focused testing
    st["findings"] += [param_hints.lead_to_finding(lead) for lead in leads]
    ctx.log("info", f"params: {len(leads)} manual-review lead(s) from parameter names")


def _s_arjun(ctx, st, guard, prof):
    # Chain: hidden parameters arjun discovers become new leads too, on top of the
    # ones param_hints classified from the visible query strings.
    urls = [u for u in _live(ctx, st) if guard.check(u)[0]][:recon_extra.MAX_ARJUN_URLS]
    findings, discovered = recon_extra.arjun_scan(ctx, urls)
    st["findings"] += findings
    new_leads = []
    for url, names in discovered.items():
        base = url.split("?", 1)[0]
        for name in names:
            # One parameter at a time: classify_url only sees the NEW one, never the
            # URL's existing query string (which params already classified it).
            new_leads += param_hints.classify_url(f"{base}?{name}=1")
    if new_leads:
        seen = {(l["base"], l["param"], l["class"]) for l in st["leads"]}
        added = [l for l in new_leads if (l["base"], l["param"], l["class"]) not in seen]
        st["leads"] = st["leads"] + added
        if added:
            ctx.log("info", f"chain: {len(added)} hidden parameter(s) added as leads for dalfox/sqlmap")


def _s_http(ctx, st, guard, prof):
    st["findings"] += httpchecks.scan(ctx, _live(ctx, st)[:60])


def _s_paths(ctx, st, guard, prof):
    st["findings"] += paths.scan(ctx, _live(ctx, st), categories=prof.get("path_categories"), guard=guard)


def _s_xss(ctx, st, guard, prof):
    st["findings"] += xss.scan(ctx, _live(ctx, st) + st["discovered"], guard=guard)


def _s_dalfox(ctx, st, guard, prof):
    in_scope = [u for u in _live(ctx, st) + st["discovered"] if "?" in u and guard.check(u)[0]]
    # Chain: parameters that param_hints called XSS-prone, or that the reflection probe
    # already flagged, are tested first and are the ones most worth the budget.
    focus = chain.lead_keys(st.get("leads", []), chain.XSS_CLASSES) | chain.reflection_keys(st["findings"])
    urls, n_focus = chain.prioritize(in_scope, focus, cap=20)
    if n_focus:
        ctx.log("info", f"chain: {n_focus} parameter(s) flagged by earlier stages → dalfox tests them first")
    found = web_extra.dalfox(ctx, urls)
    # Chain: where dalfox and the reflection probe agree, mark it as stronger proof.
    found, corro = chain.annotate_corroboration(found, chain.reflection_keys(st["findings"]))
    if corro:
        ctx.log("info", f"chain: {corro} dalfox finding(s) corroborated by the reflection probe (confidence raised)")
    st["findings"] += found


def _s_zap(ctx, st, guard, prof):
    urls = [u for u in _live(ctx, st) if guard.check(u)[0]][:3]
    st["findings"] += extra_tools.zap_baseline(ctx, urls)


def _s_nuclei(ctx, st, guard, prof):
    st["findings"] += nuclei.scan(ctx, _live(ctx, st))


def _s_nikto(ctx, st, guard, prof):
    st["findings"] += web_extra.nikto(ctx, _live(ctx, st)[:10])


def _s_testssl(ctx, st, guard, prof):
    st["findings"] += web_extra.testssl(ctx, _live(ctx, st)[:20])


def _s_wpscan(ctx, st, guard, prof):
    urls = [u for u in _live(ctx, st)
            if any("wordpress" in t.lower() for t in st["tech"].get(urlparse(u).hostname or "", []))]
    if not urls and prof.get("force_wpscan"):
        urls = _live(ctx, st)[:5]
    if not urls:
        ctx.log("info", "wpscan: no WordPress detected, skipped")
        return
    st["findings"] += web_extra.wpscan(ctx, [u for u in urls if guard.check(u)[0]][:10])


def _s_sqlmap(ctx, st, guard, prof):
    # Intrusive: runs only when the operator has switched it on in Settings.
    if not db.get_setting("allow_intrusive", False):
        ctx.log("info", "sqlmap skipped: intrusive checks are off (enable in Settings after you have authorization)")
        return
    in_scope = [u for u in _live(ctx, st) + st["discovered"] if "?" in u and guard.check(u)[0]]
    focus = chain.lead_keys(st.get("leads", []), chain.SQLI_CLASSES)
    urls, n_focus = chain.prioritize(in_scope, focus, cap=len(in_scope))
    if n_focus:
        ctx.log("info", f"chain: {n_focus} parameter(s) flagged as injection-prone → sqlmap tests them first")
    st["findings"] += extra_tools.sqlmap(ctx, urls, allow_intrusive=True)


def _s_nmap(ctx, st, guard, prof):
    hosts = sorted({extract_host(u) for u in _live(ctx, st)} - {""})[:20]
    st["findings"] += nmap.scan(ctx, hosts)


def _s_evidence(ctx, st, guard, prof):
    urls = [u for u in _live(ctx, st) if guard.check(u)[0]][:evidence.MAX_TARGETS]
    out_dir = ctx.cfg.evidence_dir / ctx.asset["id"] / ctx.scan_id
    manifest = evidence.capture(ctx, urls, out_dir)
    st["screenshots"] = manifest


def _code_guard(ctx) -> bool:
    if code_extra._local_path(ctx):
        return True
    ctx.log("info", "code stage skipped: target is not a local directory (use a file path target)")
    return False


def _s_gitleaks(ctx, st, guard, prof):
    if _code_guard(ctx):
        st["findings"] += code_extra.gitleaks(ctx)


def _s_semgrep(ctx, st, guard, prof):
    if _code_guard(ctx):
        st["findings"] += code_extra.semgrep(ctx)


def _s_depcheck(ctx, st, guard, prof):
    if _code_guard(ctx):
        st["findings"] += extra_tools.dependency_check(ctx)


def _s_trivy(ctx, st, guard, prof):
    if _code_guard(ctx):
        st["findings"] += code_extra.trivy(ctx)


STAGE_FUNCS = {
    "recon": _s_recon, "amass": _s_amass, "takeover": _s_takeover, "probe": _s_probe,
    "whatweb": _s_whatweb, "discover": _s_discover, "jsluice": _s_jsluice, "params": _s_params,
    "arjun": _s_arjun, "http": _s_http, "paths": _s_paths,
    "xss": _s_xss, "dalfox": _s_dalfox, "zap": _s_zap, "nuclei": _s_nuclei,
    "nikto": _s_nikto, "testssl": _s_testssl, "wpscan": _s_wpscan, "sqlmap": _s_sqlmap,
    "nmap": _s_nmap, "evidence": _s_evidence, "gitleaks": _s_gitleaks, "semgrep": _s_semgrep,
    "depcheck": _s_depcheck, "trivy": _s_trivy,
}


def _detect_followups(st: dict) -> set[str]:
    """What the gathered evidence says we should deepen with (tools triggering tools)."""
    fu: set[str] = set()
    tech_all = " ".join(t.lower() for techs in st["tech"].values() for t in techs)
    titles = " ".join((getattr(f, "title", "") or "").lower() for f in st["findings"])
    blob = tech_all + " " + titles
    if "wordpress" in blob or "wp-" in blob:
        fu.add("wpscan")        # a WordPress fingerprint pulls in the WordPress scanner
    # A parameter that reflects or looks injection-prone deepens with dalfox.
    if any(getattr(f, "source", "") == "argus-xss" for f in st["findings"]):
        fu.add("dalfox")
    return fu


def _run_followups(ctx, st, guard, prof, already: set, scan_id: str, log) -> None:
    """Run evidence-driven follow-up stages the profile did not include. Bounded to 2 rounds."""
    ran = set(already)
    for _round in range(2):
        wanted = _detect_followups(st) - ran
        stages = [s for s in STAGE_ORDER if s in wanted]
        if not stages:
            return
        for stage in stages:
            if _halt_reason(scan_id):
                return
            ran.add(stage)
            log("info", f"chain: evidence triggered a deeper '{stage}' check")
            _set_stage(scan_id, f"chain:{stage}", 90, log)
            try:
                STAGE_FUNCS[stage](ctx, st, guard, prof)
            except Exception as e:
                st["errors"].append(f"chain {stage} failed: {type(e).__name__}: {str(e)[:120]}")
                log("error", f"chain {stage} failed: {type(e).__name__}")


# ---------------------------------------------------------------- store + run
def _store(ctx: ScanContext, st: dict, cfg: Config, threshold: str) -> tuple[int, dict]:
    aid = ctx.asset["id"]
    new = 0
    tally = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in st["findings"]:
        d = f.to_dict()
        d["severity"] = normalize_severity(d["severity"])
        research.enrich(d)                 # pinpoint + manual verification + research links
        tally[d["severity"]] += 1
        stored, is_new = db.upsert_finding(aid, ctx.scan_id, d)
        if is_new:
            new += 1
            events.publish("finding", scan_id=ctx.scan_id, asset_id=aid, id=stored["id"],
                           title=stored["title"], severity=stored["severity"],
                           owasp=stored.get("owasp"), host=stored.get("host"),
                           location=stored.get("location"))
            if meets_threshold(d["severity"], threshold):
                alerts.notify(cfg, ctx.asset, stored)
    return new, tally


def _run_scan(cfg: Config, scan_id: str, asset_id: str) -> None:
    asset = db.get_asset(asset_id)
    if not asset:
        return

    stop = _halt_reason(scan_id)
    if stop:
        # Cancelled while still queued, or emergency stop engaged: never start it.
        db.update_scan(scan_id, status="cancelled", stage="cancelled", finished_at=db.now_iso())
        db.log_event(f"scan not started: {stop}", scan_id, asset_id, "warn", "log")
        events.publish("scan_update", scan_id=scan_id, status="cancelled", stage="cancelled")
        return

    scan = db.get_scan(scan_id) or {}
    profile = scan.get("profile") or "owasp-full"
    prof = PROFILES.get(profile, PROFILES["owasp-full"])
    wanted = set(prof["stages"])
    active = [s for s in STAGE_ORDER if s in wanted]

    log = _mk_log(scan_id, asset_id)
    guard = ScopeGuard.from_db()   # live, UI-managed scope
    ctx = ScanContext(asset=asset, scan_id=scan_id, cfg=cfg, log=log,
                      scanners_cfg=cfg.get("scanners", default={}))
    root = extract_host(asset["target"])
    st = {"root": root, "hosts": [root] if root else [], "live": [], "tech": {},
          "discovered": [], "findings": [], "errors": [], "leads": [], "followups": set(),
          "screenshots": []}

    db.update_scan(scan_id, status="running", stage="start", progress=1, started_at=db.now_iso())
    events.publish("scan_update", scan_id=scan_id, status="running", progress=1)
    log("info", f"=== Argus scan start · {prof['label']} · target={asset['target']} ===")
    log("info", f"stages: {', '.join(active)}")

    halted = None
    for i, stage in enumerate(active):
        halted = _halt_reason(scan_id)
        if halted:
            st["errors"].append(f"stopped before '{stage}': {halted}")
            log("warn", f"scan stopped: {halted}")
            break
        _set_stage(scan_id, stage, 5 + int(85 * i / max(1, len(active))), log)
        try:
            STAGE_FUNCS[stage](ctx, st, guard, prof)
        except Exception as e:
            msg = f"{stage} failed: {type(e).__name__}: {str(e)[:160]}"
            st["errors"].append(msg)
            log("error", msg)
    # Deep chaining: let the evidence gathered above trigger deeper, focused checks.
    if not halted:
        _run_followups(ctx, st, guard, prof, set(active), scan_id, log)
    halted = halted or _halt_reason(scan_id)

    _set_stage(scan_id, "store", 92, log)
    new, tally = _store(ctx, st, cfg, cfg.get("alerts", "min_severity", default="high"))
    db.touch_asset_scan(asset_id)
    final = "cancelled" if halted else "done"
    stats = {"total": len(st["findings"]), "new": new, **tally, "stages": active,
             "hosts": len(st["hosts"]), "urls": len(_live(ctx, st)),
             "errors": st["errors"][:20], "halted": halted,
             "screenshots": len(st["screenshots"])}
    db.update_scan(scan_id, status=final, stage=final, progress=100,
                   finished_at=db.now_iso(), stats=stats)
    log("info", f"=== scan {final} · {stats['total']} finding(s), {new} new, "
                f"{len(st['errors'])} stage error(s) ===")
    events.publish("scan_update", scan_id=scan_id, status=final, progress=100, stats=stats)

    try:
        path = report.generate(cfg, asset_id, scan_id)
        if path:
            log("info", f"report written: {path}")
            events.publish("report_ready", scan_id=scan_id, asset_id=asset_id, path=str(path))
    except Exception as e:
        log("warn", f"report generation failed: {e}")
