"""Extra recon adapters: whatweb (fingerprint), katana + gau (URL discovery),
arjun (hidden parameter discovery), jsluice (endpoints hiding in JS files).

These enrich the attack surface. katana/gau/arjun/jsluice feed parameterized
URLs and leads to the active scanners (e.g. dalfox, sqlmap) — this is the
"tools talk to each other" chaining: each one's output becomes another one's
input. All degrade gracefully when absent.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .base import Finding, ScanContext, run, tool_available
from .netutil import fetch


def whatweb(ctx: ScanContext, urls: list[str]) -> dict[str, list[str]]:
    """Return {host: [technologies]}."""
    bin_ = ctx.scanners_cfg.get("whatweb", "whatweb")
    tech: dict[str, list[str]] = {}
    if not (bin_ and tool_available(bin_)):
        return tech
    for url in urls:
        host = urlparse(url).hostname
        code, so, se = run([bin_, "--no-errors", "-q", "--color=never", url], timeout=90)
        if so:
            parts = [p.strip() for p in so.replace(url, "").split(",") if p.strip()]
            tech[host] = parts[:20]
    if tech:
        ctx.log("info", f"whatweb: fingerprinted {len(tech)} host(s)")
    return tech


def discover_urls(ctx: ScanContext, hosts: list[str]) -> list[str]:
    """Use katana (crawl) + gau (historical) to find more URLs, esp. with params."""
    cfg = ctx.scanners_cfg
    found: set[str] = set()

    katana = cfg.get("katana", "katana")
    if katana and tool_available(katana):
        for host in hosts:
            url = host if "://" in host else f"https://{host}"
            ctx.log("info", f"katana: crawling {url}")
            code, so, se = run([katana, "-u", url, "-silent", "-jc", "-d", "2"], timeout=180)
            for line in so.splitlines():
                if line.strip():
                    found.add(line.strip())
    else:
        ctx.log("warn", "katana not installed — skipping active crawl")

    gau = cfg.get("gau", "gau")
    if gau and tool_available(gau):
        for host in hosts:
            bare = urlparse(host).hostname or host
            ctx.log("info", f"gau: historical URLs for {bare}")
            try:
                p = subprocess.run([gau, "--threads", "5", bare], input="",
                                   capture_output=True, text=True, timeout=180, check=False)
                for line in p.stdout.splitlines():
                    if line.strip():
                        found.add(line.strip())
            except Exception:
                pass
    else:
        ctx.log("warn", "gau not installed — skipping historical URL discovery")

    urls = sorted(found)
    if urls:
        ctx.log("info", f"url-discovery: {len(urls)} URL(s) found")
    return urls


# ---------------------------------------------------------------- arjun (hidden parameters)
MAX_ARJUN_URLS = 15


def _parse_arjun_json(data) -> dict[str, list[str]]:
    """Arjun's JSON report has varied across versions. Accept the shapes seen in the wild:
    {"url": ["param", ...]}  or  {"url": {"params": [...]}}  or  a list of either.
    Always returns {url: [param names]}.
    """
    out: dict[str, list[str]] = {}

    def _names(v) -> list[str]:
        if isinstance(v, list):
            return [str(x.get("name", x) if isinstance(x, dict) else x) for x in v]
        if isinstance(v, dict):
            return _names(v.get("params") or v.get("parameters") or [])
        return []

    if isinstance(data, dict):
        for url, v in data.items():
            names = _names(v)
            if names:
                out[url] = names
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("url"):
                names = _names(item.get("params") or item.get("parameters") or [])
                if names:
                    out[item["url"]] = names
    return out


def arjun_findings(discovered: dict[str, list[str]]) -> list[Finding]:
    """Turn {url: [new param names]} into info-level leads, one per parameter.

    Pure function: no request is made here, so it's unit-testable without arjun.
    The parameter is appended as a lead (value left as a placeholder '1'), which
    lets param_hints classify it and feeds the same chain that dalfox/sqlmap use.
    """
    out: list[Finding] = []
    for url, names in discovered.items():
        p = urlparse(url)
        if not p.hostname:
            continue
        for name in names[:25]:
            out.append(Finding(
                title=f"Hidden parameter discovered: '{name}' (not linked anywhere on the page)"[:140],
                severity="info", owasp="A05",
                host=p.hostname, location=f"{urlunparse(p._replace(query=''))}?{name}=",
                source="arjun",
                description=(f"arjun found that the server responds differently when '{name}' is "
                             "present, even though no link or form references it. Hidden parameters "
                             "often bypass validation that only runs on the documented ones — "
                             "review what this parameter does by hand before reporting."),
                evidence=f"found via parameter brute-force on {url}",
                remediation="Remove unused parameters, or apply the same validation to every parameter.",
                confidence="low",
            ))
    return out


def arjun_scan(ctx: ScanContext, urls: list[str]) -> tuple[list[Finding], dict[str, list[str]]]:
    """Discover undocumented parameters on a handful of live pages.

    Active but low-impact (standard parameter brute-forcing, the same technique
    manual testers use). Returns (findings, {url: [new param names]}) — the dict
    lets the pipeline add the discovered parameters as leads for later stages.
    """
    bin_ = ctx.scanners_cfg.get("arjun", "arjun")
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "arjun not installed — skipping hidden-parameter discovery")
        return [], {}
    targets = list(dict.fromkeys(urls))[:MAX_ARJUN_URLS]
    if not targets:
        return [], {}
    discovered: dict[str, list[str]] = {}
    for url in targets:
        fd, tmp = tempfile.mkstemp(suffix=".json", prefix="argus_arjun_")
        os.close(fd)
        try:
            ctx.log("info", f"arjun: probing {url} for hidden parameters")
            run([bin_, "-u", url, "-oJ", tmp, "-t", "5", "--stable", "-q"], timeout=180)
            with open(tmp, encoding="utf-8") as fh:
                data = json.load(fh)
            parsed = _parse_arjun_json(data)
        except (OSError, ValueError):
            parsed = {}
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        # Drop parameters the URL already carries; we only care about NEW ones.
        existing = {k.lower() for k, _ in parse_qsl(urlparse(url).query)}
        for u, names in parsed.items():
            fresh = [n for n in names if n.lower() not in existing]
            if fresh:
                discovered[u or url] = fresh
    findings = arjun_findings(discovered)
    ctx.log("info", f"arjun: {len(findings)} hidden parameter(s) across {len(discovered)} URL(s)")
    return findings, discovered


# ---------------------------------------------------------------- jsluice (endpoints in JS)
MAX_JS_FILES = 20


def _parse_jsluice_urls(stdout: str) -> list[str]:
    """jsluice prints one JSON object per line. Keep only the 'url' field."""
    urls: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        u = obj.get("url") if isinstance(obj, dict) else None
        if u and isinstance(u, str):
            urls.append(u)
    return urls


def _resolve_js_url(found: str, js_url: str) -> str | None:
    """Resolve a URL jsluice extracted (often relative) against the JS file's own URL."""
    found = (found or "").strip()
    if not found or found.startswith(("data:", "javascript:", "mailto:", "#")):
        return None
    if found.startswith(("http://", "https://")):
        return found
    base = urlparse(js_url)
    if found.startswith("//"):
        return f"{base.scheme}:{found}"
    if found.startswith("/"):
        return f"{base.scheme}://{base.netloc}{found}"
    return None   # relative-to-path resolution is ambiguous without the real DOM base; skip it


def jsluice_scan(ctx: ScanContext, js_urls: list[str]) -> list[str]:
    """Pull endpoints out of JavaScript files. Argus fetches the JS itself (so scope and the
    rate limiter apply) and pipes the body to jsluice; nothing is ever executed.
    """
    bin_ = ctx.scanners_cfg.get("jsluice", "jsluice")
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "jsluice not installed — skipping JS endpoint extraction")
        return []
    targets = list(dict.fromkeys(u for u in js_urls if u.split("?")[0].endswith(".js")))[:MAX_JS_FILES]
    if not targets:
        return []
    delay = float(ctx.scanners_cfg.get("request_delay", 0.2))
    timeout = float(ctx.scanners_cfg.get("request_timeout", 10))
    found: set[str] = set()
    for js_url in targets:
        r = fetch(js_url, timeout=timeout, delay=delay, max_bytes=1_000_000)
        if r is None or not r.body:
            continue
        fd, tmp = tempfile.mkstemp(suffix=".js", prefix="argus_jsluice_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(r.body)
            code, so, se = run([bin_, "urls", tmp], timeout=30)
            for raw in _parse_jsluice_urls(so):
                resolved = _resolve_js_url(raw, js_url)
                if resolved:
                    found.add(resolved)
        except OSError:
            pass
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    if found:
        ctx.log("info", f"jsluice: {len(found)} endpoint(s) found in {len(targets)} JS file(s)")
    return sorted(found)
