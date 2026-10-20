"""Hidden path and sensitive-file discovery.

Probes a curated list of paths that commonly leak source code, secrets, backups,
debug output or admin panels, plus Disallow entries from robots.txt.

False-positive controls:
  * soft-404 detection: a random path is requested first; a 200 response that
    looks like the generic error page is discarded;
  * content validators: a path is reported only when its body matches a known
    signature (e.g. /.git/HEAD must start with 'ref:');
  * redaction: response bodies are never stored or logged, only status and size.
"""
from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, NamedTuple, Optional
from urllib.parse import urljoin, urlparse

from ..scope import ScopeGuard
from .base import Finding, ScanContext
from .netutil import Resp, fetch

MAX_BASES = 20
MAX_ROBOTS = 15


def _not_html(r: Resp) -> bool:
    head = r.body[:600].lower()
    return "<html" not in head and "<!doctype" not in head


def _low(r: Resp) -> str:
    return r.body.lower()


def _sql_dump(r: Resp) -> bool:
    return _not_html(r) and ("create table" in _low(r) or "insert into" in _low(r))


def _openapi(r: Resp) -> bool:
    return _not_html(r) and ('"swagger"' in r.body or '"openapi"' in r.body)


class Check(NamedTuple):
    path: str
    category: str
    severity: str
    owasp: str
    title: str
    validator: Callable[[Resp], bool]


CHECKS: list[Check] = [
    # --- version control metadata
    Check("/.git/HEAD", "vcs", "high", "A05", "Exposed .git repository",
          lambda r: r.body.lstrip().startswith("ref:")),
    Check("/.svn/entries", "vcs", "high", "A05", "Exposed .svn metadata",
          lambda r: _not_html(r) and len(r.body) > 0),
    # --- secrets & config
    Check("/.env", "secrets", "high", "A05", "Exposed .env file",
          lambda r: _not_html(r) and "=" in r.body),
    Check("/config.json", "config", "medium", "A05", "Config file exposed",
          lambda r: _not_html(r) and r.body.lstrip().startswith("{")),
    Check("/web.config", "config", "medium", "A05", "web.config exposed",
          lambda r: "<configuration" in _low(r)),
    Check("/.htaccess", "config", "medium", "A05", ".htaccess exposed",
          lambda r: _not_html(r) and any(k in _low(r) for k in ("rewriterule", "deny from", "authtype"))),
    Check("/crossdomain.xml", "config", "medium", "A05", "Permissive crossdomain.xml",
          lambda r: "cross-domain-policy" in _low(r) and 'domain="*"' in r.body),
    # --- backups & dumps
    Check("/backup.zip", "backup", "high", "A05", "Backup archive exposed",
          lambda r: _not_html(r) and r.body[:2] == "PK" and r.length > 1000),
    Check("/backup.sql", "backup", "high", "A05", "SQL backup exposed", _sql_dump),
    Check("/db.sql", "backup", "high", "A05", "SQL database dump exposed", _sql_dump),
    Check("/dump.sql", "backup", "high", "A05", "SQL database dump exposed", _sql_dump),
    Check("/.DS_Store", "info", "low", "A05", ".DS_Store exposed (directory listing leak)",
          lambda r: "Bud1" in r.body[:16]),
    # --- debug & diagnostics
    Check("/phpinfo.php", "debug", "medium", "A05", "phpinfo() page exposed",
          lambda r: "phpinfo()" in r.body or "PHP Version" in r.body),
    Check("/server-status", "debug", "medium", "A05", "Apache server-status exposed",
          lambda r: "Apache Server Status" in r.body),
    Check("/elmah.axd", "debug", "medium", "A05", "ELMAH error log exposed",
          lambda r: "Error Log for" in r.body or "ELMAH" in r.body),
    Check("/trace.axd", "debug", "medium", "A05", "ASP.NET trace page exposed",
          lambda r: "Application Trace" in r.body or "Request Details" in r.body),
    # --- APIs & documentation
    Check("/swagger.json", "api", "low", "A05", "OpenAPI/Swagger schema exposed", _openapi),
    Check("/openapi.json", "api", "low", "A05", "OpenAPI schema exposed", _openapi),
    Check("/v2/api-docs", "api", "low", "A05", "Swagger v2 API docs exposed", _openapi),
    Check("/actuator", "api", "medium", "A05", "Spring Boot actuator index exposed",
          lambda r: '"_links"' in r.body and "actuator" in _low(r)),
    Check("/actuator/env", "api", "high", "A05", "Spring Boot /actuator/env exposed (may leak secrets)",
          lambda r: "propertySources" in r.body),
    Check("/graphql", "api", "info", "A05", "GraphQL endpoint reachable",
          lambda r: "graphql" in _low(r) and "query" in _low(r)),
    # --- dev artifacts
    Check("/composer.json", "dev", "low", "A05", "composer.json exposed",
          lambda r: _not_html(r) and '"require"' in r.body),
    Check("/package.json", "dev", "low", "A05", "package.json exposed",
          lambda r: _not_html(r) and ('"dependencies"' in r.body or '"scripts"' in r.body)),
    # --- admin surfaces (401/403 also counts: the resource exists)
    Check("/phpmyadmin/", "admin", "medium", "A05", "phpMyAdmin login exposed",
          lambda r: "phpmyadmin" in _low(r)),
    Check("/adminer.php", "admin", "high", "A05", "Adminer database tool exposed",
          lambda r: "adminer" in _low(r)),
    Check("/admin/", "admin", "info", "A01", "Admin login form present",
          lambda r: 'type="password"' in _low(r)),
    Check("/administrator/", "admin", "info", "A01", "Admin login form present",
          lambda r: 'type="password"' in _low(r)),
    # --- WordPress
    Check("/xmlrpc.php", "wp", "low", "A05", "WordPress XML-RPC endpoint enabled",
          lambda r: "XML-RPC server accepts POST" in r.body),
    Check("/wp-content/debug.log", "wp", "high", "A05", "WordPress debug.log exposed",
          lambda r: "Warning:" in r.body or "Notice:" in r.body or "PHP " in r.body),
    Check("/readme.html", "wp", "info", "A05", "WordPress readme exposes version",
          lambda r: "WordPress" in r.body),
    Check("/wp-json/wp/v2/users", "wp", "medium", "A01", "WordPress user enumeration via REST API",
          lambda r: r.body.lstrip().startswith("[") and '"slug"' in r.body),
]

REMEDIATION = {
    "vcs": "Block dot-directories at the web server and never deploy VCS metadata.",
    "secrets": "Remove the file from the web root and rotate every exposed credential.",
    "config": "Block direct access to configuration files; move them outside the web root.",
    "backup": "Remove backup artifacts from the web root; store backups outside it.",
    "debug": "Disable debug and diagnostic endpoints in production.",
    "api": "Restrict API documentation and management endpoints to authenticated internal users.",
    "admin": "Restrict admin interfaces by IP or VPN and enforce strong authentication with MFA.",
    "dev": "Do not deploy dependency manifests into production web roots.",
    "wp": "Harden WordPress: disable XML-RPC if unused, remove debug logs, restrict user enumeration.",
    "robots": "Confirm the disallowed path is not sensitive. robots.txt is not an access control.",
    "info": "Review whether this artifact should be publicly reachable.",
}


def _soft_404(r: Resp, baseline: Optional[Resp]) -> bool:
    """True when a 200 response is indistinguishable from the generic not-found page."""
    if baseline is None or baseline.status != 200 or r.status != 200:
        return False
    # A different content type (e.g. a text .env against an HTML error page) is
    # never the generic not-found page, whatever its length.
    if ("html" in baseline.ctype) != ("html" in r.ctype):
        return False
    tol = max(20, int(0.05 * baseline.length))
    return abs(r.length - baseline.length) <= tol


def _robots_paths(base: str, timeout: float, delay: float) -> list[str]:
    r = fetch(base + "/robots.txt", timeout=timeout, delay=delay)
    if r is None or r.status != 200:
        return []
    paths: list[str] = []
    for line in r.body.splitlines():
        if not line.lower().startswith("disallow:"):
            continue
        p = line.split(":", 1)[1].strip()
        if p.startswith("/") and p != "/" and "*" not in p and "$" not in p:
            paths.append(p)
        if len(paths) >= MAX_ROBOTS:
            break
    return paths


def _make(base: str, url: str, title: str, sev: str, owasp: str, cat: str,
          r: Resp, validated: bool, note: str = "") -> Finding:
    return Finding(
        title=title,
        severity=sev,
        owasp=owasp,
        host=urlparse(base).hostname,
        location=url,
        source="argus-paths",
        description=f"{title}. Category: {cat}. {note}".strip(),
        evidence=f"HTTP {r.status}, {r.length} bytes (body redacted)",
        remediation=REMEDIATION.get(cat, "Restrict access to this path."),
        confidence="high" if validated else "medium",
    )


def _probe(base: str, chk: Check, baseline: Optional[Resp], timeout: float, delay: float) -> Optional[Finding]:
    url = urljoin(base + "/", chk.path)
    r = fetch(url, timeout=timeout, delay=delay)
    if r is None:
        return None
    if chk.category == "admin" and r.status in (401, 403):
        return _make(base, url, f"Restricted admin surface present: {chk.path}", "info",
                     chk.owasp, chk.category, r, False, "Access is restricted, but the resource exists.")
    if r.status != 200 or _soft_404(r, baseline):
        return None
    if not chk.validator(r):
        return None
    return _make(base, url, chk.title, chk.severity, chk.owasp, chk.category, r, True)


def scan(ctx: ScanContext, base_urls: list[str], categories: set | None = None,
         guard: ScopeGuard | None = None) -> list[Finding]:
    """Run path discovery against each in-scope origin. `categories=None` means all."""
    guard = guard or ScopeGuard.from_db()
    delay = float(ctx.scanners_cfg.get("request_delay", 0.2))
    timeout = float(ctx.scanners_cfg.get("request_timeout", 10))
    conc = max(1, min(int(ctx.scanners_cfg.get("concurrency", 5)), 8))

    bases: list[str] = []
    for u in base_urls:
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            continue
        b = f"{p.scheme}://{p.netloc}"
        if b in bases:
            continue
        ok, _ = guard.check(b)
        if ok:
            bases.append(b)
        if len(bases) >= MAX_BASES:
            break
    if not bases:
        ctx.log("info", "paths: no in-scope http(s) origins to test")
        return []

    out: list[Finding] = []
    for base in bases:
        baseline = fetch(urljoin(base + "/", f"argus-{secrets.token_hex(6)}"),
                         timeout=timeout, delay=delay)
        checks = [c for c in CHECKS if categories is None or c.category in categories]
        if categories is None or "robots" in categories:
            for rp in _robots_paths(base, timeout, delay):
                checks.append(Check(rp, "robots", "info", "A05",
                                    f"Path disclosed in robots.txt: {rp}", lambda r: True))
        ctx.log("info", f"paths: {len(checks)} check(s) on {base}")
        with ThreadPoolExecutor(max_workers=conc) as ex:
            for f in ex.map(lambda c: _probe(base, c, baseline, timeout, delay), checks):
                if f:
                    out.append(f)
    ctx.log("info", f"paths: {len(out)} finding(s)")
    return out
