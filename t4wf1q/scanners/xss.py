"""Built-in reflected-XSS candidate detector (canary reflection analysis).

For each query parameter we send one random marker containing HTML-significant
characters. If the marker comes back with '<' or '"' still unencoded in an HTML
response, the parameter is a candidate for reflected XSS.

Safety properties:
- No payload that executes is sent; the marker is random per request.
- Nothing is stored; only the parameter name and a yes/no survival check are kept.
- Candidates are NOT confirmed. dalfox (when installed) does payload-level checks.
"""
from __future__ import annotations

import secrets
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..scope import ScopeGuard
from .base import Finding, ScanContext
from .netutil import fetch

MAX_URLS = 30
MAX_PARAMS = 5


def probe_url(url: str, *, delay: float = 0.0, timeout: float = 10.0) -> list[Finding]:
    p = urlparse(url)
    qs = parse_qsl(p.query, keep_blank_values=True)
    if not qs or not p.hostname:
        return []
    base = urlunparse(p._replace(query="", fragment=""))
    out: list[Finding] = []

    for i, (name, _) in enumerate(qs[:MAX_PARAMS]):
        marker = "argus" + secrets.token_hex(4)
        probe_value = f"{marker}\"'<{marker}>"
        mutated = list(qs)
        mutated[i] = (name, probe_value)
        test_url = urlunparse(p._replace(query=urlencode(mutated), fragment=""))

        r = fetch(test_url, timeout=timeout, delay=delay)
        if r is None or "html" not in r.ctype:
            continue
        tag_survived = f"<{marker}>" in r.body
        quote_survived = f"\"{marker}" in r.body
        if not (tag_survived or quote_survived):
            continue  # absent or HTML-encoded: not a candidate

        out.append(Finding(
            title=f"Potential reflected XSS in parameter '{name}'",
            severity="medium",
            owasp="A03",
            cwe="CWE-79",
            host=p.hostname,
            location=f"{base}?{name}=",
            source="argus-xss",
            description=(
                "A unique marker sent in this parameter was echoed back with HTML-significant "
                "characters unencoded. Depending on the output context this can allow script "
                "injection. Candidate only: confirm in a browser or with dalfox before reporting."
            ),
            evidence=(f"'<' survived={tag_survived}, '\"' survived={quote_survived} "
                      f"(marker reflected in HTML response)"),
            remediation=("Apply context-aware output encoding (HTML, attribute, JavaScript) and "
                         "validate input. Add a strict Content-Security-Policy."),
            confidence="medium",
        ))
    return out


def scan(ctx: ScanContext, urls: list[str], guard: ScopeGuard | None = None) -> list[Finding]:
    guard = guard or ScopeGuard.from_db()
    delay = float(ctx.scanners_cfg.get("request_delay", 0.2))
    timeout = float(ctx.scanners_cfg.get("request_timeout", 10))
    conc = max(1, min(int(ctx.scanners_cfg.get("concurrency", 5)), 8))

    seen: set = set()
    targets: list[str] = []
    for u in urls:
        p = urlparse(u)
        if not p.query or not p.hostname:
            continue
        key = (p.hostname, p.path, tuple(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True))))
        if key in seen:
            continue
        ok, _ = guard.check(u)
        if not ok:
            continue
        seen.add(key)
        targets.append(u)
        if len(targets) >= MAX_URLS:
            break

    if not targets:
        ctx.log("info", "xss: no parameterized in-scope URLs to test")
        return []

    ctx.log("info", f"xss: probing {len(targets)} parameterized URL(s) (canary reflection)")
    out: list[Finding] = []
    with ThreadPoolExecutor(max_workers=conc) as ex:
        for res in ex.map(lambda u: probe_url(u, delay=delay, timeout=timeout), targets):
            out.extend(res)
    ctx.log("info", f"xss: {len(out)} candidate(s)")
    return out
