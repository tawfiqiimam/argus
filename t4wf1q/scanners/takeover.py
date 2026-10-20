"""Subdomain takeover detection.

A subdomain is a *candidate* for takeover when:
  (a) its CNAME points at a third-party service AND that service shows its
      "unclaimed resource" page, and/or
  (b) the CNAME target no longer resolves (NXDOMAIN) — someone could register it.

Confidence: high = both signals, medium = one strong signal, low = NXDOMAIN only.
Every result is marked for manual verification. A scanner signal is never
treated as a confirmed takeover.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..scope import ScopeGuard
from .base import Finding, ScanContext, run, tool_available
from .netutil import Resp, fetch

try:  # dnspython is preferred; `dig` is the fallback
    import dns.resolver as _dnsres  # type: ignore
except ImportError:  # pragma: no cover - depends on environment
    _dnsres = None

# (provider, CNAME suffixes, CNAME substrings, unclaimed-page signatures)
# Signatures are lower-case and matched against the lower-cased body.
PROVIDERS: list[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = [
    ("GitHub Pages", (".github.io",), (), ("there isn't a github pages site here",)),
    ("Heroku", (".herokuapp.com", ".herokudns.com"), (), ("no such app",)),
    ("AWS S3", (".s3.amazonaws.com",), (".s3-website",),
     ("nosuchbucket", "the specified bucket does not exist")),
    ("Azure", (".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"), (),
     ("404 web site not found", "error 404 - web app not found")),
    ("Shopify", (".myshopify.com",), (), ("sorry, this shop is currently unavailable",)),
    ("Fastly", (".fastly.net", ".fastlylb.net"), (), ("fastly error: unknown domain",)),
    ("Pantheon", (".pantheonsite.io",), (), ("404 error unknown site!",)),
    ("Ghost", (".ghost.io",), (), ("the thing you were looking for is no longer here",)),
    ("Surge.sh", (".surge.sh",), (), ("project not found",)),
    ("Bitbucket", (".bitbucket.io",), (), ("repository not found",)),
    ("Tumblr", (".tumblr.com",), (),
     ("whatever you were looking for doesn't currently exist at this address",)),
    ("Webflow", (".webflow.io",), (),
     ("the page you are looking for doesn't exist or has been moved",)),
    ("Helpscout", (".helpscoutdocs.com",), (), ("no settings were found for this company",)),
    ("Zendesk", (".zendesk.com",), (), ("help center closed",)),
    ("Vercel", (".vercel.app",), (), ("the deployment could not be found",)),
    ("Netlify", (".netlify.app",), (), ("not found - request id",)),
]

Resolver = Callable[[str], Optional[str]]
Exists = Callable[[str], Optional[bool]]
Fetcher = Callable[[str], Optional[Resp]]


def classify(target: str):
    """Return the matching PROVIDERS entry for a CNAME target, or None."""
    t = target.lower().rstrip(".")
    for entry in PROVIDERS:
        _, suffixes, contains, _ = entry
        if any(t.endswith(s) for s in suffixes) or any(c in t for c in contains):
            return entry
    return None


def check_host(host: str, *, resolve_cname: Resolver, name_exists: Exists,
               fetch_fn: Fetcher) -> Optional[Finding]:
    """Evaluate one host. Dependencies are injected so the logic is testable."""
    cname = resolve_cname(host)
    if not cname:
        return None
    target = cname.lower().rstrip(".")
    prov = classify(target)
    dangling = name_exists(target) is False  # only a definite NXDOMAIN counts
    if not prov and not dangling:
        return None

    body_hit = False
    if prov:
        resp = fetch_fn(f"https://{host}/") or fetch_fn(f"http://{host}/")
        if resp is not None:
            low = resp.body.lower()
            body_hit = any(sig in low for sig in prov[3])
    if not (dangling or body_hit):
        return None  # a live third-party CNAME is not a takeover

    if dangling and body_hit:
        confidence = "high"
    elif dangling or body_hit:
        confidence = "medium" if body_hit else "low"
    provider = prov[0] if prov else "unknown provider"
    return Finding(
        title=f"Subdomain takeover candidate: {host}",
        severity="high",
        owasp="A05",
        host=host,
        location=f"https://{host}",
        source="argus-takeover",
        description=(
            f"{host} is a CNAME to {target} ({provider}). "
            f"{'The CNAME target does not resolve (NXDOMAIN). ' if dangling else ''}"
            f"{'The response shows the provider unclaimed-resource page. ' if body_hit else ''}"
            "If the resource can be claimed by a third party, they could serve content "
            "under this subdomain. Status: UNVERIFIED candidate, manual verification required."
        ),
        evidence=(f"CNAME {host} -> {target} | provider={provider} | "
                  f"NXDOMAIN={dangling} | unclaimed-signature={'matched' if body_hit else 'not matched'}"),
        remediation=("Remove the dangling DNS record, or reclaim the resource on the provider. "
                     "Confirm ownership first; do not claim third-party resources without authorization."),
        confidence=confidence,
    )


# ---------------------------------------------------------------- DNS helpers
def dns_cname(host: str, timeout: float = 5) -> Optional[str]:
    if _dnsres is not None:
        try:
            ans = _dnsres.resolve(host, "CNAME", lifetime=timeout)
            return str(ans[0].target).rstrip(".")
        except Exception:
            return None
    _, out, _ = run(["dig", "+short", "+time=5", "+tries=1", "CNAME", host], timeout=int(timeout) + 5)
    for line in out.splitlines():
        line = line.strip()
        if line.endswith("."):
            return line.rstrip(".")
    return None


def dns_name_exists(name: str, timeout: float = 5) -> Optional[bool]:
    """True = resolves, False = NXDOMAIN, None = inconclusive."""
    if _dnsres is not None:
        try:
            _dnsres.resolve(name, "A", lifetime=timeout)
            return True
        except _dnsres.NXDOMAIN:
            return False
        except Exception:
            return None
    _, out, _ = run(["dig", "+noall", "+comments", "+time=5", "+tries=1", "A", name],
                    timeout=int(timeout) + 5)
    if "status: NXDOMAIN" in out:
        return False
    if "status: NOERROR" in out:
        return True
    return None


def scan(ctx: ScanContext, hosts: list[str], guard: ScopeGuard | None = None) -> list[Finding]:
    guard = guard or ScopeGuard.from_db()
    delay = float(ctx.scanners_cfg.get("request_delay", 0.2))
    timeout = float(ctx.scanners_cfg.get("request_timeout", 10))
    out: list[Finding] = []

    if _dnsres is None and not tool_available("dig"):
        ctx.log("warn", "takeover: neither dnspython nor dig available — DNS checks skipped "
                        "(pip install dnspython)")
        return out

    def fetch_fn(url: str) -> Optional[Resp]:
        ok, _ = guard.check(url)
        return fetch(url, timeout=timeout, delay=delay) if ok else None

    ctx.log("info", f"takeover: checking CNAME chains for {len(hosts)} host(s)")
    for host in dict.fromkeys(hosts):
        ok, _ = guard.check(host)
        if not ok:
            continue
        try:
            f = check_host(
                host,
                resolve_cname=lambda h: dns_cname(h, timeout),
                name_exists=lambda n: dns_name_exists(n, timeout),
                fetch_fn=fetch_fn,
            )
        except Exception as e:
            ctx.log("warn", f"takeover: {host} check failed: {type(e).__name__}")
            continue
        if f:
            out.append(f)
            ctx.log("warn", f"takeover candidate: {host} ({f.confidence} confidence)")
    ctx.log("info", f"takeover: {len(out)} candidate(s)")
    return out
