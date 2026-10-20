"""Extra recon adapters: whatweb (fingerprint), katana + gau (URL discovery).

These enrich the attack surface. katana/gau feed parameterized URLs to the
active scanners (e.g. dalfox). All degrade gracefully when absent.
"""
from __future__ import annotations

import subprocess
from urllib.parse import urlparse

from .base import ScanContext, run, tool_available


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
