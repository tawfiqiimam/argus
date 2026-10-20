"""Recon: subdomain enumeration (subfinder) + liveness/tech probe (httpx).

This is the bug-bounty entry point: give it a root domain and it discovers the
attack surface, then filters every discovered host back through the scope guard
so only authorized subdomains move forward.
"""
from __future__ import annotations

import json

from .base import ScanContext, run, tool_available


def enumerate_subdomains(ctx: ScanContext, root: str) -> list[str]:
    cfg = ctx.scanners_cfg
    bin_ = cfg.get("subfinder", "subfinder")
    found: set[str] = {root}

    if bin_ and tool_available(bin_):
        ctx.log("info", f"subfinder: enumerating subdomains of {root}")
        code, out, err = run([bin_, "-silent", "-d", root], timeout=300)
        if code == 0:
            for line in out.splitlines():
                h = line.strip().lower()
                if h:
                    found.add(h)
            ctx.log("info", f"subfinder: {len(found)} host(s) discovered")
        else:
            ctx.log("warn", f"subfinder exited {code}: {err.strip()[:160]}")
    else:
        ctx.log("warn", "subfinder not installed — using root host only "
                        "(install: go install .../subfinder@latest)")
    return sorted(found)


def probe_hosts(ctx: ScanContext, hosts: list[str]) -> list[dict]:
    """Return live-host records: [{host,url,status,title,tech[]}]."""
    cfg = ctx.scanners_cfg
    bin_ = cfg.get("httpx", "httpx")
    results: list[dict] = []

    if bin_ and tool_available(bin_):
        ctx.log("info", f"httpx: probing {len(hosts)} host(s) for liveness + tech")
        stdin = "\n".join(hosts)
        import subprocess
        try:
            p = subprocess.run(
                [bin_, "-silent", "-json", "-title", "-tech-detect", "-status-code"],
                input=stdin, capture_output=True, text=True, timeout=300, check=False,
            )
            for line in p.stdout.splitlines():
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                results.append({
                    "host": j.get("host") or j.get("input"),
                    "url": j.get("url") or j.get("input"),
                    "status": j.get("status_code") or j.get("status-code"),
                    "title": j.get("title"),
                    "tech": j.get("tech") or j.get("technologies") or [],
                })
        except Exception as e:  # pragma: no cover
            ctx.log("warn", f"httpx failed: {e}")
    else:
        ctx.log("warn", "httpx not installed — assuming hosts are live over https")
        for h in hosts:
            results.append({"host": h, "url": f"https://{h}", "status": None,
                            "title": None, "tech": []})

    ctx.log("info", f"httpx: {len([r for r in results if r])} responsive endpoint(s)")
    return results
