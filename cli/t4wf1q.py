#!/usr/bin/env python3
"""T4WF1Q VMS — command line interface.

A thin, pretty client over the REST API. Works against a local server or a
remote one (e.g. your domain behind a Cloudflare tunnel).

    ./cli/t4wf1q.py login --server http://127.0.0.1:8000 --key <API_KEY>
    ./cli/t4wf1q.py scan https://juice-shop.local --profile owasp-full
    ./cli/t4wf1q.py findings --severity critical
    ./cli/t4wf1q.py report --asset <id>
    ./cli/t4wf1q.py watch                # live tail of the scan console
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

app = typer.Typer(add_completion=False, help="T4WF1Q Vulnerability Management System CLI")
console = Console()

CFG = Path.home() / ".config" / "t4wf1q" / "cli.json"
SEV_COLOR = {"critical": "red", "high": "dark_orange", "medium": "yellow",
             "low": "blue", "info": "grey50"}

BANNER = Text("""
 ████████╗██╗  ██╗██╗    ██╗███████╗ ██╗ ██████╗
 ╚══██╔══╝██║  ██║██║    ██║██╔════╝███║██╔═══██╗
    ██║   ███████║██║ █╗ ██║█████╗  ╚██║██║   ██║
    ██║   ╚════██║██║███╗██║██╔══╝   ██║██║▄▄ ██║
    ██║        ██║╚███╔███╔╝██║      ██║╚██████╔╝
    ╚═╝        ╚═╝ ╚══╝╚══╝ ╚═╝      ╚═╝ ╚══▀▀═╝ VMS""", style="bold magenta")


def _load() -> dict:
    if CFG.exists():
        return json.loads(CFG.read_text())
    return {}


def _save(d: dict) -> None:
    CFG.parent.mkdir(parents=True, exist_ok=True)
    CFG.write_text(json.dumps(d, indent=2))


def _client() -> tuple[httpx.Client, str]:
    c = _load()
    server = c.get("server") or os.environ.get("T4WF1Q_SERVER", "http://127.0.0.1:8000")
    key = c.get("key") or os.environ.get("T4WF1Q_API_KEY", "")
    if not key:
        console.print("[red]Not logged in.[/] Run:  t4wf1q login --key <API_KEY>")
        raise typer.Exit(1)
    return httpx.Client(base_url=server, headers={"x-api-key": key}, timeout=30, verify=False), server


def _get(path, **kw):
    cl, _ = _client()
    r = cl.get(path, **kw)
    r.raise_for_status()
    return r.json()


def _post(path, body=None):
    cl, _ = _client()
    r = cl.post(path, json=body or {})
    r.raise_for_status()
    return r.json()


@app.command()
def login(server: str = typer.Option("http://127.0.0.1:8000"), key: str = typer.Option(...)):
    """Save server URL + API key."""
    try:
        r = httpx.get(f"{server}/api/stats", headers={"x-api-key": key}, timeout=15, verify=False)
        r.raise_for_status()
    except Exception as e:
        console.print(f"[red]Connection failed:[/] {e}")
        raise typer.Exit(1)
    _save({"server": server, "key": key})
    console.print(BANNER)
    console.print(f"[green]✓ Connected[/] to {server}")


@app.command()
def scope(action: str = typer.Argument("list", help="list | check"),
          target: str = typer.Argument(None)):
    """View scope or check whether a target is in scope."""
    if action == "list":
        s = _get("/api/scope")
        console.print(Panel(
            f"[bold]enforce:[/] {s['enforce']}\n[bold]allow:[/] {', '.join(s['allow']) or '—'}\n"
            f"[bold]deny:[/] {', '.join(s['deny']) or '—'}", title="Scope"))
    elif action == "check" and target:
        r = _post("/api/scope/check", {"pattern": target})
        color = "green" if r["allowed"] else "red"
        console.print(f"[{color}]{'IN SCOPE' if r['allowed'] else 'OUT OF SCOPE'}[/] "
                      f"{r['host']} — {r['reason']}")
    else:
        console.print("usage: t4wf1q scope [list|check <target>]")


@app.command()
def assets():
    """List assets."""
    data = _get("/api/assets")
    t = Table(title="Assets", header_style="bold magenta")
    for col in ("ID", "Name", "Target", "Risk", "Crit", "High", "Med", "Low"):
        t.add_column(col)
    for a in data:
        c = a["counts"]
        t.add_row(a["id"], a["name"], a["target"], str(a["risk"]),
                  str(c["critical"]), str(c["high"]), str(c["medium"]), str(c["low"]))
    console.print(t)


@app.command()
def scan(target: str, profile: str = typer.Option("owasp-full"),
         name: str = typer.Option(None), kind: str = typer.Option("web")):
    """Add a target (if new) and launch a scan."""
    cl, server = _client()
    r = cl.post("/api/assets", json={"target": target, "name": name, "kind": kind})
    if r.status_code >= 400:
        console.print(f"[red]{r.json().get('detail', r.text)}[/]")
        raise typer.Exit(1)
    asset = r.json()
    s = cl.post(f"/api/assets/{asset['id']}/scan", json={"profile": profile}).json()
    console.print(BANNER)
    console.print(f"[green]✓ Scan queued[/] · asset [cyan]{asset['id']}[/] · profile [yellow]{profile}[/]")
    console.print(f"  Live console:  [blue]{server}[/]  →  Live Scan")
    console.print(f"  Tail here:     t4wf1q watch --scan {s['id']}")


@app.command()
def findings(severity: str = typer.Option(None), status: str = typer.Option(None),
             owasp: str = typer.Option(None), asset: str = typer.Option(None)):
    """List findings with optional filters."""
    q = {k: v for k, v in dict(severity=severity, status=status, owasp=owasp, asset_id=asset).items() if v}
    data = _get("/api/findings", params=q)
    t = Table(title=f"Findings ({len(data)})", header_style="bold magenta")
    for col in ("Severity", "Title", "OWASP", "Location", "Status"):
        t.add_column(col, overflow="fold")
    for f in data:
        sev = f["severity"]
        t.add_row(f"[{SEV_COLOR.get(sev,'white')}]{sev.upper()}[/]",
                  f["title"], f.get("owasp") or "-",
                  (f.get("location") or f.get("host") or "-")[:48], f["status"])
    console.print(t)


@app.command()
def report(asset: str = typer.Option(..., help="asset id")):
    """Generate a report for an asset."""
    r = _post(f"/api/assets/{asset}/report")
    console.print(f"[green]✓ Report:[/] {r['path']}")


@app.command()
def watch(scan: str = typer.Option(None, help="scan id (defaults to newest)")):
    """Live-tail a scan's console via WebSocket."""
    import asyncio
    try:
        import websockets  # type: ignore
    except ImportError:
        console.print("[yellow]pip install websockets[/] to use live watch.")
        raise typer.Exit(1)
    c = _load()
    server = c.get("server", "http://127.0.0.1:8000")
    key = c.get("key", "")
    ws_url = server.replace("http", "ws", 1) + f"/ws?key={key}"

    async def run():
        async with websockets.connect(ws_url) as ws:
            console.print(BANNER)
            console.print("[grey50]live — Ctrl+C to stop[/]\n")
            async for raw in ws:
                ev = json.loads(raw)
                if scan and ev.get("scan_id") and ev["scan_id"] != scan:
                    continue
                if ev["kind"] == "log":
                    console.print(f"[grey50]·[/] {ev['message']}")
                elif ev["kind"] == "finding":
                    sev = ev["severity"]
                    console.print(f"[{SEV_COLOR.get(sev,'white')}]◆ {sev.upper()}[/] {ev['title']} "
                                  f"[grey50]{ev.get('location','')}[/]")
                elif ev["kind"] == "scan_update" and ev.get("status") == "done":
                    console.print("[green]✓ scan complete[/]")
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    app()
