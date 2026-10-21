"""Adapters for the remaining spec tools: Amass, OWASP ZAP (baseline),
OWASP Dependency-Check and SQLMap.

Safety defaults:
- ZAP runs passive rules plus a short spider through a local daemon, never the active scanner.
- SQLMap runs only when the asset has an explicit `allow_intrusive` flag, uses
  level 1 / risk 1 / techniques BEU, extracts no data, and tests at most 3 URLs.
- Every tool runs with an argument list (no shell), a timeout, and a private temp dir.
Parsers are pure functions so they can be unit-tested without the tools installed.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlparse

from ..scoring import guess_owasp, normalize_severity
from .base import Finding, ScanContext, run, tool_available
from .code_extra import _local_path

_TAG = re.compile(r"<[^>]+>")


def _text(s) -> str:
    return _TAG.sub("", str(s or "")).strip()


# ---------------------------------------------------------------- Amass (passive)
def amass_enum(ctx: ScanContext, root: str) -> list[str]:
    bin_ = ctx.scanners_cfg.get("amass", "amass")
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "amass not installed — skipping passive enumeration")
        return []
    ctx.log("info", f"amass: passive enumeration of {root}")
    _, out, _ = run([bin_, "enum", "-passive", "-silent", "-d", root], timeout=600)
    hosts = sorted({
        h for h in (line.strip().lower().rstrip(".") for line in out.splitlines())
        if h and (h == root or h.endswith("." + root))
    })
    ctx.log("info", f"amass: {len(hosts)} host(s)")
    return hosts


# ---------------------------------------------------------------- OWASP ZAP baseline
_ZAP_SEV = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_ZAP_CONF = {"3": "high", "2": "medium"}


def parse_zap(data: dict, fallback_host: str | None, fallback_url: str) -> list[Finding]:
    out: list[Finding] = []
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            if str(a.get("confidence", "")) == "0":   # ZAP's own "false positive" marker
                continue
            risk = str(a.get("riskcode", "0"))
            cweid = str(a.get("cweid", "") or "")
            cwe = f"CWE-{cweid}" if cweid.isdigit() and cweid != "0" else None
            instances = [i for i in (a.get("instances") or []) if isinstance(i, dict)]
            uri = (instances[0].get("uri") if instances else None) or fallback_url
            title = _text(a.get("name") or a.get("alert") or "ZAP alert")
            out.append(Finding(
                title=f"ZAP: {title}"[:140],
                severity=_ZAP_SEV.get(risk, "info"),
                owasp=guess_owasp(title, _text(a.get("desc"))),
                host=urlparse(uri).hostname or fallback_host,
                location=uri,
                source="zap",
                cwe=cwe,
                description=_text(a.get("desc"))[:1500],
                evidence=f"{len(instances)} instance(s) flagged by ZAP baseline",
                remediation=_text(a.get("solution"))[:1000] or "Review the ZAP alert and apply the recommended fix.",
                confidence=_ZAP_CONF.get(str(a.get("confidence", "")), "low"),
            ))
    return out


_ZAP_CONF_CODE = {"false positive": "0", "low": "1", "medium": "2", "high": "3", "confirmed": "4"}


def zap_alerts_to_report(alerts: list[dict]) -> dict:
    """Convert ZAP API alerts (core.alerts) into the JSON-report shape parse_zap reads.

    Alerts for the same rule, risk, confidence and CWE are grouped, with one instance per URL.
    Pure function: testable without a running ZAP.
    """
    grouped: dict[tuple, dict] = {}
    for a in alerts or []:
        name = str(a.get("alert") or a.get("name") or "ZAP alert")
        risk = str(a.get("riskcode", "0"))
        conf = _ZAP_CONF_CODE.get(str(a.get("confidence", "")).strip().lower(), "1")
        cweid = str(a.get("cweid", "") or "")
        item = grouped.setdefault((name, risk, conf, cweid), {
            "name": name, "riskcode": risk, "confidence": conf, "cweid": cweid,
            "desc": a.get("description", ""), "solution": a.get("solution", ""), "instances": [],
        })
        if a.get("url"):
            item["instances"].append({"uri": a["url"]})
    return {"site": [{"alerts": list(grouped.values())}]}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until(check, timeout: float, what: str) -> None:
    """Poll check() until it returns truthy. Errors from check count as 'not yet'."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if check():
                return
        except Exception:
            pass
        time.sleep(2)
    raise TimeoutError(what)


def zap_baseline(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    """Passive rules plus a short spider, driven through a local ZAP daemon.

    The active scanner is never started. The daemon listens on 127.0.0.1 only, with a
    random API key, and is shut down when the stage ends.
    Needs the `zaproxy` program and the `zapv2` Python module (see scripts/install-tools.sh).
    """
    binary = shutil.which("zaproxy")
    if not binary:
        ctx.log("warn", "OWASP ZAP not installed — skipping (run ./update.sh or: sudo apt install zaproxy)")
        return []
    try:
        from zapv2 import ZAPv2
    except ImportError:
        ctx.log("warn", "zapv2 module missing — skipping ZAP (sudo apt install python3-owasp-zap-v2.4)")
        return []
    targets = [u for u in urls if u][:3]
    if not targets:
        return []

    port, api_key = _free_port(), secrets.token_hex(16)
    home = tempfile.mkdtemp(prefix="argus_zap_")
    proxy = f"http://127.0.0.1:{port}"
    out: list[Finding] = []
    proc = None
    zap = None
    try:
        ctx.log("info", "zap: starting the ZAP daemon (the first start can take a minute)")
        proc = subprocess.Popen(
            [binary, "-daemon", "-host", "127.0.0.1", "-port", str(port),
             "-dir", home, "-config", f"api.key={api_key}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        zap = ZAPv2(apikey=api_key, proxies={"http": proxy, "https": proxy})
        ready_by = time.monotonic() + 180
        while True:                       # fail fast if the daemon process dies on start
            if proc.poll() is not None:
                raise RuntimeError("ZAP exited on start")
            try:
                zap.core.version()
                break
            except Exception:
                if time.monotonic() > ready_by:
                    raise TimeoutError("ZAP daemon start")
                time.sleep(2)

        for url in targets:
            parsed = urlparse(url)
            host = parsed.hostname
            origin = f"{parsed.scheme}://{parsed.netloc}"
            ctx.log("info", f"zap: passive rules + short spider on {host}")
            try:
                scan_id = zap.spider.scan(url, maxchildren=15)
                _wait_until(lambda: int(zap.spider.status(scan_id)) >= 100, 180, "spider")
                _wait_until(lambda: int(zap.pscan.records_to_scan()) == 0, 60, "passive scan")
                alerts = zap.core.alerts(baseurl=origin)
                out += parse_zap(zap_alerts_to_report(alerts), host, url)
            except TimeoutError as e:
                ctx.log("warn", f"zap: {host} did not finish in time ({e}); keeping what was found")
            except Exception as e:
                ctx.log("warn", f"zap: could not scan {host} ({type(e).__name__})")
    except Exception as e:
        ctx.log("warn", f"zap: daemon unavailable ({type(e).__name__}) — skipping ZAP")
    finally:
        if zap is not None:
            try:
                zap.core.shutdown()
            except Exception:
                pass
        if proc is not None:
            try:
                proc.wait(timeout=30)
            except Exception:
                proc.kill()
        shutil.rmtree(home, ignore_errors=True)
    ctx.log("info", f"zap: {len(out)} finding(s)")
    return out


# ---------------------------------------------------------------- OWASP Dependency-Check
def parse_depcheck(data: dict) -> list[Finding]:
    out: list[Finding] = []
    for dep in data.get("dependencies", []) or []:
        fname = dep.get("fileName") or dep.get("filePath") or "dependency"
        for v in dep.get("vulnerabilities", []) or []:
            name = str(v.get("name", "vulnerability"))
            score = (v.get("cvssv3") or {}).get("baseScore") or (v.get("cvssv2") or {}).get("score")
            cwes = [str(c) for c in (v.get("cwes") or [])]
            out.append(Finding(
                title=f"{fname}: {name}"[:140],
                severity=normalize_severity(v.get("severity")),
                cvss=float(score) if score else None,
                owasp="A06",
                location=fname,
                source="dependency-check",
                cve=name if name.startswith("CVE-") else None,
                cwe=", ".join(cwes) or None,
                description=_text(v.get("description"))[:1500],
                evidence=f"vulnerable component: {fname}",
                remediation="Upgrade the affected component to a patched version.",
                confidence="high",
            ))
    return out


def dependency_check(ctx: ScanContext) -> list[Finding]:
    path = _local_path(ctx)
    if not path:
        return []
    bin_ = ctx.scanners_cfg.get("dependency_check", "dependency-check")
    if not tool_available(bin_):
        ctx.log("warn", "dependency-check not installed — skipping (OWASP Dependency-Check)")
        return []
    tmp = tempfile.mkdtemp(prefix="argus_depcheck_")
    cmd = [bin_, "--project", "argus-scan", "--scan", path, "--format", "JSON", "--out", tmp]
    if ctx.scanners_cfg.get("depcheck_noupdate"):
        cmd.append("--noupdate")
    ctx.log("info", f"dependency-check: scanning {path}")
    try:
        run(cmd, timeout=1800)
        with open(os.path.join(tmp, "dependency-check-report.json"), encoding="utf-8") as fh:
            findings = parse_depcheck(json.load(fh))
    except (OSError, ValueError) as e:
        ctx.log("warn", f"dependency-check: no report produced ({type(e).__name__})")
        findings = []
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ctx.log("info", f"dependency-check: {len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------- SQLMap (gated)
_SQLI_PARAM = re.compile(r"Parameter: (\S+) \((\w+)\)")


def parse_sqlmap(stdout: str, url: str) -> list[Finding]:
    low = stdout.lower()
    if "is vulnerable" not in low and "identified the following injection point" not in low:
        return []
    params = sorted({p for p, _ in _SQLI_PARAM.findall(stdout)}) or ["unknown"]
    return [Finding(
        title="SQL injection candidate (sqlmap confirmed an injectable parameter)",
        severity="high",
        owasp="A03",
        cwe="CWE-89",
        host=urlparse(url).hostname,
        location=url,
        source="sqlmap",
        description=(f"sqlmap reports injectable parameter(s): {', '.join(params)}. "
                     "Verify manually. No data was extracted."),
        evidence=f"Parameters: {', '.join(params)}",
        remediation="Use parameterized queries or prepared statements and validate input on the server.",
        confidence="high",
    )]


def sqlmap(ctx: ScanContext, urls: list[str], allow_intrusive: bool) -> list[Finding]:
    if not allow_intrusive:
        ctx.log("warn", "sqlmap: skipped, intrusive modules are not enabled for this target")
        return []
    bin_ = ctx.scanners_cfg.get("sqlmap", "sqlmap")
    if not tool_available(bin_):
        ctx.log("warn", "sqlmap not installed — skipping SQL injection checks")
        return []
    out: list[Finding] = []
    for url in [u for u in urls if "?" in u and "=" in u][:3]:
        tmp = tempfile.mkdtemp(prefix="argus_sqlmap_")
        ctx.log("info", f"sqlmap: low-risk check (level 1, risk 1) on {urlparse(url).hostname}")
        try:
            _, so, _ = run([bin_, "-u", url, "--batch", "--level", "1", "--risk", "1",
                            "--technique", "BEU", "--smart", "--timeout", "10", "--retries", "1",
                            "--random-agent", "--disable-coloring", "--flush-session",
                            "--output-dir", tmp], timeout=600)
            out += parse_sqlmap(so, url)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    ctx.log("info", f"sqlmap: {len(out)} finding(s)")
    return out
