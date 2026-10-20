"""Auto report generation: self-contained HTML, optional PDF via WeasyPrint."""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import db
from .config import Config
from .scoring import risk_score, OWASP_TOP10
from .checklist import coverage

_TEMPLATES = Path(__file__).resolve().parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(["html", "xml"]),
)


def generate(cfg: Config, asset_id: str, scan_id: str | None = None) -> Path | None:
    asset = db.get_asset(asset_id)
    if not asset:
        return None

    findings = db.list_findings(asset_id=asset_id, limit=1000)
    open_findings = [f for f in findings if f["status"] not in ("fixed", "verified", "false_positive")]
    counts = db.severity_counts(asset_id)
    owc = db.owasp_counts(asset_id)
    checklist_items = db.list_checklist(asset_id)
    subs = db.list_subdomains(asset_id)

    owasp_rows = []
    for code, name in OWASP_TOP10.items():
        owasp_rows.append({"code": code, "name": name, "count": owc.get(code, 0)})

    ctx = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "asset": asset,
        "scan": db.get_scan(scan_id) if scan_id else None,
        "findings": sorted(open_findings, key=_sev_key, reverse=True),
        "all_findings": findings,
        "counts": counts,
        "risk": risk_score(counts),
        "owasp_rows": owasp_rows,
        "checklist": checklist_items,
        "checklist_cov": coverage(checklist_items) if checklist_items else None,
        "subdomains": subs,
        "live_subs": [s for s in subs if s.get("alive")],
    }

    html = _env.get_template("report.html.j2").render(**ctx)

    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in (asset.get("name") or asset["target"]))[:40]
    base = cfg.reports_dir / f"Argus_{safe}_{stamp}"

    html_path = base.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")

    # Try PDF; fall back silently to HTML only.
    try:
        from weasyprint import HTML  # type: ignore
        pdf_path = base.with_suffix(".pdf")
        HTML(string=html).write_pdf(str(pdf_path))
        return pdf_path
    except Exception:
        return html_path


def _sev_key(f: dict) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return order.get(f["severity"], 0)


# ---------------------------------------------------------------- JSON / CSV export
_SECRET_RE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization)(\s*[:=]\s*)(\S+)")
_AWS_RE = re.compile(r"AKIA[0-9A-Z]{16}")
COLUMNS = ["severity", "title", "owasp", "cve", "cwe", "confidence", "cvss", "location",
           "host", "source", "status", "description", "evidence", "remediation",
           "first_seen", "last_seen", "seen_count"]


def redact(text):
    """Mask credentials that may appear in evidence before they leave the system."""
    if not text:
        return text
    out = _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", str(text))
    return _AWS_RE.sub("[REDACTED-AWS-KEY]", out)


def _csv_safe(v) -> str:
    """Stop spreadsheet formula injection when the CSV is opened in Excel/Sheets."""
    if v is None:
        return ""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def export(cfg: Config, asset_id: str, fmt: str):
    asset = db.get_asset(asset_id)
    if not asset:
        return None
    if fmt not in ("json", "csv"):
        raise ValueError("unsupported format")
    findings = db.list_findings(asset_id=asset_id, limit=5000)
    counts = db.severity_counts(asset_id)
    rows = []
    for f in findings:
        rows.append({
            "severity": f["severity"], "title": redact(f["title"]), "owasp": f.get("owasp") or "",
            "cve": f.get("cve") or "", "cwe": f.get("cwe") or "", "confidence": f.get("confidence") or "",
            "cvss": f.get("cvss") or "", "location": redact(f.get("location") or ""),
            "host": f.get("host") or "", "source": f.get("source") or "", "status": f["status"],
            "description": redact(f.get("description") or ""),
            "evidence": redact(f.get("evidence") or ""),
            "remediation": redact(f.get("remediation") or ""),
            "first_seen": f["first_seen"], "last_seen": f["last_seen"], "seen_count": f["seen_count"],
        })
    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = "".join(c if c.isalnum() else "_" for c in (asset.get("name") or asset["target"]))[:40]
    base = cfg.reports_dir / f"Argus_{safe}_{stamp}"
    if fmt == "json":
        doc = {
            "tool": "Argus",
            "generated": datetime.now(timezone.utc).isoformat(),
            "asset": {"id": asset["id"], "name": asset["name"], "target": asset["target"]},
            "summary": {"counts": counts, "risk": risk_score(counts), "total": len(rows)},
            "findings": rows,
        }
        p = base.with_suffix(".json")
        p.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        return p
    p = base.with_suffix(".csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _csv_safe(r.get(k)) for k in COLUMNS})
    return p
