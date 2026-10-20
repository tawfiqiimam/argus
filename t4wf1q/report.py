"""Auto report generation: self-contained HTML, optional PDF via WeasyPrint."""
from __future__ import annotations

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
    base = cfg.reports_dir / f"T4WF1Q_{safe}_{stamp}"

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
