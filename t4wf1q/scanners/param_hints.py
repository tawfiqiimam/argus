"""Parameter-name leads for manual review (passive, sends NO requests).

The crawler already gives us URLs. This module looks only at the parameter
NAMES in those URLs and flags the ones that commonly carry a bug class
(SSRF, LFI/RFI, IDOR, open redirect, XSS/SSTI/SQLi, command injection).
A lead is a place to look, with a manual verification hint. It is never a
confirmed finding, and parameter values are never stored.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from .base import Finding

MAX_LEADS = 200

# (class label, OWASP category, parameter names, manual verification hint)
PATTERNS: list[tuple[str, str, frozenset[str], str]] = [
    ("SSRF", "A10", frozenset({"url", "src", "dest", "feed", "webhook"}),
     "Check whether the server fetches this value (response or timing changes when the value changes). "
     "Use only hosts you control, and only if the program allows out-of-band testing."),
    ("LFI/RFI", "A01", frozenset({"file", "page", "template", "path", "include"}),
     "Check whether the value is used as a file path: compare a valid value with an invalid one. "
     "Prove it with a harmless, non-sensitive file only."),
    ("IDOR", "A01", frozenset({"id", "user_id", "order", "invoice", "doc"}),
     "Use two accounts. Request this object with account B's id while logged in as account A, "
     "then compare the responses."),
    ("Open Redirect", "A01", frozenset({"redirect", "next", "returnto", "goto"}),
     "Check whether the parameter sends the browser to another domain. Use a domain you control, "
     "and only if the program allows it."),
    ("XSS/SSTI/SQLi", "A03", frozenset({"q", "search", "name", "title", "comment"}),
     "Run the marker test: a unique string plus special characters. Check reflection and encoding. "
     "For SQLi/SSTI, check whether the response changes with the input. Do not extract data."),
    ("Command Injection", "A03", frozenset({"cmd", "exec", "shell", "ping", "host"}),
     "Check whether the value reaches a system command, using a harmless marker only. "
     "Stop at proof and run nothing else."),
]


def classify_url(url: str) -> list[dict]:
    """One lead per (parameter, class) found in a URL's query string. Pure string analysis."""
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return []
    netloc = parsed.netloc.rsplit("@", 1)[-1]          # drop any user:pass@ part
    base = f"{parsed.scheme}://{netloc}{parsed.path or '/'}"
    names = dict.fromkeys(k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
    leads: list[dict] = []
    for name in names:
        for label, owasp, params, hint in PATTERNS:
            if name in params:
                leads.append({"param": name, "class": label, "owasp": owasp, "hint": hint,
                              "host": parsed.hostname, "base": base})
    return leads


def leads_for_urls(urls) -> list[dict]:
    """Deduplicated leads across many URLs, capped at MAX_LEADS."""
    seen: set[tuple[str, str, str]] = set()
    out: list[dict] = []
    for url in urls:
        for lead in classify_url(url):
            key = (lead["base"], lead["param"], lead["class"])
            if key in seen:
                continue
            seen.add(key)
            out.append(lead)
            if len(out) >= MAX_LEADS:
                return out
    return out


def lead_to_finding(lead: dict) -> Finding:
    """Info-level finding. Only the parameter NAME is stored, never its value."""
    param, cls = lead["param"], lead["class"]
    return Finding(
        title=f"Parameter lead: '{param}' may be {cls} (manual review)"[:140],
        severity="info",
        owasp=lead["owasp"],
        host=lead["host"],
        location=lead["base"],
        source="param-hints",
        description=(f"The parameter name '{param}' often carries {cls}. This lead comes from the name "
                     f"alone; no request was sent to test it. Manual check: {lead['hint']}"),
        evidence=f"{lead['base']}?{param}=...",
        remediation="Review this parameter by hand. Only a confirmed issue belongs in the report.",
        confidence="low",
    )
