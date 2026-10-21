"""Lead-driven chaining: let the scanners feed each other.

The pipeline keeps a shared state (`st`) that every stage reads and writes. This
module turns that shared state into *leads*: when one tool notices something
(a suspicious parameter name, a reflected marker, a technology), later tools use
it to focus their work and go deeper on exactly those spots instead of testing
blindly.

Everything here is pure and string-only, so it is unit-testable without any
scanner installed, and it only ever *reorders* or *annotates* real discovered
URLs. It never invents a URL and never turns detection into exploitation.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

# Parameter-name classes (from param_hints) worth deep XSS / injection testing.
XSS_CLASSES = frozenset({"XSS/SSTI/SQLi"})
SQLI_CLASSES = frozenset({"XSS/SSTI/SQLi"})


def _key(host: str | None, path: str | None, param: str | None) -> tuple[str, str, str]:
    return ((host or "").lower(), path or "/", (param or "").lower())


def _params(url: str) -> list[str]:
    p = urlparse(url or "")
    return [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]


def reflection_keys(findings) -> set[tuple[str, str, str]]:
    """(host, path, param) for every parameter the reflection probe (argus-xss) flagged."""
    keys: set[tuple[str, str, str]] = set()
    for f in findings or []:
        if getattr(f, "source", "") != "argus-xss":
            continue
        loc = getattr(f, "location", "") or ""
        p = urlparse(loc)
        for name in _params(loc):
            keys.add(_key(p.hostname, p.path, name))
    return keys


def lead_keys(leads, classes) -> set[tuple[str, str, str]]:
    """(host, path, param) for param-name leads whose class is in `classes`."""
    keys: set[tuple[str, str, str]] = set()
    for lead in leads or []:
        if lead.get("class") not in classes:
            continue
        path = urlparse(lead.get("base", "")).path or "/"
        keys.add(_key(lead.get("host"), path, lead.get("param")))
    return keys


def prioritize(urls, focus_keys, cap: int) -> tuple[list[str], int]:
    """Reorder real URLs so any whose parameter matches a focus key comes first.

    Returns (ordered_unique_urls_capped, focus_count). Nothing is invented: the
    output is a subset of `urls`, only reordered and de-duplicated.
    """
    focus: list[str] = []
    rest: list[str] = []
    for u in urls or []:
        hit = any(_key(urlparse(u).hostname, urlparse(u).path, k) in focus_keys for k in _params(u))
        (focus if hit else rest).append(u)
    ordered = list(dict.fromkeys(focus + rest))
    focus_in_cap = sum(1 for u in ordered[:cap] if u in set(focus))
    return ordered[:cap], focus_in_cap


def annotate_corroboration(findings, reflection_keys_set):
    """Mark dalfox findings that land on a parameter the reflection probe also flagged.

    Two independent checks agreeing is stronger proof, so the confidence is raised
    and a note is added. Mutates and returns the same Finding objects.
    """
    corroborated = 0
    for f in findings or []:
        loc = getattr(f, "location", "") or ""
        p = urlparse(loc)
        if any(_key(p.hostname, p.path, name) in reflection_keys_set for name in _params(loc)):
            note = (" Corroborated: the reflection probe independently flagged this same "
                    "parameter, so two checks agree it reflects unencoded input.")
            if note.strip() not in (getattr(f, "description", "") or ""):
                f.description = (getattr(f, "description", "") or "") + note
            if getattr(f, "confidence", "") == "medium":
                f.confidence = "high"
            corroborated += 1
    return findings, corroborated
