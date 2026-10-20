"""Severity + CVSS helpers and OWASP Top 10 (2021/2025) mapping."""
from __future__ import annotations

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Risk points used to produce a single 0-100 asset/program risk score.
SEVERITY_POINTS = {"info": 0, "low": 1, "medium": 4, "high": 9, "critical": 16}


def normalize_severity(value: str | None) -> str:
    if not value:
        return "info"
    v = str(value).strip().lower()
    aliases = {
        "informational": "info",
        "informative": "info",
        "unknown": "info",
        "moderate": "medium",
        "med": "medium",
        "crit": "critical",
    }
    v = aliases.get(v, v)
    return v if v in SEVERITY_WEIGHT else "info"


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "info"
    s = float(score)
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0.0:
        return "low"
    return "info"


def meets_threshold(sev: str, threshold: str) -> bool:
    return SEVERITY_WEIGHT.get(normalize_severity(sev), 0) >= SEVERITY_WEIGHT.get(
        normalize_severity(threshold), 0
    )


def risk_score(counts: dict[str, int]) -> int:
    """Map severity counts -> a bounded 0-100 score (diminishing returns)."""
    raw = sum(SEVERITY_POINTS.get(normalize_severity(k), 0) * v for k, v in counts.items())
    if raw <= 0:
        return 0
    # logarithmic-ish compression so 3 criticals != 48/100 but still high
    import math

    score = 100 * (1 - math.exp(-raw / 40.0))
    return min(100, round(score))


# ---------------------------------------------------------------------------
#  OWASP Top 10 (2021, with 2025-draft labels noted in UI)
# ---------------------------------------------------------------------------
OWASP_TOP10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components",
    "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures",
    "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

# keyword -> OWASP category, used to auto-tag findings coming from scanners
_OWASP_KEYWORDS = [
    (["idor", "access control", "forced browse", "directory listing", "cors", "privilege"], "A01"),
    (["tls", "ssl", "cipher", "cert", "weak crypto", "cleartext", "http only", "hsts"], "A02"),
    (["sqli", "sql injection", "xss", "command injection", "rce", "injection", "ssti", "lfi", "xxe"], "A03"),
    (["business logic", "insecure design", "rate limit"], "A04"),
    (["misconfig", "default", "header", "exposed", "debug", "verbose error", "stack trace", "listing"], "A05"),
    (["cve-", "outdated", "vulnerable component", "known vuln", "version"], "A06"),
    (["auth", "login", "session", "cookie", "jwt", "password", "mfa", "brute"], "A07"),
    (["integrity", "deserial", "sri", "supply chain", "unsigned"], "A08"),
    (["logging", "monitoring", "audit"], "A09"),
    (["ssrf", "request forgery"], "A10"),
]


def guess_owasp(*texts: str) -> str:
    blob = " ".join(t for t in texts if t).lower()
    for keywords, cat in _OWASP_KEYWORDS:
        if any(k in blob for k in keywords):
            return cat
    return "A05"  # misconfiguration is the safest default bucket
