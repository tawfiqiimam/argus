"""Manual OWASP Top 10 checklist catalog.

Automated scanners can't reliably detect categories like Insecure Design (A04)
or Logging & Monitoring Failures (A09). These are the manual review items a
security researcher ticks off per asset, so the VMS stays honest about
coverage instead of pretending a scanner found everything.
"""
from __future__ import annotations

CATALOG = [
    # A01 Broken Access Control
    {"key": "a01-idor", "owasp": "A01", "title": "Test object references for IDOR (swap IDs between accounts)"},
    {"key": "a01-vert", "owasp": "A01", "title": "Vertical privilege escalation: can a user reach admin functions?"},
    {"key": "a01-force", "owasp": "A01", "title": "Forced browsing to unlinked/admin endpoints"},
    {"key": "a01-cors", "owasp": "A01", "title": "CORS policy does not reflect arbitrary Origin with credentials"},

    # A02 Cryptographic Failures
    {"key": "a02-tls", "owasp": "A02", "title": "Strong TLS only (no SSLv3/TLS1.0/1.1, no weak ciphers)"},
    {"key": "a02-transit", "owasp": "A02", "title": "All sensitive data in transit over HTTPS; HSTS set"},
    {"key": "a02-atrest", "owasp": "A02", "title": "Sensitive data at rest encrypted; no secrets in responses"},

    # A03 Injection
    {"key": "a03-sqli", "owasp": "A03", "title": "Inputs parameterized; manual SQLi on key params"},
    {"key": "a03-xss", "owasp": "A03", "title": "Reflected/stored/DOM XSS checked on user-controlled output"},
    {"key": "a03-cmd", "owasp": "A03", "title": "No OS command / template (SSTI) injection on dynamic features"},

    # A04 Insecure Design (manual)
    {"key": "a04-logic", "owasp": "A04", "title": "Business-logic abuse (negative qty, race, workflow bypass)"},
    {"key": "a04-rate", "owasp": "A04", "title": "Rate limiting on auth, OTP, password reset, expensive actions"},
    {"key": "a04-threat", "owasp": "A04", "title": "Threat model reviewed for critical flows"},

    # A05 Security Misconfiguration
    {"key": "a05-headers", "owasp": "A05", "title": "Security headers present (CSP, X-Frame-Options, etc.)"},
    {"key": "a05-defaults", "owasp": "A05", "title": "No default creds, sample apps, or debug consoles exposed"},
    {"key": "a05-errors", "owasp": "A05", "title": "Error pages do not leak stack traces / versions"},

    # A06 Vulnerable & Outdated Components
    {"key": "a06-inventory", "owasp": "A06", "title": "Component inventory reviewed; known CVEs triaged"},
    {"key": "a06-js", "owasp": "A06", "title": "Front-end JS libraries checked for known vulns"},

    # A07 Auth Failures
    {"key": "a07-brute", "owasp": "A07", "title": "Account lockout / throttling against brute force"},
    {"key": "a07-session", "owasp": "A07", "title": "Session fixation, cookie flags (HttpOnly/Secure/SameSite)"},
    {"key": "a07-reset", "owasp": "A07", "title": "Password reset flow cannot be abused / tokens not guessable"},

    # A08 Integrity Failures
    {"key": "a08-deser", "owasp": "A08", "title": "No insecure deserialization of untrusted data"},
    {"key": "a08-sri", "owasp": "A08", "title": "Third-party scripts use SRI; update channel is signed"},

    # A09 Logging & Monitoring (manual)
    {"key": "a09-logs", "owasp": "A09", "title": "Security events logged (auth, access control failures)"},
    {"key": "a09-alert", "owasp": "A09", "title": "Alerting exists for suspicious activity; logs tamper-resistant"},

    # A10 SSRF
    {"key": "a10-ssrf", "owasp": "A10", "title": "URL-fetching features validated against SSRF (metadata, internal)"},
]


def coverage(items: list[dict]) -> dict:
    total = len(items) or 1
    done = sum(1 for i in items if i["state"] in ("pass", "fail", "na"))
    failed = sum(1 for i in items if i["state"] == "fail")
    return {
        "total": len(items),
        "reviewed": done,
        "failed": failed,
        "percent": round(100 * done / total),
    }
