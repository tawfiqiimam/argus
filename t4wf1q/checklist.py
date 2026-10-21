"""Manual OWASP Top 10 hunting checklist.

Scanners miss whole bug classes — access control, business logic, SSRF chains,
auth bypasses. This catalog is a researcher's hunting list per OWASP category:
each item says exactly how to test it by hand and how severe it usually is, so
the dashboard stays honest about coverage and points you at the critical bugs.

Each item: key, owasp, title, severity (critical|high|medium), how (manual steps).
The `how` text stops at proof — it never describes exploitation or data theft.
Old keys are kept so saved progress is never orphaned.
"""
from __future__ import annotations

CATALOG = [
    # ---------------- A01 Broken Access Control ----------------
    {"key": "a01-idor", "owasp": "A01", "severity": "critical",
     "title": "IDOR — swap object IDs between two accounts",
     "how": "With accounts A and B, open an object as A, then replay the exact request using A's "
            "id while authenticated as B. If B sees A's data, it is IDOR. Proof = both responses."},
    {"key": "a01-vert", "owasp": "A01", "severity": "critical",
     "title": "Vertical privilege escalation to admin functions",
     "how": "As a normal user, call admin-only endpoints/actions directly (forced browsing, or change "
            "a role field). If it works, that's a broken access control. Compare normal vs admin responses."},
    {"key": "a01-force", "owasp": "A01", "severity": "high",
     "title": "Forced browsing to unlinked / hidden endpoints",
     "how": "Request admin, debug, backup or internal paths that aren't linked. A 200 with real content "
            "instead of a login redirect is the finding."},
    {"key": "a01-cors", "owasp": "A01", "severity": "high",
     "title": "CORS reflects arbitrary Origin with credentials",
     "how": "Send Origin: https://evil.example and check if Access-Control-Allow-Origin echoes it while "
            "Allow-Credentials is true. That lets another site read authenticated responses."},
    {"key": "a01-jwt", "owasp": "A01", "severity": "critical",
     "title": "JWT tampering (alg=none, weak secret, kid abuse)",
     "how": "Decode the token. Try alg:none, a brute-forced HS256 secret, or a swapped user/role claim. "
            "If a forged token is accepted, auth is broken. Only use your own tokens."},
    {"key": "a01-massassign", "owasp": "A01", "severity": "high",
     "title": "Mass assignment / parameter tampering",
     "how": "Add fields the UI doesn't send (role, is_admin, price, verified) to a create/update request "
            "and see if the server honours them."},

    # ---------------- A02 Cryptographic Failures ----------------
    {"key": "a02-tls", "owasp": "A02", "severity": "medium",
     "title": "Weak TLS (old protocols / ciphers)",
     "how": "Run testssl.sh. Flag SSLv3/TLS1.0/1.1, RC4, export ciphers, or an expired/mismatched cert."},
    {"key": "a02-transit", "owasp": "A02", "severity": "high",
     "title": "Sensitive data without TLS / missing HSTS",
     "how": "Open the site over http:// and watch for cleartext or no redirect; check for Strict-Transport-Security."},
    {"key": "a02-atrest", "owasp": "A02", "severity": "high",
     "title": "Secrets or PII leaked in responses",
     "how": "Grep responses and JS bundles for tokens, API keys, internal hostnames, emails, or debug data."},
    {"key": "a02-secrets", "owasp": "A02", "severity": "critical",
     "title": "Exposed secrets in JS / source maps / .git / .env",
     "how": "Fetch /.git/config, /.env, *.js.map, and search JS for keys. A live secret is often critical."},

    # ---------------- A03 Injection ----------------
    {"key": "a03-sqli", "owasp": "A03", "severity": "critical",
     "title": "SQL injection on key parameters",
     "how": "Send ' and '' and compare behaviour; look for driver errors or boolean differences. Confirm "
            "with a safe boolean/time test. Do not extract data — stop at proof."},
    {"key": "a03-xss", "owasp": "A03", "severity": "high",
     "title": "Reflected / stored / DOM XSS",
     "how": "Send a unique marker with \" ' < >. If it reflects unencoded, confirm execution in a browser "
            "and note the context. For stored, check where the input is later rendered."},
    {"key": "a03-cmd", "owasp": "A03", "severity": "critical",
     "title": "OS command injection",
     "how": "On features that run commands (ping, convert, export), inject a harmless marker (e.g. a delay "
            "or a unique token) and watch for it. Stop at proof; run nothing else."},
    {"key": "a03-ssti", "owasp": "A03", "severity": "critical",
     "title": "Server-side template injection (SSTI)",
     "how": "Send {{7*7}} / ${7*7} / <%= 7*7 %> in inputs rendered server-side. If 49 appears, it's SSTI. "
            "Identify the engine, then stop at proof."},
    {"key": "a03-xxe", "owasp": "A03", "severity": "critical",
     "title": "XML external entity (XXE)",
     "how": "On XML/SOAP/SVG/DOCX uploads, submit a document with a harmless external entity to a listener "
            "you control. An inbound hit proves XXE. No local file reads."},
    {"key": "a03-nosqli", "owasp": "A03", "severity": "high",
     "title": "NoSQL / LDAP injection",
     "how": "Try operator payloads ([$ne], [$gt]) or LDAP metacharacters in auth/search and watch for "
            "auth bypass or changed result counts."},

    # ---------------- A04 Insecure Design ----------------
    {"key": "a04-logic", "owasp": "A04", "severity": "high",
     "title": "Business-logic abuse (quantity, workflow, replay)",
     "how": "Try negative/huge quantities, skip a required step, reuse a one-time token, or replay a "
            "purchase/transfer. Proof = reaching an unintended state."},
    {"key": "a04-race", "owasp": "A04", "severity": "high",
     "title": "Race condition on limited actions",
     "how": "Fire the same request many times in parallel (coupon, withdrawal, vote, redeem). Look for "
            "double-spend or limit bypass."},
    {"key": "a04-rate", "owasp": "A04", "severity": "medium",
     "title": "Missing rate limiting on sensitive actions",
     "how": "Send many requests to login, OTP, password reset, or an expensive endpoint and check for "
            "throttling/lockout."},

    # ---------------- A05 Security Misconfiguration ----------------
    {"key": "a05-headers", "owasp": "A05", "severity": "medium",
     "title": "Missing security headers",
     "how": "Check for CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy."},
    {"key": "a05-defaults", "owasp": "A05", "severity": "high",
     "title": "Default creds / sample apps / exposed consoles",
     "how": "Look for actuator, phpinfo, admin consoles, default logins, or install pages reachable without auth."},
    {"key": "a05-errors", "owasp": "A05", "severity": "medium",
     "title": "Verbose errors leak stack traces / versions",
     "how": "Trigger an error (bad type, missing field) and look for stack traces, framework versions, or SQL."},
    {"key": "a05-takeover", "owasp": "A05", "severity": "critical",
     "title": "Subdomain takeover",
     "how": "Find CNAMEs pointing at unclaimed services (S3, GitHub Pages, Heroku…). A dangling target you "
            "can register means takeover. Confirm the service says 'not found', do not claim third-party assets."},

    # ---------------- A06 Vulnerable Components ----------------
    {"key": "a06-inventory", "owasp": "A06", "severity": "high",
     "title": "Known-CVE components in use",
     "how": "List components and versions (banners, JS, headers). Match versions to CVEs and confirm the "
            "vulnerable path is reachable."},
    {"key": "a06-js", "owasp": "A06", "severity": "medium",
     "title": "Outdated front-end JS libraries",
     "how": "Identify library versions in loaded JS and check them against known advisories."},

    # ---------------- A07 Auth Failures ----------------
    {"key": "a07-brute", "owasp": "A07", "severity": "high",
     "title": "No lockout / throttling on login",
     "how": "Send repeated bad logins (your own account) and watch for lockout, CAPTCHA, or delay."},
    {"key": "a07-session", "owasp": "A07", "severity": "high",
     "title": "Weak session / cookie handling",
     "how": "Check cookie flags (HttpOnly, Secure, SameSite), session fixation, and whether logout/rotation works."},
    {"key": "a07-reset", "owasp": "A07", "severity": "critical",
     "title": "Password reset / account takeover flow",
     "how": "Inspect the reset token (guessable? reusable? host-header poisoning?) and whether email can be "
            "changed without re-auth. Use only your own accounts."},
    {"key": "a07-mfa", "owasp": "A07", "severity": "high",
     "title": "MFA / OTP bypass",
     "how": "Try skipping the OTP step, brute-forcing a short code without rate limit, or reusing a code."},

    # ---------------- A08 Integrity Failures ----------------
    {"key": "a08-deser", "owasp": "A08", "severity": "critical",
     "title": "Insecure deserialization",
     "how": "Find where serialized objects are accepted (cookies, tokens, uploads). Flag untrusted data fed "
            "to a deserializer; confirm the sink, don't build a gadget chain on a live target."},
    {"key": "a08-upload", "owasp": "A08", "severity": "critical",
     "title": "Unrestricted file upload → code execution",
     "how": "Upload an unexpected type (e.g. a server-executable), bypass checks via extension/content-type/"
            "magic bytes, and see if it is reachable/executed. Prove reachability, not full RCE."},
    {"key": "a08-sri", "owasp": "A08", "severity": "medium",
     "title": "Third-party scripts without integrity",
     "how": "Check external <script> tags for an SRI hash and whether the update channel is signed."},

    # ---------------- A09 Logging & Monitoring ----------------
    {"key": "a09-logs", "owasp": "A09", "severity": "medium",
     "title": "Security events not logged",
     "how": "Trigger failed logins / access-control denials and confirm (with the owner) they are recorded."},
    {"key": "a09-alert", "owasp": "A09", "severity": "medium",
     "title": "No alerting on suspicious activity",
     "how": "Check whether spikes of failures or clear attack patterns raise any alert."},

    # ---------------- A10 SSRF ----------------
    {"key": "a10-ssrf", "owasp": "A10", "severity": "critical",
     "title": "SSRF in URL-fetching features",
     "how": "Find webhooks, URL import, PDF/preview generators. Point them at a listener you control and watch "
            "for the inbound request. Never touch cloud metadata or real internal hosts. Out-of-band testing "
            "only if the program allows it."},
    {"key": "a10-redirect", "owasp": "A10", "severity": "medium",
     "title": "Open redirect (can chain to takeover/SSRF)",
     "how": "Put an external URL in redirect/next/return params and see if the browser is sent off-domain. "
            "Useful as a chain primitive; note where it lands."},
]


def meta_by_key() -> dict:
    """item_key -> {severity, how, owasp, title} for merging into stored checklist rows."""
    return {i["key"]: {"severity": i.get("severity", "medium"), "how": i.get("how", ""),
                       "owasp": i["owasp"], "title": i["title"]} for i in CATALOG}


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
