"""Turn a raw finding into something a researcher can act on.

For every finding we attach:
  * a PINPOINT line — the exact host, path, parameter and method to look at;
  * step-by-step MANUAL VERIFICATION for that bug class (safe, proof-only);
  * RESEARCH links (OWASP cheat sheet, the CWE page, PortSwigger Academy).

The verification steps stop at proof. They never describe exploitation, data
extraction or anything destructive. Everything here is a pure function of the
finding dict, so it is fully unit-testable.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

# OWASP category -> (how to verify by hand, [research links])
_OWASP = {
    "A01": (
        ["Note the object reference in the request (an id, uuid, filename or path).",
         "Log in as user A and open the object; repeat the exact request as user B.",
         "If B sees A's data, it is IDOR. For privilege checks, request an admin-only "
         "endpoint as a normal user and compare the responses.",
         "Proof = two responses side by side (different accounts, same object). Stop there."],
        ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
         "https://portswigger.net/web-security/access-control/idor"],
    ),
    "A02": (
        ["Confirm the weak transport: open the URL over http:// and watch for a redirect to https.",
         "Check the TLS config (testssl.sh output) and whether Strict-Transport-Security is set.",
         "Look for sensitive data (tokens, PII) sent without TLS or stored in responses.",
         "Proof = the request/response showing missing HSTS, weak cipher, or cleartext data."],
        ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
         "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
    ),
    "A03": (
        ["Send a unique marker plus special characters (\" ' < > and for SQL a single quote) in the parameter.",
         "Watch the response: reflected unencoded = XSS context; SQL/driver error or a change in "
         "behaviour between ' and '' = SQL injection candidate; template output evaluated (e.g. 7*7 -> 49) = SSTI.",
         "For XSS, confirm execution in a real browser and note the exact context (HTML, attribute, JS).",
         "Proof = the reflected marker or the error. Do NOT extract data or run further payloads."],
        ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
         "https://portswigger.net/web-security/sql-injection",
         "https://portswigger.net/web-security/cross-site-scripting"],
    ),
    "A04": (
        ["Map the normal flow first (the intended steps and their order).",
         "Try to break the assumptions: negative or huge quantities, skipping a step, replaying a "
         "request, or doing two requests at once (race).",
         "Proof = a request sequence that reaches a state the design did not intend."],
        ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
         "https://portswigger.net/web-security/logic-flaws"],
    ),
    "A05": (
        ["Reproduce the exposed item directly (the debug page, default page, verbose error, or missing header).",
         "For headers, show the response without the expected security header.",
         "For exposed consoles/defaults, show the page loads without auth.",
         "Proof = the raw response. Do not change any server setting."],
        ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
         "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"],
    ),
    "A06": (
        ["Identify the component and its exact version (from the banner, JS file, or response).",
         "Match the version against the CVE (see the CVE link on this finding).",
         "Confirm the vulnerable code path is actually reachable, not just present.",
         "Proof = the version string plus the matching CVE reference."],
        ["https://owasp.org/www-project-dependency-check/",
         "https://nvd.nist.gov/"],
    ),
    "A07": (
        ["Test the auth control named in the finding: lockout/throttling, session cookie flags, "
         "or the password-reset token.",
         "For brute force, send several bad logins and watch for a lockout or rate limit.",
         "For sessions, inspect the cookie for HttpOnly / Secure / SameSite.",
         "Proof = the response showing the missing control. Never use real users' accounts."],
        ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
         "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
    ),
    "A08": (
        ["Identify where untrusted data is deserialized or where an update/script is loaded without integrity.",
         "For third-party scripts, check for a Subresource Integrity (SRI) hash.",
         "Proof = the object/flow that accepts untrusted serialized data, or the script tag without SRI."],
        ["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
         "https://portswigger.net/web-security/deserialization"],
    ),
    "A09": (
        ["Trigger a security-relevant event (a failed login or an access-control denial).",
         "Check whether it is logged and whether any alert fires.",
         "Proof = evidence the event was not recorded or not alerted (often needs app owner confirmation)."],
        ["https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"],
    ),
    "A10": (
        ["Find the feature that fetches a URL (webhook, image/url import, pdf render, link preview).",
         "Point it at a host you control and watch for an inbound request (out-of-band), or at a "
         "harmless internal marker, and compare response/timing.",
         "Proof = the server-side fetch reaching your listener. Do NOT touch cloud metadata or real internal services.",
         "Only run this if the program allows out-of-band testing."],
        ["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
         "https://portswigger.net/web-security/ssrf"],
    ),
}

# A few source-specific first steps, prepended when they add precision.
_SOURCE = {
    "argus-xss": "The reflection probe already saw an unencoded marker here, so start by reproducing that.",
    "dalfox": "dalfox produced a proof-of-concept URL — open it in a browser to confirm the script runs.",
    "param-hints": "This is a NAME-based lead only; nothing was sent yet. Begin the verification below.",
    "testssl": "Re-run testssl.sh against the host to reproduce the exact TLS weakness.",
    "nuclei": "Reproduce the matched template's request by hand and confirm the response it keyed on.",
}


def _cwe_link(cwe: str | None) -> str | None:
    if not cwe:
        return None
    num = "".join(ch for ch in str(cwe) if ch.isdigit())
    return f"https://cwe.mitre.org/data/definitions/{num}.html" if num else None


def pinpoint(finding: dict) -> str:
    """Exact spot to look at: host, path, parameter(s) and the likely method."""
    loc = finding.get("location") or ""
    host = finding.get("host") or urlparse(loc).hostname or "the target"
    p = urlparse(loc)
    params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
    bits = [f"host {host}"]
    if p.path and p.path != "/":
        bits.append(f"path {p.path}")
    if params:
        bits.append("parameter " + ", ".join(f"'{x}'" for x in params))
        bits.append("method GET (query string)")
    elif loc:
        bits.append(f"at {loc}")
    return " · ".join(bits)


def enrich(finding: dict) -> dict:
    """Add `verify` (pinpoint + manual steps) and research links to a finding dict. In place."""
    owasp = (finding.get("owasp") or "").upper()
    if owasp not in _OWASP:
        owasp = _guess_owasp_from_cwe(finding.get("cwe"))
    steps, links = _OWASP.get(owasp, ([], []))

    lines = [f"Pinpoint: {pinpoint(finding)}", ""]
    src = finding.get("source")
    if src in _SOURCE:
        lines.append(_SOURCE[src])
    if steps:
        lines.append("Verify by hand:")
        lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)]
    finding["verify"] = "\n".join(lines).strip()

    refs = list(finding.get("reference") or [])
    for link in [_cwe_link(finding.get("cwe"))] + list(links):
        if link and link not in refs:
            refs.append(link)
    finding["reference"] = refs
    return finding


def _guess_owasp_from_cwe(cwe: str | None) -> str:
    num = "".join(ch for ch in str(cwe or "") if ch.isdigit())
    return {
        "79": "A03", "89": "A03", "94": "A03", "78": "A03", "1336": "A03",
        "22": "A01", "639": "A01", "284": "A01", "918": "A10",
        "287": "A07", "384": "A07", "502": "A08", "319": "A02", "1021": "A05",
    }.get(num, "")
