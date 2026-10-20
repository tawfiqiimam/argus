"""Built-in HTTP(S) checks — pure Python, zero external tools required.

These run everywhere (even with no Kali tools installed) so the VMS always
produces real findings on localhost. Covers a slice of OWASP A02/A05/A07.
"""
from __future__ import annotations

import ssl
import socket
from urllib.parse import urlparse

import httpx

from .base import Finding, ScanContext

SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy header", "medium", "A05"),
    "x-frame-options": ("Missing X-Frame-Options (clickjacking)", "low", "A05"),
    "x-content-type-options": ("Missing X-Content-Type-Options: nosniff", "low", "A05"),
    "strict-transport-security": ("Missing HSTS header", "medium", "A02"),
    "referrer-policy": ("Missing Referrer-Policy header", "info", "A05"),
    "permissions-policy": ("Missing Permissions-Policy header", "info", "A05"),
}


def scan(ctx: ScanContext, urls: list[str]) -> list[Finding]:
    timeout = int(ctx.scanners_cfg.get("request_timeout", 20))
    findings: list[Finding] = []
    ctx.log("info", f"http-checks: inspecting {len(urls)} endpoint(s)")

    for url in urls:
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                r = client.get(url)
        except Exception as e:
            ctx.log("warn", f"http-checks: {url} unreachable ({type(e).__name__})")
            continue

        host = urlparse(str(r.url)).hostname
        headers = {k.lower(): v for k, v in r.headers.items()}

        # Missing security headers
        for hdr, (title, sev, owasp) in SECURITY_HEADERS.items():
            if hdr not in headers:
                findings.append(Finding(
                    title=title, severity=sev, owasp=owasp, host=host, location=url,
                    source="http-checks",
                    description=f"The response from {url} does not set the {hdr} header.",
                    evidence=f"HTTP {r.status_code}; header '{hdr}' absent",
                    remediation=f"Add the {hdr} response header at the web server or app layer.",
                ))

        # Cleartext HTTP
        if str(r.url).startswith("http://"):
            findings.append(Finding(
                title="Service available over cleartext HTTP", severity="medium",
                owasp="A02", host=host, location=url, source="http-checks",
                description="Traffic is served without TLS and can be intercepted.",
                remediation="Redirect all HTTP to HTTPS and enable HSTS.",
            ))

        # Server banner leak
        if "server" in headers and any(ch.isdigit() for ch in headers["server"]):
            findings.append(Finding(
                title="Server version disclosed in banner", severity="low", owasp="A05",
                host=host, location=url, source="http-checks",
                description="The Server header reveals software and version.",
                evidence=f"Server: {headers['server']}",
                remediation="Suppress or genericize the Server header.",
            ))

        # Set-Cookie flags
        for cookie in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []:
            low = cookie.lower()
            missing = [f for f in ("httponly", "secure") if f not in low]
            if missing:
                findings.append(Finding(
                    title=f"Cookie missing {'/'.join(missing)} flag", severity="low",
                    owasp="A07", host=host, location=url, source="http-checks",
                    description="A session cookie lacks hardening flags.",
                    evidence=cookie.split(";")[0] + " ; ...",
                    remediation="Set HttpOnly, Secure and SameSite on session cookies.",
                ))

    # TLS certificate expiry check (HTTPS hosts)
    for url in urls:
        p = urlparse(url)
        if p.scheme != "https":
            continue
        host = p.hostname
        port = p.port or 443
        try:
            cert_days = _cert_days_left(host, port, timeout)
        except Exception:
            continue
        if cert_days is not None and cert_days < 0:
            findings.append(Finding(
                title="TLS certificate expired", severity="high", owasp="A02",
                host=host, location=f"{host}:{port}", source="http-checks",
                description="The TLS certificate is past its expiry date.",
                evidence=f"expired {abs(cert_days)} day(s) ago",
                remediation="Renew the certificate and automate renewal.",
            ))
        elif cert_days is not None and cert_days < 14:
            findings.append(Finding(
                title="TLS certificate expiring soon", severity="low", owasp="A02",
                host=host, location=f"{host}:{port}", source="http-checks",
                description="The TLS certificate expires within two weeks.",
                evidence=f"{cert_days} day(s) remaining",
                remediation="Renew ahead of expiry; automate with ACME.",
            ))

    ctx.log("info", f"http-checks: {len(findings)} finding(s)")
    return findings


def _cert_days_left(host: str, port: int, timeout: int) -> int | None:
    from datetime import datetime, timezone
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    if not cert or "notAfter" not in cert:
        return None
    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return (exp - datetime.now(timezone.utc)).days
