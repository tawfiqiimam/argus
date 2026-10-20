"""Scope allowlist enforcement.

The whole point of the VMS is that automation can run unattended. The scope
guard makes sure unattended scans only ever touch hosts you are authorized to
test. It is deliberately strict and fails closed.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


def extract_host(target: str) -> str:
    """Pull a bare hostname/IP out of a URL or host[:port] string."""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        # could be host, host:port, or a path-like target
        t = "//" + t
    parsed = urlparse(t)
    host = parsed.hostname or ""
    return host.lower().rstrip(".")


def _match_pattern(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower().rstrip(".")
    if not pattern:
        return False

    # CIDR / IP match
    try:
        if "/" in pattern:
            net = ipaddress.ip_network(pattern, strict=False)
            return ipaddress.ip_address(host) in net
        # exact IP
        if _is_ip(pattern) and _is_ip(host):
            return ipaddress.ip_address(host) == ipaddress.ip_address(pattern)
    except ValueError:
        pass

    # wildcard like *.example.com
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)

    # plain domain: authorizes the domain AND its subdomains
    return host == pattern or host.endswith("." + pattern)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class ScopeGuard:
    def __init__(self, enforce: bool, allow: list[str], deny: list[str]):
        self.enforce = bool(enforce)
        self.allow = [a for a in (allow or []) if a]
        self.deny = [d for d in (deny or []) if d]

    @classmethod
    def from_config(cls, cfg) -> "ScopeGuard":
        return cls(
            enforce=cfg.get("scope", "enforce", default=True),
            allow=cfg.get("scope", "allow", default=[]),
            deny=cfg.get("scope", "deny", default=[]),
        )

    def check(self, target: str) -> tuple[bool, str]:
        """Return (allowed, reason)."""
        host = extract_host(target)
        if not host:
            return False, "could not parse a host from target"

        for d in self.deny:
            if _match_pattern(host, d):
                return False, f"host matches deny rule '{d}'"

        if not self.enforce:
            return True, "scope enforcement disabled (use only on authorized targets)"

        for a in self.allow:
            if _match_pattern(host, a):
                return True, f"authorized by allow rule '{a}'"

        return False, (
            f"'{host}' is not in scope. Add it with:  t4wf1q scope add {host}\n"
            "   Only add targets you own or are authorized (e.g. a bug-bounty) to test."
        )

    def in_scope_hosts(self, hosts: list[str]) -> list[str]:
        """Filter a list of discovered subdomains down to authorized ones."""
        out = []
        for h in hosts:
            ok, _ = self.check(h)
            if ok:
                out.append(h)
        return out


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$")


def looks_like_domain(host: str) -> bool:
    return bool(DOMAIN_RE.match(host)) and not _is_ip(host)
