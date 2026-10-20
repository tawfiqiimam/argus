"""Scope allowlist enforcement.

The whole point of the VMS is that automation can run unattended. The scope
guard makes sure unattended scans only ever touch hosts you are authorized to
test. It is deliberately strict and fails closed.

Two hard limits sit on top of the allowlist:
- Cloud metadata and link-local addresses are never scannable (SSRF protection).
- Private, loopback and reserved addresses are refused unless the operator
  explicitly enables "allow_private" (intended for local lab targets only).
Hostnames are resolved and every returned address is checked, so a public name
that points at an internal address is refused too.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import threading
from urllib.parse import urlparse

_ALWAYS_BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "169.254.0.0/16",       # IPv4 link-local, includes AWS/GCP/Azure metadata
    "100.100.100.200/32",   # Alibaba Cloud metadata
    "fd00:ec2::/32",        # AWS IPv6 metadata
    "fe80::/10",            # IPv6 link-local
    "0.0.0.0/8",
)]
_ALWAYS_BLOCKED_NAMES = {
    "metadata", "metadata.google.internal", "instance-data", "instance-data.ec2.internal",
}


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


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


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


_resolve_lock = threading.Lock()
_resolve_cache: dict[str, list[str]] = {}


def _resolve(host: str) -> list[str]:
    """Resolve a hostname to its addresses (cached). Unresolvable names give []."""
    with _resolve_lock:
        if host in _resolve_cache:
            return _resolve_cache[host]
    try:
        addrs = sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except (OSError, UnicodeError, ValueError):
        addrs = []
    with _resolve_lock:
        if len(_resolve_cache) > 5000:
            _resolve_cache.clear()
        _resolve_cache[host] = addrs
    return addrs


def _address_block_reason(value: str, allow_private: bool) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "unparseable address (refused)"
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if any(ip.version == net.version and ip in net for net in _ALWAYS_BLOCKED_NETS):
        return "cloud metadata or link-local address"
    if ip.is_unspecified or ip.is_multicast:
        return "unspecified or multicast address"
    if not allow_private and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
        return ("private, loopback or reserved address "
                "(enable 'Allow private targets' in Settings for local lab targets only)")
    return None


class ScopeGuard:
    def __init__(self, enforce: bool, allow: list[str], deny: list[str], allow_private: bool = False):
        self.enforce = bool(enforce)
        self.allow = [a for a in (allow or []) if a]
        self.deny = [d for d in (deny or []) if d]
        self.allow_private = bool(allow_private)

    @classmethod
    def from_config(cls, cfg) -> "ScopeGuard":
        return cls(
            enforce=cfg.get("scope", "enforce", default=True),
            allow=cfg.get("scope", "allow", default=[]),
            deny=cfg.get("scope", "deny", default=[]),
            allow_private=cfg.get("scope", "allow_private", default=False),
        )

    @classmethod
    def from_db(cls) -> "ScopeGuard":
        """Build the guard from runtime-editable scope stored in the DB."""
        from . import db
        allow, deny = db.scope_lists()
        return cls(
            enforce=bool(db.get_setting("scope_enforce", True)),
            allow=allow,
            deny=deny,
            allow_private=bool(db.get_setting("allow_private", False)),
        )

    def host_block_reason(self, host: str) -> str | None:
        """Refuse metadata endpoints, and private/loopback targets unless allowed.

        Applies even when scope enforcement is switched off.
        """
        if host in _ALWAYS_BLOCKED_NAMES:
            return "cloud metadata hostname is never scannable"
        if _is_ip(host):
            return _address_block_reason(host, self.allow_private)
        for addr in _resolve(host):
            reason = _address_block_reason(addr, self.allow_private)
            if reason:
                return f"'{host}' resolves to {addr}: {reason}"
        return None

    def check(self, target: str) -> tuple[bool, str]:
        """Return (allowed, reason)."""
        host = extract_host(target)
        if not host:
            return False, "could not parse a host from target"

        for d in self.deny:
            if _match_pattern(host, d):
                return False, f"host matches deny rule '{d}'"

        if not self.enforce:
            reason = self.host_block_reason(host)
            if reason:
                return False, reason
            return True, "scope enforcement disabled (use only on authorized targets)"

        for a in self.allow:
            if _match_pattern(host, a):
                reason = self.host_block_reason(host)
                if reason:
                    return False, reason
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
