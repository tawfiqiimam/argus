"""Shared stdlib-only HTTP client for the active web modules.

Deliberate choices for a security tool:
- Direct connections: environment proxies are ignored, so scan traffic never
  leaks through an unknown proxy.
- Redirects are NOT followed: a 3xx is reported as-is (needed for soft-404 and
  takeover checks).
- Bodies are size-capped and are never written to disk or to logs.
- A process-wide throttle caps the request rate regardless of thread count.
"""
from __future__ import annotations

import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

UA = "Mozilla/5.0 (compatible; Argus-VMS/1.0; authorized-assessment)"

# Scanned targets frequently have broken certificates; verification is not the
# point of this client (the scope guard decides *whether* we talk to a host).
_ctx = ssl._create_unverified_context()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_ctx),
    _NoRedirect,
)

_lock = threading.Lock()
_next_slot = [0.0]


@dataclass
class Resp:
    url: str
    status: int
    headers: dict = field(default_factory=dict)
    body: str = ""
    length: int = 0

    @property
    def ctype(self) -> str:
        return self.headers.get("content-type", "").lower()


def throttle(delay: float) -> None:
    """Global rate limit: at most one request per `delay` seconds, any thread."""
    if delay <= 0:
        return
    with _lock:
        now = time.monotonic()
        start = max(now, _next_slot[0])
        _next_slot[0] = start + delay
    wait = start - now
    if wait > 0:
        time.sleep(wait)


def fetch(url: str, *, timeout: float = 10, delay: float = 0.0,
          max_bytes: int = 200_000, headers: dict | None = None) -> Resp | None:
    """GET a URL. Returns None on network failure (never raises)."""
    throttle(delay)
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            status = r.status
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            data = r.read(max_bytes)
    except urllib.error.HTTPError as e:
        status = e.code
        hdrs = {k.lower(): v for k, v in (e.headers or {}).items()}
        try:
            data = e.read(max_bytes)
        except Exception:
            data = b""
    except Exception:
        return None
    return Resp(url=url, status=status, headers=hdrs,
                body=data.decode("utf-8", "replace"), length=len(data))
