"""Common helpers for scanner wrappers.

Design goal: every wrapper runs the *real* Kali tool when it's on PATH, but
degrades gracefully (and loudly) when a tool is missing, so the whole system
still boots and demos on any machine. A missing tool is reported as a scan
event, never a crash.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable

LogFn = Callable[[str, str], None]  # (level, message)


def tool_available(binary: str) -> bool:
    if not binary:
        return False
    return shutil.which(binary) is not None


def run(cmd: list[str], timeout: int = 600) -> tuple[int, str, str]:
    """Run a command, capturing output. Never raises on non-zero exit."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:  # pragma: no cover - defensive
        return 1, "", str(e)


def fingerprint(*parts: str) -> str:
    h = hashlib.sha1("|".join(p or "" for p in parts).encode()).hexdigest()
    return h[:16]


@dataclass
class Finding:
    title: str
    severity: str = "info"
    cvss: float | None = None
    owasp: str | None = None
    host: str | None = None
    location: str | None = None
    source: str | None = None
    description: str | None = None
    evidence: str | None = None
    remediation: str | None = None
    reference: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["fingerprint"] = fingerprint(
            self.source or "", self.title, self.host or "", self.location or ""
        )
        return d


@dataclass
class ScanContext:
    asset: dict
    scan_id: str
    cfg: object                      # t4wf1q.config.Config
    log: LogFn
    targets: list[str] = field(default_factory=list)   # resolved in-scope hosts/urls
    hosts: list[str] = field(default_factory=list)      # discovered subdomains
    scanners_cfg: dict = field(default_factory=dict)
