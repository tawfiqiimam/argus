"""Configuration loading for Argus VMS."""
from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT / "config.yaml"
EXAMPLE_CONFIG_PATH = ROOT / "config.yaml.example"

_DEFAULTS: dict[str, Any] = {
    "server": {"host": "127.0.0.1", "port": 8000},
    "auth": {"api_key": ""},
    "database": {"path": "data/t4wf1q.db"},
    "reports": {"dir": "reports"},
    # allow_private: let scans reach loopback/RFC1918 targets (local labs only).
    # Cloud metadata addresses are blocked regardless of this setting.
    "scope": {"enforce": True, "allow": ["localhost", "127.0.0.1"], "deny": [], "allow_private": False},
    "security": {"rate_limit_per_min": 600},
    "automation": {
        "enabled": True,
        "full_scan_cron_hour": 2,
        "change_watch_minutes": 15,
        "update_templates_daily": True,
    },
    "alerts": {
        "min_severity": "high",
        "telegram": {"bot_token": "", "chat_id": ""},
        "discord": {"webhook_url": ""},
    },
    "scanners": {
        "subfinder": "subfinder",
        "httpx": "httpx",
        "nmap": "nmap",
        "nuclei": "nuclei",
        "nikto": "nikto",
        "testssl": "testssl.sh",
        "nuclei_rate_limit": 150,
        "nmap_top_ports": 1000,
        "request_timeout": 20,
        "request_delay": 0.2,
        "concurrency": 5,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


class Config:
    def __init__(self, data: dict[str, Any], path: Path | None = None):
        self._data = data
        self.path = path

    @classmethod
    def load(cls, path: str | os.PathLike | None = None) -> "Config":
        p = Path(path) if path else DEFAULT_CONFIG_PATH
        data = dict(_DEFAULTS)
        if p.exists():
            with open(p, "r", encoding="utf-8") as fh:
                user = yaml.safe_load(fh) or {}
            data = _deep_merge(data, user)
        # Allow env override of the API key (handy for Docker/CI).
        env_key = os.environ.get("T4WF1Q_API_KEY")
        if env_key:
            data.setdefault("auth", {})["api_key"] = env_key
        # If no key configured at all, mint an ephemeral one so the app still boots.
        if not data["auth"].get("api_key") or data["auth"]["api_key"].startswith("CHANGE_ME"):
            data["auth"]["ephemeral_key"] = True
            if not data["auth"].get("api_key") or data["auth"]["api_key"].startswith("CHANGE_ME"):
                data["auth"]["api_key"] = secrets.token_urlsafe(32)
        return cls(data, p if p.exists() else None)

    def get(self, *keys, default=None):
        cur: Any = self._data
        for k in keys:
            if not isinstance(cur, dict) or k not in cur:
                return default
            cur = cur[k]
        return cur

    # convenient typed accessors ------------------------------------------
    @property
    def host(self) -> str:
        return self.get("server", "host", default="127.0.0.1")

    @property
    def port(self) -> int:
        return int(self.get("server", "port", default=8000))

    @property
    def api_key(self) -> str:
        return self.get("auth", "api_key", default="")

    @property
    def db_path(self) -> Path:
        return ROOT / self.get("database", "path", default="data/t4wf1q.db")

    @property
    def reports_dir(self) -> Path:
        return ROOT / self.get("reports", "dir", default="reports")

    @property
    def evidence_dir(self) -> Path:
        """Screenshots and other captured evidence, grouped under reports/evidence."""
        return self.reports_dir / "evidence"

    @property
    def raw(self) -> dict:
        return self._data


# module-level singleton, lazily built
_config: Config | None = None


def get_config(reload: bool = False) -> Config:
    global _config
    if _config is None or reload:
        _config = Config.load()
    return _config
