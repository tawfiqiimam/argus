"""Alert delivery (Telegram / Discord). All optional and best-effort."""
from __future__ import annotations

import httpx

from .config import Config

_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def notify(cfg: Config, asset: dict, finding: dict) -> None:
    text = (
        f"{_EMOJI.get(finding['severity'], '•')} *T4WF1Q · {finding['severity'].upper()}*\n"
        f"*{finding['title']}*\n"
        f"Asset: {asset.get('name') or asset.get('target')}\n"
        f"Where: `{finding.get('location') or finding.get('host') or '-'}`\n"
        f"OWASP: {finding.get('owasp') or '-'}"
    )
    _telegram(cfg, text)
    _discord(cfg, text)


def _telegram(cfg: Config, text: str) -> None:
    token = cfg.get("alerts", "telegram", "bot_token", default="")
    chat = cfg.get("alerts", "telegram", "chat_id", default="")
    if not (token and chat):
        return
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat, "text": text, "parse_mode": "Markdown"},
            timeout=15,
        )
    except Exception:
        pass


def _discord(cfg: Config, text: str) -> None:
    url = cfg.get("alerts", "discord", "webhook_url", default="")
    if not url:
        return
    try:
        httpx.post(url, json={"content": text}, timeout=15)
    except Exception:
        pass
