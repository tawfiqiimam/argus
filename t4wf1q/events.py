"""In-process async pub/sub bus for live dashboard updates (WebSocket)."""
from __future__ import annotations

import asyncio
import json
from typing import Any

_subscribers: set[asyncio.Queue] = set()
_loop: asyncio.AbstractEventLoop | None = None


def bind_loop(loop: asyncio.AbstractEventLoop) -> None:
    global _loop
    _loop = loop


async def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers.add(q)
    return q


def unsubscribe(q: asyncio.Queue) -> None:
    _subscribers.discard(q)


async def _broadcast(payload: dict[str, Any]) -> None:
    data = json.dumps(payload, default=str)
    dead = []
    for q in list(_subscribers):
        try:
            q.put_nowait(data)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        _subscribers.discard(q)


def publish(kind: str, **data: Any) -> None:
    """Thread-safe publish. Safe to call from scanner worker threads."""
    payload = {"kind": kind, **data}
    if _loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(_broadcast(payload), _loop)
    except RuntimeError:
        pass
