"""Screenshot evidence capture (gowitness).

A screenshot is evidence a researcher and a triager can both look at without
re-running anything — useful on its own, and it feeds the report. gowitness's
CLI has changed across versions (v2 vs v3 subcommands), so this adapter tries
the modern command first and falls back to the older one. Success is judged by
whether new image files actually appeared, not by the exit code alone, so a
partial or differently-flagged version still gets credit for what it produced.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from .base import ScanContext, run, tool_available

IMG_EXT = (".png", ".jpg", ".jpeg")
MAX_TARGETS = 25


def _safe_name(url: str) -> str:
    p = urlparse(url)
    name = f"{p.hostname or 'host'}_{p.path or ''}".strip("_/")
    name = "".join(c if c.isalnum() or c in "-._" else "_" for c in name)
    return name[:120] or "screenshot"


def capture(ctx: ScanContext, urls: list[str], out_dir: Path) -> list[dict]:
    """Screenshot each URL into out_dir. Returns [{"url","host","file"}], file is relative
    to out_dir. Never raises; a missing tool or a failed capture just means an empty list.
    """
    bin_ = ctx.scanners_cfg.get("gowitness", "gowitness")
    if not (bin_ and tool_available(bin_)):
        ctx.log("warn", "gowitness not installed — skipping screenshot evidence")
        return []
    targets = list(dict.fromkeys(urls))[:MAX_TARGETS]
    if not targets:
        return []
    out_dir.mkdir(parents=True, exist_ok=True)

    before = {p.name for p in out_dir.iterdir() if p.suffix.lower() in IMG_EXT}
    fd, list_path = tempfile.mkstemp(suffix=".txt", prefix="argus_gowitness_")
    after = before
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(targets))

        ctx.log("info", f"gowitness: capturing {len(targets)} screenshot(s)")
        # Try the v3 command shape first, then the older v2 shape. Either one writing
        # files into out_dir counts as success; an unsupported shape just errors quietly.
        run([bin_, "scan", "file", "-f", list_path, "--screenshot-path", str(out_dir),
             "--no-http-server"], timeout=300)
        after = {p.name for p in out_dir.iterdir() if p.suffix.lower() in IMG_EXT}
        if after == before:
            run([bin_, "file", "-f", list_path, "-P", str(out_dir), "--disable-logging"], timeout=300)
            after = {p.name for p in out_dir.iterdir() if p.suffix.lower() in IMG_EXT}
    except OSError:
        pass
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass

    new_files = sorted(after - before)
    manifest: list[dict] = []
    # gowitness names files from its own hash of the URL, so we cannot map file->url
    # exactly without parsing its database (format varies by version). Report what
    # exists; the file names and host are still useful as standalone evidence.
    for fname in new_files:
        manifest.append({"file": fname, "host": None, "url": None})
    if manifest:
        ctx.log("info", f"gowitness: {len(manifest)} screenshot(s) saved")
    else:
        ctx.log("warn", "gowitness: produced no screenshots (check the install / version)")
    return manifest
