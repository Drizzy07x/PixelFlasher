#!/usr/bin/env python
"""Create a redacted diagnostics bundle for beta bug reports."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from platform_utils import app_data_dir, current_platform

try:
    from platformdirs import user_data_dir
except Exception:  # pragma: no cover
    user_data_dir = None

try:
    from constants import APPNAME, VERSION
except Exception:  # pragma: no cover
    APPNAME = "PixelFlasher"
    VERSION = "unknown"

MAX_COLLECTED_LOGS = 24


SERIAL_RE = re.compile(r"\b([A-Z0-9]{8,}|[a-f0-9]{16,})\b", re.IGNORECASE)
HOME = str(Path.home())
USER = os.environ.get("USERNAME") or os.environ.get("USER") or ""
HOSTNAME = socket.gethostname()


def redact(text: str) -> str:
    if not text:
        return text
    redacted = text
    replacements = {
        HOME: "<home>",
        USER: "<user>",
        HOSTNAME: "<host>",
    }
    for needle, replacement in replacements.items():
        if needle:
            redacted = redacted.replace(needle, replacement)
    redacted = SERIAL_RE.sub(lambda match: match.group(0)[:4] + "…redacted", redacted)
    return redacted


def _safe_read(path: Path, max_bytes: int = 400_000) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception as exc:
        return f"Could not read {path}: {exc}"


def config_root() -> Path:
    """Resolve the directory the application actually uses.

    The runtime resolves its configuration with ``roaming=True`` on Windows, so
    anything derived from the non-roaming default points at a directory
    PixelFlasher never writes to.
    """
    if user_data_dir is not None:
        return Path(user_data_dir(APPNAME, appauthor=False, roaming=True))
    return app_data_dir(APPNAME)


def _sorted_existing(directory: Path, pattern: str) -> list[Path]:
    try:
        candidates = [path for path in directory.glob(pattern) if path.is_file()]
    except OSError:
        return []
    # Newest first: session logs carry a sortable timestamp in their name.
    return sorted(candidates, reverse=True)


def _candidate_logs(root: Path) -> Iterable[Path]:
    collected = 0
    app_root = config_root()
    for directory, pattern in (
        (app_root / "logs", "*.log"),
        (app_root / "logs", "*.txt"),
        (app_root / "puml", "*.puml"),
    ):
        for candidate in _sorted_existing(directory, pattern):
            if collected >= MAX_COLLECTED_LOGS:
                return
            collected += 1
            yield candidate
    # Retain the 9.x layout so a bundle taken beside an upgraded install still
    # carries whatever the legacy build left behind.
    names = ["PixelFlasher.log", "puml.txt", "plantuml.txt"]
    locations = [root, Path.cwd(), Path.home()]
    for location in locations:
        for name in names:
            candidate = location / name
            if candidate.is_file():
                if collected >= MAX_COLLECTED_LOGS:
                    return
                collected += 1
                yield candidate


def _system_info() -> dict[str, object]:
    info = current_platform().to_dict()
    app_root = config_root()
    return {
        "app": APPNAME,
        "version": VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "executable": sys.executable,
        "platform_info": info,
        "config_dir": str(app_root),
        "data_dir": str(app_root),
        "log_dir": str(app_root / "logs"),
    }


def create_diagnostics_bundle(output: str | None = None) -> Path:
    root = Path(__file__).resolve().parent
    if output:
        out_path = Path(output).expanduser().resolve()
    else:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = Path.cwd() / f"PixelFlasher-diagnostics-{stamp}.zip"

    with tempfile.TemporaryDirectory(prefix="pf-diagnostics-") as tmp:
        tmp_path = Path(tmp)
        system_info = json.dumps(_system_info(), indent=2)
        (tmp_path / "system_info.json").write_text(redact(system_info), encoding="utf-8")

        from self_test import format_results, run_checks
        (tmp_path / "self_test.txt").write_text(redact(format_results(run_checks())), encoding="utf-8")

        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        for index, log_file in enumerate(_candidate_logs(root), start=1):
            safe_name = f"log_{index}_{log_file.name}"
            (log_dir / safe_name).write_text(redact(_safe_read(log_file)), encoding="utf-8")

        with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
            for path in tmp_path.rglob("*"):
                if path.is_file():
                    zipf.write(path, path.relative_to(tmp_path))

    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a redacted PixelFlasher diagnostics ZIP.")
    parser.add_argument("--output", "-o", help="output ZIP path")
    args = parser.parse_args(argv)
    out_path = create_diagnostics_bundle(args.output)
    print(f"Diagnostics bundle created: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
