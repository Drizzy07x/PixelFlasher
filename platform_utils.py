#!/usr/bin/env python
"""Cross-platform helpers for PixelFlasher.

The project historically had platform checks spread across UI and runtime code.
This module provides a small, testable compatibility layer that new code can use
first. Existing risky flashing logic can migrate here gradually.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

try:
    from platformdirs import user_config_dir, user_data_dir, user_log_dir
except Exception:  # pragma: no cover - optional dependency fallback
    user_config_dir = user_data_dir = user_log_dir = None  # type: ignore[assignment]

try:
    from constants import APPNAME
except Exception:  # pragma: no cover
    APPNAME = "PixelFlasher"


@dataclass(frozen=True)
class PlatformInfo:
    """Small serializable summary of the host OS."""

    system: str
    release: str
    version: str
    machine: str
    python: str
    executable: str
    is_windows: bool
    is_linux: bool
    is_macos: bool
    is_frozen: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def current_platform() -> PlatformInfo:
    system = platform.system()
    return PlatformInfo(
        system=system,
        release=platform.release(),
        version=platform.version(),
        machine=platform.machine(),
        python=platform.python_version(),
        executable=sys.executable,
        is_windows=system == "Windows",
        is_linux=system == "Linux",
        is_macos=system == "Darwin",
        is_frozen=bool(getattr(sys, "frozen", False)),
    )


def is_windows() -> bool:
    return current_platform().is_windows


def is_linux() -> bool:
    return current_platform().is_linux


def is_macos() -> bool:
    return current_platform().is_macos


def executable_name(name: str) -> str:
    """Return a platform-appropriate executable filename.

    `adb` becomes `adb.exe` on Windows and remains `adb` elsewhere.
    """

    if is_windows() and not name.lower().endswith(".exe"):
        return f"{name}.exe"
    return name


def repo_root() -> Path:
    return Path(__file__).resolve().parent


def app_config_dir(app_name: str = APPNAME) -> Path:
    if user_config_dir:
        return Path(user_config_dir(app_name, appauthor=False))
    return Path.home() / f".{app_name}"


def app_data_dir(app_name: str = APPNAME) -> Path:
    if user_data_dir:
        return Path(user_data_dir(app_name, appauthor=False))
    return Path.home() / f".{app_name}"


def app_log_dir(app_name: str = APPNAME) -> Path:
    if user_log_dir:
        return Path(user_log_dir(app_name, appauthor=False))
    return app_data_dir(app_name) / "logs"


def ensure_directory(path: str | Path) -> Path:
    directory = Path(path).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def make_executable(path: str | Path) -> bool:
    target = Path(path)
    if not target.exists() or is_windows():
        return target.exists()
    mode = target.stat().st_mode
    target.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return os.access(target, os.X_OK)


def resolve_executable(names: Iterable[str], extra_dirs: Sequence[str | Path] | None = None) -> Path | None:
    """Find an executable in explicit dirs first, then PATH."""

    normalized_names = []
    for name in names:
        normalized_names.append(name)
        if is_windows() and not name.lower().endswith(".exe"):
            normalized_names.append(f"{name}.exe")

    for directory in extra_dirs or []:
        base = Path(directory).expanduser()
        for name in normalized_names:
            candidate = base / name
            if candidate.is_file():
                return candidate.resolve()

    for name in normalized_names:
        found = shutil.which(name)
        if found:
            return Path(found).resolve()
    return None


def build_open_command(path: str | Path) -> list[str]:
    """Build the command used to open a file/folder without executing it."""

    target = str(Path(path).expanduser())
    if is_windows():
        # os.startfile is used at execution time, but this string is testable.
        return ["startfile", target]
    if is_macos():
        return ["open", target]
    return ["xdg-open", target]


def open_path(path: str | Path, *, dry_run: bool = False) -> list[str]:
    """Open a path in the platform default file manager.

    Returns the command shape for logging/tests. With `dry_run=True`, no process
    is started.
    """

    command = build_open_command(path)
    if dry_run:
        return command
    if command[0] == "startfile":  # pragma: no cover - Windows only
        os.startfile(command[1])  # type: ignore[attr-defined]
    else:  # pragma: no cover - do not open UI during automated tests
        subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return command


def default_shell() -> str:
    if is_windows():
        return os.environ.get("COMSPEC", "cmd.exe")
    return os.environ.get("SHELL", "/bin/sh")


def path_for_display(path: str | Path, *, home_token: str = "~") -> str:
    """Compact a path for UI display without changing the actual path."""

    try:
        p = Path(path).expanduser().resolve()
        home = Path.home().resolve()
        return str(p).replace(str(home), home_token, 1) if str(p).startswith(str(home)) else str(p)
    except Exception:
        return str(path)
