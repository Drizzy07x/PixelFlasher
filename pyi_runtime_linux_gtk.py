"""PyInstaller Linux GTK runtime isolation.

Keeps Linux beta packages from loading incompatible host GVFS/GIO modules and
filters known harmless GTK/wxPython stderr noise that appears on some
Ubuntu/GNOME setups. This hook runs before wx/GTK is imported.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
from pathlib import Path

_KNOWN_GTK_NOISE = (
    "gtk_image_menu_item_set_image",
    "GTK_IS_IMAGE_MENU_ITEM",
    "gtk_box_gadget_distribute",
    "GtkScrollbar",
    "Negative content width",
    "Negative content height",
    "while allocating gadget",
    "GLib-GIO-WARNING",
    "Error creating IO channel for /proc/self/mountinfo",
    "g-io-error-quark",
    "libgvfscommon.so: undefined symbol",
    "Failed to load module: /usr/lib",
    "libgvfsdbus.so",
    "wxMenuBar@",
    "lost focus even though it didn't have it",
)


def _filter_known_stderr_noise() -> None:
    if os.environ.get("PIXELFLASHER_FILTER_GTK_WARNINGS", "1") in {"0", "false", "False"}:
        return
    if not sys.platform.startswith("linux"):
        return
    try:
        original_fd = os.dup(2)
        read_fd, write_fd = os.pipe()
        os.dup2(write_fd, 2)
        os.close(write_fd)
    except Exception:
        return

    def pump() -> None:
        with os.fdopen(read_fd, "rb", closefd=True) as reader:
            pending = b""
            while True:
                chunk = reader.readline()
                if not chunk:
                    if pending:
                        _write_if_not_noise(original_fd, pending)
                    break
                _write_if_not_noise(original_fd, chunk)

    def _write_if_not_noise(fd: int, data: bytes) -> None:
        text = data.decode("utf-8", "replace")
        if any(pattern in text for pattern in _KNOWN_GTK_NOISE):
            return
        try:
            os.write(fd, data)
        except Exception:
            pass

    thread = threading.Thread(target=pump, name="pf-stderr-filter", daemon=True)
    thread.start()


if sys.platform.startswith("linux"):
    os.environ.setdefault("GIO_USE_VFS", "local")
    os.environ.setdefault("NO_AT_BRIDGE", "1")
    os.environ.setdefault("G_ENABLE_DIAGNOSTIC", "0")

    base = Path(getattr(sys, "_MEIPASS", tempfile.gettempdir()))
    gio_modules = base / "empty-gio-modules"
    try:
        gio_modules.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("GIO_MODULE_DIR", str(gio_modules))
    except Exception:
        pass

    _filter_known_stderr_noise()
