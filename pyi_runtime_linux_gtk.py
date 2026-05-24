"""PyInstaller Linux GTK runtime isolation.

Ubuntu 26.04 and newer systems can try to load host GVFS/GIO modules into the
PyInstaller process. When the packaged app carries GTK/GIO-related libraries
from an older build host, loading host modules can print symbol errors such as:

    libgvfscommon.so: undefined symbol: g_variant_builder_init_static
    Failed to load module: libgvfsdbus.so

PixelFlasher only needs local file dialogs for the beta package, so force local
GIO VFS and point GIO modules at an empty directory before wx/GTK is imported.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

if sys.platform.startswith("linux"):
    os.environ.setdefault("GIO_USE_VFS", "local")

    base = Path(getattr(sys, "_MEIPASS", tempfile.gettempdir()))
    gio_modules = base / "empty-gio-modules"
    try:
        gio_modules.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("GIO_MODULE_DIR", str(gio_modules))
    except Exception:
        # Best-effort only. Never block startup because of log suppression.
        pass
