"""Primary Modern UI startup wrapper with safe legacy fallback."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

import wx

from ui.pages.modern_preview_web import create_modern_preview_frame, is_webview_available


OPEN_LEGACY_EXIT_CODE = 2


def legacy_override_requested(argv: Sequence[str] | None = None, env: dict[str, str] | None = None) -> bool:
    args = tuple(argv or ())
    values = env if env is not None else os.environ
    return "--legacy-ui" in args or values.get("PIXELFLASHER_LEGACY_UI") == "1"


def launch_modern_primary(argv: Sequence[str] | None = None) -> int:
    if legacy_override_requested(argv or sys.argv):
        return OPEN_LEGACY_EXIT_CODE
    if not is_webview_available():
        return OPEN_LEGACY_EXIT_CODE

    app = wx.App(False)
    legacy_requested = {"value": False}

    def request_legacy() -> None:
        legacy_requested["value"] = True
        frame = getattr(app, "_modern_primary_frame", None)
        if frame is not None:
            frame.Close()
        app.ExitMainLoop()

    frame = create_modern_preview_frame(page="dashboard", parent=None, on_open_legacy=request_legacy)
    if frame is None:
        return OPEN_LEGACY_EXIT_CODE

    app._modern_primary_frame = frame  # type: ignore[attr-defined]
    frame.Show(True)
    frame.Raise()
    app.MainLoop()
    return OPEN_LEGACY_EXIT_CODE if legacy_requested["value"] else 0
