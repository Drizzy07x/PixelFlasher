"""Primary Modern UI startup wrapper."""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from types import SimpleNamespace

import wx

from ui.pages.modern_preview_web import create_modern_preview_frame, is_webview_available


def launch_modern_primary(argv: Sequence[str] | None = None) -> int:
    _ = argv
    if not is_webview_available():
        print("Modern UI WebView is not available.")
        return 1

    app = wx.App(False)
    engine = _create_hidden_engine()
    frame = create_modern_preview_frame(page="dashboard", parent=None, state_host=engine)
    if frame is None:
        if engine is not None:
            engine.Destroy()
        return 1

    app._modern_primary_frame = frame  # type: ignore[attr-defined]
    app._modern_engine_frame = engine  # type: ignore[attr-defined]

    def on_close(event: wx.CloseEvent) -> None:
        if engine is not None:
            engine.Destroy()
        event.Skip()
        wx.CallAfter(app.ExitMainLoop)

    frame.Bind(wx.EVT_CLOSE, on_close)
    frame.Show(True)
    frame.Raise()
    app.MainLoop()
    return 0


def _create_hidden_engine() -> wx.Frame:
    os.environ["PIXELFLASHER_MODERN_ENGINE"] = "1"
    import Main

    Main.global_args = SimpleNamespace(config=None, console=False, console_only=False)
    Main.init_config_path()
    timestamp = time.strftime("%Y-%m-%d_%Hh%Mm%Ss")
    pumlfile = os.path.join(Main.get_config_path(), "puml", f"PixelFlasher_{timestamp}.puml")
    Main.set_pumlfile(pumlfile)
    Main.puml(f"@startuml {timestamp}\nscale 2\nstart\n", False, "w")
    Main.puml("<style>\n  note {\n    FontName Courier\n    FontSize 10\n  }\n</style>\n")
    frame = Main.PixelFlasher(None, "PixelFlasher")
    frame.Hide()
    return frame
