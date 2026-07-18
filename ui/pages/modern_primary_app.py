"""Primary PixelFlasher 10 startup.

The visible application is a native wx window containing the bundled React
document. Its engine is headless: this module never constructs or imports the
classic frame.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from platformdirs import user_data_dir
import wx

from constants import APPNAME, CONFIG_FILE_NAME
from pixelflasher_core import ApplicationRuntime
from ui.core_command_factory import create_command_factory
from ui.pages.modern_webview_host import (
    create_modern_webview_frame,
    frontend_index_path,
    is_webview_available,
)


def launch_modern_primary(argv: Sequence[str] | None = None) -> int:
    if not is_webview_available():
        print("PixelFlasher requires the platform WebView runtime.")
        return 1

    try:
        index_path = frontend_index_path()
    except Exception as exc:
        print(f"PixelFlasher React application is unavailable: {exc}")
        return 1

    config_path = _config_path_from_argv(tuple(argv or ()))
    runtime: ApplicationRuntime | None = None
    app: wx.App | None = None
    frame: wx.Frame | None = None
    try:
        runtime = ApplicationRuntime.open(config_path)
        app = wx.App(False)
        frame = create_modern_webview_frame(
            runtime,
            command_factory=create_command_factory(runtime.snapshot),
            index_path=index_path,
        )
        # Keep lifecycle owners reachable for the duration of the native loop.
        app._pixelflasher_runtime = runtime  # type: ignore[attr-defined]
        app._pixelflasher_frame = frame  # type: ignore[attr-defined]
        frame.Show(True)
        frame.Raise()
        app.MainLoop()
        runtime.shutdown()
        return 0
    except Exception as exc:
        print(f"PixelFlasher startup failed: {exc}")
        if frame is not None:
            frame.Destroy()
        if runtime is not None:
            runtime.shutdown()
        return 1


def _config_path_from_argv(argv: tuple[str, ...]) -> Path:
    """Resolve the supported explicit config override without argparse side effects."""

    for index, argument in enumerate(argv[1:], start=1):
        if argument.startswith("--config="):
            value = argument.partition("=")[2].strip()
            if value:
                return Path(value).expanduser().resolve()
        if argument == "--config" and index + 1 < len(argv):
            value = str(argv[index + 1]).strip()
            if value:
                return Path(value).expanduser().resolve()
    return Path(user_data_dir(APPNAME, appauthor=False, roaming=True)) / CONFIG_FILE_NAME


__all__ = ["launch_modern_primary"]
