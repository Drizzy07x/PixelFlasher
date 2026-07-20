"""Primary PixelFlasher 10 startup.

The visible application is a native wx window containing the bundled React
document. Its engine is headless: this module never constructs or imports the
classic frame.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import wx
from platformdirs import user_data_dir

from constants import APPNAME, CONFIG_FILE_NAME
from pixelflasher_core import LEGACY_V9_DATABASE_NAME, ApplicationRuntime
from pixelflasher_core.patch_resources import (
    load_optional_packaged_patch_resource_registry,
)
from pixelflasher_core.platform_tools_distribution import (
    load_optional_platform_tools_distribution,
)
from pixelflasher_core.root_app_distribution import (
    load_optional_root_app_distribution,
)
from platform_utils import repo_root
from ui.core_command_factory import create_command_factory
from ui.pages.modern_webview_host import (
    create_modern_webview_frame,
    frontend_index_path,
    is_webview_available,
)
from ui_smoke_contract import write_ui_smoke_receipt


@dataclass(frozen=True, slots=True)
class UiSmokeOptions:
    report_path: Path
    timeout_seconds: int = 30


def launch_modern_primary(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(argv or ())
    try:
        smoke_options = _ui_smoke_options_from_argv(arguments)
    except ValueError as exc:
        print(f"PixelFlasher UI smoke options are invalid: {exc}")
        return 2

    if not is_webview_available():
        print("PixelFlasher requires the platform WebView runtime.")
        return 1

    try:
        index_path = frontend_index_path()
    except Exception as exc:
        print(f"PixelFlasher React application is unavailable: {exc}")
        return 1

    config_path = _config_path_from_argv(arguments)
    runtime: ApplicationRuntime | None = None
    app: wx.App | None = None
    frame: wx.Frame | None = None
    smoke_timer: object | None = None
    bridge_revision: int | None = None
    smoke_timed_out = False
    try:
        system_data_root = Path(user_data_dir(APPNAME, appauthor=False, roaming=True))
        platform_tools_distribution = load_optional_platform_tools_distribution(
            repo_root() / "resources" / "platform-tools" / "runtime"
        )
        root_app_distribution = load_optional_root_app_distribution(
            repo_root() / "resources" / "root-apps" / "runtime"
        )
        patch_resource_registry = load_optional_packaged_patch_resource_registry(
            repo_root()
        )
        runtime = ApplicationRuntime.open(
            config_path,
            enable_device_monitor=True,
            legacy_database_path=system_data_root / LEGACY_V9_DATABASE_NAME,
            platform_tools_catalog=(
                platform_tools_distribution.catalog
                if platform_tools_distribution is not None
                else None
            ),
            platform_tools_downloader=(
                platform_tools_distribution.downloader
                if platform_tools_distribution is not None
                else None
            ),
            patch_resource_registry=patch_resource_registry,
            root_app_catalog=(
                root_app_distribution.catalog
                if root_app_distribution is not None
                else None
            ),
            root_app_downloader=(
                root_app_distribution.downloader
                if root_app_distribution is not None
                else None
            ),
        )
        app = wx.App(False)

        def bridge_ready(revision: int) -> None:
            nonlocal bridge_revision
            bridge_revision = revision
            if frame is not None:
                # Queue closure after the bridge response and snapshot scripts.
                # Smoke mode owns this isolated process, so background device
                # discovery must not veto the proof after React is ready.
                wx.CallAfter(frame.Close, True)

        frame = create_modern_webview_frame(
            runtime.engine,
            adb_terminal_service=runtime.adb_terminal_service,
            command_factory=create_command_factory(runtime.engine.snapshot),
            support_destination_registrar=runtime.register_support_destination,
            application_directories=_application_directories_for_config(config_path),
            bridge_ready_callback=bridge_ready if smoke_options is not None else None,
            index_path=index_path,
        )
        # Keep lifecycle owners reachable for the duration of the native loop.
        app._pixelflasher_runtime = runtime  # type: ignore[attr-defined]
        app._pixelflasher_frame = frame  # type: ignore[attr-defined]
        frame.Show(True)
        frame.Raise()
        if smoke_options is not None:
            def smoke_timeout() -> None:
                nonlocal smoke_timed_out
                smoke_timed_out = True
                if frame is not None:
                    frame.Close(True)

            smoke_timer = wx.CallLater(smoke_options.timeout_seconds * 1000, smoke_timeout)
        app.MainLoop()
        if smoke_timer is not None:
            smoke_timer.Stop()  # type: ignore[attr-defined]
        runtime.shutdown()
        if smoke_options is not None:
            if bridge_revision is None:
                reason = "timed out" if smoke_timed_out else "closed before becoming ready"
                print(f"PixelFlasher UI smoke {reason}.")
                return 1
            write_ui_smoke_receipt(
                smoke_options.report_path,
                bridge_revision=bridge_revision,
            )
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


def _ui_smoke_options_from_argv(argv: tuple[str, ...]) -> UiSmokeOptions | None:
    report_value: str | None = None
    timeout_value: str | None = None
    index = 1
    while index < len(argv):
        argument = str(argv[index])
        if argument.startswith("--ui-smoke-report="):
            if report_value is not None:
                raise ValueError("--ui-smoke-report can only be provided once")
            report_value = argument.partition("=")[2].strip()
        elif argument == "--ui-smoke-report":
            if report_value is not None:
                raise ValueError("--ui-smoke-report can only be provided once")
            index += 1
            if index >= len(argv):
                raise ValueError("--ui-smoke-report requires a destination")
            report_value = str(argv[index]).strip()
        elif argument.startswith("--ui-smoke-timeout="):
            if timeout_value is not None:
                raise ValueError("--ui-smoke-timeout can only be provided once")
            timeout_value = argument.partition("=")[2].strip()
        elif argument == "--ui-smoke-timeout":
            if timeout_value is not None:
                raise ValueError("--ui-smoke-timeout can only be provided once")
            index += 1
            if index >= len(argv):
                raise ValueError("--ui-smoke-timeout requires seconds")
            timeout_value = str(argv[index]).strip()
        index += 1

    if report_value is None:
        if timeout_value is not None:
            raise ValueError("--ui-smoke-timeout requires --ui-smoke-report")
        return None
    if not report_value:
        raise ValueError("--ui-smoke-report requires a non-empty destination")
    try:
        timeout_seconds = 30 if timeout_value is None else int(timeout_value)
    except ValueError as exc:
        raise ValueError("--ui-smoke-timeout must be an integer") from exc
    if not 5 <= timeout_seconds <= 120:
        raise ValueError("--ui-smoke-timeout must be between 5 and 120 seconds")
    return UiSmokeOptions(
        report_path=Path(report_value).expanduser().absolute(),
        timeout_seconds=timeout_seconds,
    )


def _application_directories_for_config(config_path: Path) -> dict[str, Path]:
    """Create only backend-owned shell folders and keep their paths out of React."""

    root = config_path.expanduser().absolute().parent
    directories = {
        "configuration": root,
        "logs": root / "logs",
        "cache": root / f".{config_path.name}.cache",
    }
    for directory in directories.values():
        if directory.exists():
            continue
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError:
            # Startup remains available. The host returns a typed unavailable
            # result if the user later asks to open this directory.
            pass
    return directories


__all__ = ["UiSmokeOptions", "launch_modern_primary"]
