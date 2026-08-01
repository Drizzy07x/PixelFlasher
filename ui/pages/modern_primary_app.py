"""Primary PixelFlasher 10 startup.

The visible application is a native wx window containing the bundled React
document. Its engine is headless: this module never constructs or imports the
classic frame.
"""

from __future__ import annotations

import ctypes
import logging
import sys
import tempfile
import threading
import traceback
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TextIO

import wx
from platformdirs import user_data_dir

from constants import APPNAME, CONFIG_FILE_NAME, VERSION
from pixelflasher_core import LEGACY_V9_DATABASE_NAME, ApplicationRuntime
from pixelflasher_core.contracts import (
    OperationFinished,
    OperationResult,
    OperationStatus,
    ProgressEvent,
)
from pixelflasher_core.firmware_distribution import (
    load_optional_firmware_distribution,
)
from pixelflasher_core.keybox_distribution import (
    load_optional_keybox_revocations,
)
from pixelflasher_core.patch_resources import (
    load_optional_packaged_patch_resource_registry,
)
from pixelflasher_core.platform_tools_distribution import (
    load_optional_platform_tools_distribution,
)
from pixelflasher_core.root_app_distribution import (
    load_optional_root_app_distribution,
)
from pixelflasher_core.scrcpy_distribution import (
    load_optional_scrcpy_distribution,
)
from pixelflasher_core.support_distribution import (
    load_optional_support_recipient,
)
from pixelflasher_core.update_distribution import (
    load_optional_update_distribution,
)
from platform_utils import repo_root
from ui.core_command_factory import create_command_factory
from ui.pages.modern_webview_host import (
    create_modern_webview_frame,
    frontend_index_path,
    is_webview_available,
)
from ui_smoke_contract import write_ui_smoke_receipt

_SESSION_LOG_RETENTION = 10
_STARTUP_ERROR_LOG_NAME = "PixelFlasher-startup-error.log"
_SESSION_EVENT_LOGGER_NAME = "pixelflasher.operations"


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

    config_path = _config_path_from_argv(arguments)
    application_directories = _application_directories_for_config(config_path)
    session_log = _open_session_log(application_directories["logs"])
    # A smoke run owns a headless process, so it must never raise a modal dialog.
    interactive = smoke_options is None
    try:
        return _launch(
            config_path,
            application_directories,
            smoke_options,
            interactive=interactive,
        )
    finally:
        if session_log is not None:
            session_log.close()


def _launch(
    config_path: Path,
    application_directories: dict[str, Path],
    smoke_options: UiSmokeOptions | None,
    *,
    interactive: bool,
) -> int:
    if not is_webview_available():
        _report_startup_failure(
            "PixelFlasher requires the platform WebView runtime.",
            None,
            interactive=interactive,
        )
        return 1

    try:
        index_path = frontend_index_path()
    except Exception as exc:
        _report_startup_failure(
            f"PixelFlasher React application is unavailable: {exc}",
            exc,
            interactive=interactive,
        )
        return 1

    runtime: ApplicationRuntime | None = None
    app: wx.App | None = None
    frame: wx.Frame | None = None
    smoke_timer: object | None = None
    bridge_revision: int | None = None
    ui_smoke_journey: dict[str, object] | None = None
    ui_smoke_error: str | None = None
    smoke_timed_out = False
    try:
        system_data_root = Path(user_data_dir(APPNAME, appauthor=False, roaming=True))
        distribution_failures: list[str] = []
        platform_tools_distribution = _load_optional_distribution(
            "platform-tools",
            lambda: load_optional_platform_tools_distribution(
                repo_root() / "resources" / "platform-tools" / "runtime"
            ),
            distribution_failures,
        )
        root_app_distribution = _load_optional_distribution(
            "root-apps",
            lambda: load_optional_root_app_distribution(repo_root() / "resources" / "root-apps" / "runtime"),
            distribution_failures,
        )
        firmware_distribution = _load_optional_distribution(
            "firmware",
            lambda: load_optional_firmware_distribution(repo_root() / "resources" / "firmware" / "runtime"),
            distribution_failures,
        )
        scrcpy_distribution = _load_optional_distribution(
            "scrcpy",
            lambda: load_optional_scrcpy_distribution(repo_root() / "resources" / "scrcpy" / "runtime"),
            distribution_failures,
        )
        update_distribution = _load_optional_distribution(
            "updates",
            lambda: load_optional_update_distribution(
                repo_root() / "resources" / "updates" / "runtime" / "manifest.json"
            ),
            distribution_failures,
        )
        support_recipient = _load_optional_distribution(
            "support",
            lambda: load_optional_support_recipient(
                repo_root() / "resources" / "support" / "recipient-public-key.pem"
            ),
            distribution_failures,
        )
        keybox_revocations = _load_optional_distribution(
            "keybox",
            lambda: load_optional_keybox_revocations(repo_root() / "resources" / "keybox" / "revocations.json"),
            distribution_failures,
        )
        patch_resource_registry = _load_optional_distribution(
            "patch-resources",
            lambda: load_optional_packaged_patch_resource_registry(repo_root()),
            distribution_failures,
        )
        if distribution_failures:
            # Keep tampering distinguishable from "not provisioned": the codes stay
            # on the record even though the launch continues without the catalogs.
            # The packaged console is hidden, so print() alone reaches nobody: the
            # codes also go to the durable startup log the failure dialog cites.
            summary = "PixelFlasher official downloads unavailable: " + ", ".join(distribution_failures)
            print(summary)
            logging.getLogger(_SESSION_EVENT_LOGGER_NAME).warning(summary)
            _append_startup_error_log(summary)
        runtime = ApplicationRuntime.open(
            config_path,
            enable_device_monitor=True,
            legacy_database_path=system_data_root / LEGACY_V9_DATABASE_NAME,
            platform_tools_catalog=(
                platform_tools_distribution.catalog if platform_tools_distribution is not None else None
            ),
            platform_tools_downloader=(
                platform_tools_distribution.downloader if platform_tools_distribution is not None else None
            ),
            patch_resource_registry=patch_resource_registry,
            root_app_catalog=(root_app_distribution.catalog if root_app_distribution is not None else None),
            root_app_downloader=(root_app_distribution.downloader if root_app_distribution is not None else None),
            firmware_catalog=(firmware_distribution.catalog if firmware_distribution is not None else None),
            firmware_downloader=(firmware_distribution.downloader if firmware_distribution is not None else None),
            scrcpy_catalog=(scrcpy_distribution.catalog if scrcpy_distribution is not None else None),
            scrcpy_downloader=(scrcpy_distribution.downloader if scrcpy_distribution is not None else None),
            update_manifest_source=(update_distribution.source if update_distribution is not None else None),
            update_manifest_verifier=(update_distribution.verifier if update_distribution is not None else None),
            support_recipient_public_key=(support_recipient.public_key_pem if support_recipient is not None else None),
            support_key_id=(support_recipient.key_id if support_recipient is not None else None),
            keybox_revocation_provider=(keybox_revocations.provider if keybox_revocations is not None else None),
        )
        # Without this the session log records nothing but this module's own
        # prints, so a support package proves nothing about the session it
        # documents. The runtime event stream is the one seam that already sees
        # every command's progress and its terminal outcome.
        runtime.subscribe(_SessionEventRecorder())
        app = wx.App(False)

        def bridge_ready(revision: int) -> None:
            nonlocal bridge_revision
            bridge_revision = revision
            if frame is not None:
                wx.CallAfter(frame.run_packaged_ui_smoke, ui_journey_complete)

        def ui_journey_complete(
            journey: dict[str, object] | None,
            error: str | None,
        ) -> None:
            nonlocal ui_smoke_journey, ui_smoke_error
            ui_smoke_journey = journey
            ui_smoke_error = error
            if frame is not None:
                # Smoke mode owns this isolated process, so background device
                # discovery must not veto shutdown after the journey finishes.
                wx.CallAfter(frame.Close, True)

        frame = create_modern_webview_frame(
            runtime.engine,
            adb_terminal_service=runtime.adb_terminal_service,
            command_factory=create_command_factory(runtime.engine.snapshot),
            support_destination_registrar=runtime.register_support_destination,
            application_directories=application_directories,
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
            if ui_smoke_journey is None:
                reason = ui_smoke_error or "closed before completing the UI journey"
                print(f"PixelFlasher UI smoke failed: {reason}.")
                return 1
            write_ui_smoke_receipt(
                smoke_options.report_path,
                bridge_revision=bridge_revision,
                journey=ui_smoke_journey,
            )
        return 0
    except Exception as exc:
        # Release the device first: reporting blocks on a modal dialog for an
        # unbounded time, and a live runtime keeps polling the attached handset
        # for as long as nobody clicks OK. The detail still reaches the session
        # log, which is closed by the caller only after this returns.
        if frame is not None:
            with suppress(Exception):
                frame.Destroy()
        if runtime is not None:
            with suppress(Exception):
                runtime.shutdown()
        _report_startup_failure(f"PixelFlasher startup failed: {exc}", exc, interactive=interactive)
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


def _load_optional_distribution[LoadedT](
    label: str,
    loader: Callable[[], LoadedT | None],
    failures: list[str],
) -> LoadedT | None:
    """Degrade one unverifiable packaged distribution instead of aborting the launch."""

    try:
        return loader()
    except Exception as exc:
        code = str(getattr(exc, "code", "")) or type(exc).__name__
        failures.append(f"{label}: {code}")
        return None


class _TeeStream:
    """Mirror interpreter output into the session log without owning either stream."""

    def __init__(self, primary: TextIO | None, mirror: TextIO) -> None:
        self._primary = primary
        self._mirror = mirror

    def write(self, text: str) -> int:
        for stream in (self._primary, self._mirror):
            if stream is None:
                continue
            try:
                stream.write(text)
            except (OSError, ValueError):
                continue
        return len(text)

    def writelines(self, lines: object) -> None:
        for line in lines:  # type: ignore[attr-defined]
            self.write(str(line))

    def flush(self) -> None:
        for stream in (self._primary, self._mirror):
            if stream is None:
                continue
            try:
                stream.flush()
            except (OSError, ValueError):
                continue

    def isatty(self) -> bool:
        return False

    def __getattr__(self, name: str) -> object:
        # Everything else (encoding, fileno, buffer) belongs to the real stream.
        return getattr(self._primary, name)


class _SessionEventRecorder:
    """Turn the runtime event stream into the session log's producer.

    Every command publishes an ``OperationFinished`` and long-running ones also
    publish progress, so the recorded narrative is what a support package needs:
    which operation ran, against which device, and how it ended.
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger(_SESSION_EVENT_LOGGER_NAME)
        self._lock = threading.Lock()
        self._last_progress = ""

    def __call__(self, event: object) -> None:
        if isinstance(event, ProgressEvent):
            self._record_progress(event)
        elif isinstance(event, OperationFinished):
            self._record_result(event.result)

    def _record_progress(self, event: ProgressEvent) -> None:
        line = f"{event.kind or 'operation'} {event.operation_id} {event.phase}"
        if event.target_serial:
            line = f"{line} [{event.target_serial}]"
        if event.message:
            line = f"{line}: {event.message}"
        with self._lock:
            # Percent-driven updates repeat the same text hundreds of times per
            # flash; one line per distinct step keeps the log collectible.
            if line == self._last_progress:
                return
            self._last_progress = line
        self._logger.info(line)

    def _record_result(self, result: OperationResult) -> None:
        line = f"operation {result.operation_id} {result.status} {result.code}"
        if result.message:
            line = f"{line}: {result.message}"
        # Only the user-facing message is recorded; stdout/stderr may carry
        # device contents that no support package should ship unredacted.
        self._logger.log(
            logging.INFO if result.status is OperationStatus.SUCCESS else logging.WARNING,
            line,
        )


class _SessionLog:
    """Own the per-session log file and the sinks that feed it."""

    def __init__(self, path: Path, stream: TextIO) -> None:
        self.path = path
        self._stream = stream
        self._handler = logging.StreamHandler(stream)
        self._handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        self._root = logging.getLogger()
        self._previous_level = self._root.level
        self._root.addHandler(self._handler)
        if self._previous_level == logging.NOTSET or self._previous_level > logging.INFO:
            self._root.setLevel(logging.INFO)
        self._previous_stdout = sys.stdout
        self._previous_stderr = sys.stderr
        sys.stdout = _TeeStream(self._previous_stdout, stream)  # type: ignore[assignment]
        sys.stderr = _TeeStream(self._previous_stderr, stream)  # type: ignore[assignment]

    def close(self) -> None:
        sys.stdout = self._previous_stdout
        sys.stderr = self._previous_stderr
        self._root.removeHandler(self._handler)
        self._root.setLevel(self._previous_level)
        try:
            self._handler.close()
        except (OSError, ValueError):
            pass
        try:
            self._stream.close()
        except (OSError, ValueError):
            pass


def _open_session_log(logs_directory: Path) -> _SessionLog | None:
    """Record this session where the support package and the user both look."""

    try:
        logs_directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    _prune_session_logs(logs_directory)
    stem = f"{APPNAME}_{datetime.now():%Y-%m-%d_%Hh%Mm%Ss}"
    for attempt in range(1, 10):
        candidate = logs_directory / (f"{stem}.log" if attempt == 1 else f"{stem}_{attempt}.log")
        try:
            stream = candidate.open("x", buffering=1, encoding="utf-8", errors="replace")
        except FileExistsError:
            continue
        except OSError:
            return None
        session_log = _SessionLog(candidate, stream)
        print(f"{APPNAME} {VERSION} session started {datetime.now():%Y-%m-%d %H:%M:%S}")
        return session_log
    return None


def _prune_session_logs(logs_directory: Path, keep: int = _SESSION_LOG_RETENTION) -> None:
    """Keep the log directory bounded so support packages stay under their file limits."""

    try:
        # The timestamped names sort chronologically, so plain name order is enough.
        existing = sorted(path for path in logs_directory.glob(f"{APPNAME}_*.log") if path.is_file())
    except OSError:
        return
    for path in existing[: max(0, len(existing) - keep + 1)]:
        try:
            path.unlink()
        except OSError:
            # A concurrent instance still holds this file; leaving it is harmless.
            continue


def _report_startup_failure(
    summary: str,
    exc: BaseException | None,
    *,
    interactive: bool,
) -> None:
    """Make a startup failure reachable when the packaged console is hidden."""

    detail = summary
    if exc is not None:
        detail = summary + "\n" + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    # The session log receives this through the stdout tee installed at launch.
    print(detail)
    startup_log = _append_startup_error_log(detail)
    if not interactive:
        return
    message = summary if startup_log is None else f"{summary}\n\nDetails were written to:\n{startup_log}"
    _show_startup_failure_dialog(message)


def _append_startup_error_log(detail: str) -> Path | None:
    path = Path(tempfile.gettempdir()) / _STARTUP_ERROR_LOG_NAME
    try:
        with path.open("a", encoding="utf-8", errors="replace") as log:
            log.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {detail}\n")
    except OSError:
        return None
    return path


def _show_startup_failure_dialog(message: str) -> None:
    """Use the OS dialog: wx may be exactly what failed, and there is no wx.App yet."""

    if sys.platform != "win32":
        return
    try:
        ctypes.windll.user32.MessageBoxW(None, message, f"{APPNAME} startup failed", 0x10)
    except Exception:
        pass


__all__ = ["UiSmokeOptions", "launch_modern_primary"]
