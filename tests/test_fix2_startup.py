"""Round-2 regression tests for the startup/diagnostics packet.

Covers IMPORTANT-09 (the session log had no producers), IMPORTANT-10 (the
entrypoint dialog could hang a headless CI run), IMPORTANT-11 (the startup
failure modal blocked ahead of runtime shutdown), IMPORTANT-12 (degraded
distributions were only printed) and IMPORTANT-16 (a killed daemon download
thread left a truncated file under the user's chosen name).
"""

from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import Main
from pixelflasher_core import ApplicationRuntime
from pixelflasher_core.contracts import AppCommand
from ui.pages import modern_primary_app

REPO_ROOT = Path(__file__).resolve().parent.parent


class _Stop(Exception):
    """Marker raised in place of the real runtime so no engine is constructed."""


class _FakeRuntime:
    """Stand in for ApplicationRuntime without opening repositories or a poller."""

    def __init__(self, order: list[str]) -> None:
        self._order = order
        self.listeners: list[object] = []
        self.engine = SimpleNamespace(snapshot=lambda: object())
        self.adb_terminal_service = object()

    def register_support_destination(self, path: object) -> None:
        return None

    def subscribe(self, listener: object, **_: object):
        self.listeners.append(listener)
        return lambda: None

    def shutdown(self) -> None:
        self._order.append("shutdown")


def _launch_with_fake_runtime(directory: str, order: list[str], **overrides):
    runtime = _FakeRuntime(order)

    class _Opener:
        @staticmethod
        def open(config_path: Path, **kwargs: object) -> _FakeRuntime:
            return runtime

    patches = [
        patch("tempfile.gettempdir", return_value=directory),
        patch.object(modern_primary_app, "is_webview_available", return_value=True),
        patch.object(modern_primary_app, "frontend_index_path", return_value=Path("index.html")),
        patch.object(modern_primary_app, "ApplicationRuntime", _Opener),
        patch.object(modern_primary_app, "create_command_factory", lambda snapshot: object()),
        patch.object(modern_primary_app.wx, "App", MagicMock()),
        patch.object(
            modern_primary_app,
            "create_modern_webview_frame",
            side_effect=overrides.get("frame_error", RuntimeError("frame boom")),
        ),
        patch.object(modern_primary_app, "_show_startup_failure_dialog", lambda message: order.append("dialog")),
    ]
    with contextlib.ExitStack() as stack:
        for item in patches:
            stack.enter_context(item)
        result = modern_primary_app._launch(
            Path(directory) / "PixelFlasher.json",
            {"logs": Path(directory) / "logs"},
            None,
            interactive=overrides.get("interactive", True),
        )
    return runtime, result


# -----------------------------------------------------------------------------
#  IMPORTANT-09  the session log had no producers, so it proved nothing
# -----------------------------------------------------------------------------
class SessionLogProducerTests(unittest.TestCase):
    def test_runtime_events_reach_the_session_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = ApplicationRuntime.open(root / "PixelFlasher.json")
            session_log = modern_primary_app._open_session_log(root / "logs")
            assert session_log is not None
            try:
                runtime.subscribe(modern_primary_app._SessionEventRecorder())
                result = runtime.engine.execute(
                    AppCommand("unsupported", operation_id="session-log-proof")
                )
            finally:
                session_log.close()
                runtime.shutdown()

            written = session_log.path.read_text(encoding="utf-8")
            self.assertFalse(result.ok)
            self.assertIn("session-log-proof", written)
            self.assertIn(str(result.status), written)
            self.assertIn(result.code, written)

    def test_launch_feeds_the_session_log_from_the_runtime_event_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime, _ = _launch_with_fake_runtime(directory, [])

            self.assertTrue(
                any(
                    isinstance(listener, modern_primary_app._SessionEventRecorder)
                    for listener in runtime.listeners
                ),
                "the launch installed no session log producer",
            )

    def test_repeated_progress_text_is_recorded_once_but_outcomes_always(self):
        from pixelflasher_core.contracts import (
            OperationFinished,
            OperationResult,
            ProgressEvent,
            ProgressPhase,
        )

        with tempfile.TemporaryDirectory() as directory:
            session_log = modern_primary_app._open_session_log(Path(directory) / "logs")
            assert session_log is not None
            recorder = modern_primary_app._SessionEventRecorder()
            try:
                for _ in range(3):
                    recorder(
                        ProgressEvent(
                            "op-1",
                            ProgressPhase.RUNNING,
                            "writing boot",
                            50,
                            kind="flash.execute",
                            target_serial="ABC123",
                        )
                    )
                recorder(
                    OperationFinished(
                        OperationResult.failed("op-1", code="flash_failed", message="device rejected the image")
                    )
                )
            finally:
                session_log.close()

            written = session_log.path.read_text(encoding="utf-8")
            self.assertEqual(1, written.count("writing boot"))
            self.assertIn("flash.execute op-1", written)
            self.assertIn("ABC123", written)
            self.assertIn("flash_failed", written)


# -----------------------------------------------------------------------------
#  IMPORTANT-11  the modal blocked while the runtime kept polling the device
# -----------------------------------------------------------------------------
class StartupFailureCleanupOrderTests(unittest.TestCase):
    def test_runtime_is_shut_down_before_the_modal_dialog_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            order: list[str] = []
            with contextlib.redirect_stdout(io.StringIO()):
                _, result = _launch_with_fake_runtime(directory, order)

            self.assertEqual(1, result)
            self.assertEqual(["shutdown", "dialog"], order)

    def test_a_failing_shutdown_still_reports_the_startup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            order: list[str] = []
            runtime = _FakeRuntime(order)

            def explode() -> None:
                order.append("shutdown")
                raise RuntimeError("shutdown boom")

            runtime.shutdown = explode  # type: ignore[method-assign]

            class _Opener:
                @staticmethod
                def open(config_path: Path, **kwargs: object) -> _FakeRuntime:
                    return runtime

            with (
                patch("tempfile.gettempdir", return_value=directory),
                patch.object(modern_primary_app, "is_webview_available", return_value=True),
                patch.object(modern_primary_app, "frontend_index_path", return_value=Path("index.html")),
                patch.object(modern_primary_app, "ApplicationRuntime", _Opener),
                patch.object(modern_primary_app, "create_command_factory", lambda snapshot: object()),
                patch.object(modern_primary_app.wx, "App", MagicMock()),
                patch.object(
                    modern_primary_app,
                    "create_modern_webview_frame",
                    side_effect=RuntimeError("frame boom"),
                ),
                patch.object(
                    modern_primary_app,
                    "_show_startup_failure_dialog",
                    lambda message: order.append("dialog"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = modern_primary_app._launch(
                    Path(directory) / "PixelFlasher.json",
                    {"logs": Path(directory) / "logs"},
                    None,
                    interactive=True,
                )

            self.assertEqual(1, result)
            self.assertEqual(["shutdown", "dialog"], order)


# -----------------------------------------------------------------------------
#  IMPORTANT-12  degraded distributions were only printed to a hidden console
# -----------------------------------------------------------------------------
class DistributionFailureDurabilityTests(unittest.TestCase):
    def test_unavailable_downloads_land_in_the_durable_startup_log(self):
        class _ManifestError(RuntimeError):
            code = "platform_tools_manifest_verification_failed"

        class _Opener:
            @staticmethod
            def open(config_path: Path, **kwargs: object) -> object:
                raise _Stop("runtime construction is out of scope for this test")

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("tempfile.gettempdir", return_value=directory),
                patch.object(modern_primary_app, "is_webview_available", return_value=True),
                patch.object(modern_primary_app, "frontend_index_path", return_value=Path("index.html")),
                patch.object(
                    modern_primary_app,
                    "load_optional_platform_tools_distribution",
                    side_effect=_ManifestError("manifest has expired"),
                ),
                patch.object(modern_primary_app, "ApplicationRuntime", _Opener),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = modern_primary_app._launch(
                    Path(directory) / "PixelFlasher.json",
                    {"logs": Path(directory) / "logs"},
                    None,
                    interactive=False,
                )

            self.assertEqual(1, result)
            written = (Path(directory) / modern_primary_app._STARTUP_ERROR_LOG_NAME).read_text(encoding="utf-8")
            self.assertIn("official downloads unavailable", written)
            self.assertIn("platform_tools_manifest_verification_failed", written)


# -----------------------------------------------------------------------------
#  IMPORTANT-10  the entrypoint dialog could hang a headless CI smoke run
# -----------------------------------------------------------------------------
def _load_entrypoint() -> ModuleType:
    """Import PixelFlasher.py without running its module level launch calls."""

    path = REPO_ROOT / "PixelFlasher.py"
    source = path.read_text(encoding="utf-8")
    body = "\n".join(
        line
        for line in source.splitlines()
        if not line.startswith(("_run_cli_command(", "_run_modern_primary("))
    )
    module = ModuleType("pixelflasher_entrypoint_under_test")
    exec(compile(body, str(path), "exec"), module.__dict__)
    return module


class EntrypointSmokeDialogTests(unittest.TestCase):
    def setUp(self):
        self.entrypoint = _load_entrypoint()

    def test_ui_smoke_run_never_raises_a_modal_dialog(self):
        argv = ["PixelFlasher.exe", "--ui-smoke-report", "report.json", "--config", "cfg.json"]
        with (
            patch.object(sys, "platform", "win32"),
            patch("ctypes.windll.user32.MessageBoxW") as message_box,
        ):
            self.entrypoint._show_startup_failure_dialog("Modern UI startup unavailable: boom", None, argv)

        message_box.assert_not_called()

    def test_inline_ui_smoke_report_is_also_suppressed(self):
        argv = ["PixelFlasher.exe", "--ui-smoke-report=report.json"]
        with (
            patch.object(sys, "platform", "win32"),
            patch("ctypes.windll.user32.MessageBoxW") as message_box,
        ):
            self.entrypoint._show_startup_failure_dialog("Modern UI startup unavailable: boom", None, argv)

        message_box.assert_not_called()

    def test_an_interactive_run_still_reaches_the_dialog(self):
        with (
            patch.object(sys, "platform", "win32"),
            patch("ctypes.windll.user32.MessageBoxW") as message_box,
        ):
            self.entrypoint._show_startup_failure_dialog("Modern UI startup unavailable: boom", None, ["PixelFlasher.exe"])

        message_box.assert_called_once()

    def test_the_entrypoint_forwards_argv_to_the_dialog(self):
        argv = ["PixelFlasher.exe", "--ui-smoke-report", "report.json"]
        calls: list[tuple[object, ...]] = []
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch("tempfile.gettempdir", return_value=directory),
                patch.object(
                    self.entrypoint,
                    "_show_startup_failure_dialog",
                    lambda *args: calls.append(args),
                ),
                patch(
                    "ui.pages.modern_primary_app.launch_modern_primary",
                    side_effect=RuntimeError("boom"),
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(SystemExit):
                    self.entrypoint._run_modern_primary(argv)

        self.assertEqual(1, len(calls))
        self.assertEqual(argv, list(calls[0][2]))


# -----------------------------------------------------------------------------
#  IMPORTANT-16  a killed daemon download thread left a truncated firmware file
# -----------------------------------------------------------------------------
class _CancelButtonStub:
    def __init__(self):
        self.handler = None

    def Bind(self, event, handler):
        self.handler = handler


class _ProgressWindowStub:
    def __init__(self, cancel_button):
        self.cancel_button = cancel_button

    def add_download(self, url, filename):
        return MagicMock(), self.cancel_button

    def remove_download(self, url):
        pass


class _GoogleImagesMenuStub:
    def __init__(self):
        self.cancel_button = _CancelButtonStub()
        self.progress = _ProgressWindowStub(self.cancel_button)
        self.parent = MagicMock()
        del self.parent.download_progress_window
        self.parent.get_progress_window.return_value = self.progress

    def get_progress_window(self):
        return self.progress


class DownloadPromotionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.destination = os.path.join(self.tempdir.name, "image.zip")

    def _start(self, chunks):
        menu = _GoogleImagesMenuStub()
        response = MagicMock()
        response.headers = {'content-length': '8'}
        response.iter_content.return_value = chunks
        with (
            patch("Main.wx.CallAfter"),
            patch("Main.requests.get", return_value=response) as requests_get,
            patch("Main.threading.Thread") as thread,
        ):
            Main.GoogleImagesBaseMenu.download_with_progress(
                menu, "https://dl.google.com/image.zip", self.destination, lambda: None)
        return menu, requests_get, thread

    def test_an_interrupted_transfer_never_writes_the_destination_name(self):
        """A daemon thread killed at interpreter exit must not leave a truncated ZIP."""

        menu, requests_get, thread = self._start([b"abcd", b"efgh"])

        class _Frozen(BaseException):
            """Models the abrupt death of the daemon worker: no handler catches it."""

        def interrupted_chunks():
            yield b"abcd"
            raise _Frozen("the daemon worker died at interpreter finalization")

        requests_get.return_value.iter_content.return_value = interrupted_chunks()
        with contextlib.redirect_stdout(io.StringIO()):
            with (
                patch("Main.wx.CallAfter"),
                patch("Main.requests.get", requests_get),
            ):
                with self.assertRaises(_Frozen):
                    thread.call_args.kwargs['target']()

        # The truncated bytes exist, but never under the name the user picked and
        # never with the firmware's own file name.
        self.assertFalse(os.path.exists(self.destination))
        self.assertEqual(b"abcd", Path(self.destination + ".part").read_bytes())

    def test_a_completed_transfer_is_promoted_to_the_destination(self):
        menu, requests_get, thread = self._start([b"abcd", b"efgh"])

        with contextlib.redirect_stdout(io.StringIO()):
            with (
                patch("Main.wx.CallAfter"),
                patch("Main.requests.get", requests_get),
            ):
                thread.call_args.kwargs['target']()

        self.assertTrue(os.path.exists(self.destination))
        self.assertEqual(b"abcdefgh", Path(self.destination).read_bytes())
        self.assertFalse(os.path.exists(self.destination + ".part"))

    def test_a_failed_download_leaves_an_existing_good_copy_untouched(self):
        Path(self.destination).write_bytes(b"previously downloaded firmware")
        menu, requests_get, thread = self._start([b"abcd"])

        def exploding_chunks():
            yield b"abcd"
            raise OSError("connection reset")

        requests_get.return_value.iter_content.return_value = exploding_chunks()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with (
                patch("Main.wx.CallAfter"),
                patch("Main.requests.get", requests_get),
            ):
                thread.call_args.kwargs['target']()

        self.assertIn("Download error", output.getvalue())
        self.assertEqual(b"previously downloaded firmware", Path(self.destination).read_bytes())
        self.assertFalse(os.path.exists(self.destination + ".part"))


if __name__ == "__main__":
    unittest.main()
