"""Regression tests for the startup/diagnostics packet (BUG-11/12/13/21)."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
from platformdirs import user_data_dir

import diagnostics
from constants import APPNAME
from pixelflasher_core.support_v2 import SupportPackageReader
from pixelflasher_core.support_v2_service import (
    _ALLOWED_LOG_SUFFIXES,
    SupportPackageV2Service,
)
from ui.pages import modern_primary_app

SESSION_LOG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. ()-]{0,159}\.log$")
NOW = datetime(2026, 7, 18, 12, 0, 0, tzinfo=UTC)


class _Stop(Exception):
    """Marker raised in place of the real runtime so no engine is constructed."""


class SessionLogTests(unittest.TestCase):
    def test_launching_opens_a_session_log_that_captures_stdout_and_logging(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory) / "logs"
            session_log = modern_primary_app._open_session_log(logs)
            self.assertIsNotNone(session_log)
            assert session_log is not None
            try:
                print("device scan produced 1 device")
                logging.getLogger("pixelflasher.test").info("flash plan prepared")
            finally:
                session_log.close()

            self.assertIs(sys.stdout, session_log._previous_stdout)
            written = session_log.path.read_text(encoding="utf-8")
            self.assertIn("device scan produced 1 device", written)
            self.assertIn("flash plan prepared", written)
            self.assertIn(APPNAME, written)

    def test_session_log_name_is_collectible_by_the_support_package(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory) / "logs"
            session_log = modern_primary_app._open_session_log(logs)
            assert session_log is not None
            session_log.close()

            self.assertTrue(session_log.path.name.startswith(f"{APPNAME}_"))
            self.assertRegex(session_log.path.name, SESSION_LOG_NAME)
            self.assertIn(session_log.path.suffix, _ALLOWED_LOG_SUFFIXES)

    def test_session_logs_are_retained_within_a_bounded_window(self):
        with tempfile.TemporaryDirectory() as directory:
            logs = Path(directory)
            for index in range(20):
                (logs / f"{APPNAME}_2026-01-{index + 1:02d}_10h00m00s.log").write_text("old", encoding="utf-8")

            session_log = modern_primary_app._open_session_log(logs)
            assert session_log is not None
            session_log.close()

            remaining = sorted(path.name for path in logs.glob(f"{APPNAME}_*.log"))
            self.assertEqual(modern_primary_app._SESSION_LOG_RETENTION, len(remaining))
            self.assertIn(session_log.path.name, remaining)
            self.assertNotIn(f"{APPNAME}_2026-01-01_10h00m00s.log", remaining)


class StartupFailureVisibilityTests(unittest.TestCase):
    def test_startup_failure_is_written_to_the_startup_error_log(self):
        with tempfile.TemporaryDirectory() as directory:
            try:
                raise RuntimeError("boom")
            except RuntimeError as exc:
                with patch("tempfile.gettempdir", return_value=directory):
                    modern_primary_app._report_startup_failure(
                        "PixelFlasher startup failed: boom",
                        exc,
                        interactive=False,
                    )
            written = (Path(directory) / modern_primary_app._STARTUP_ERROR_LOG_NAME).read_text(encoding="utf-8")
            self.assertIn("PixelFlasher startup failed: boom", written)
            self.assertIn("RuntimeError", written)
            self.assertIn("Traceback", written)

    def test_missing_frontend_reports_instead_of_only_printing(self):
        with tempfile.TemporaryDirectory() as directory:
            dialogs: list[str] = []
            with (
                patch("tempfile.gettempdir", return_value=directory),
                patch.object(modern_primary_app, "is_webview_available", return_value=True),
                patch.object(
                    modern_primary_app,
                    "frontend_index_path",
                    side_effect=FileNotFoundError("ui/web/dist/index.html"),
                ),
                patch.object(modern_primary_app, "_show_startup_failure_dialog", dialogs.append),
            ):
                result = modern_primary_app._launch(
                    Path(directory) / "PixelFlasher.json",
                    {"logs": Path(directory) / "logs"},
                    None,
                    interactive=True,
                )

            self.assertEqual(1, result)
            written = (Path(directory) / modern_primary_app._STARTUP_ERROR_LOG_NAME).read_text(encoding="utf-8")
            self.assertIn("PixelFlasher React application is unavailable", written)
            self.assertEqual(1, len(dialogs))
            self.assertIn("PixelFlasher React application is unavailable", dialogs[0])

    def test_smoke_runs_never_raise_a_modal_dialog(self):
        with tempfile.TemporaryDirectory() as directory:
            dialogs: list[str] = []
            with (
                patch("tempfile.gettempdir", return_value=directory),
                patch.object(modern_primary_app, "is_webview_available", return_value=False),
                patch.object(modern_primary_app, "_show_startup_failure_dialog", dialogs.append),
            ):
                result = modern_primary_app._launch(
                    Path(directory) / "PixelFlasher.json",
                    {"logs": Path(directory) / "logs"},
                    modern_primary_app.UiSmokeOptions(Path(directory) / "receipt.json"),
                    interactive=False,
                )

            self.assertEqual(1, result)
            self.assertEqual([], dialogs)


class DistributionDegradationTests(unittest.TestCase):
    def test_unverifiable_distribution_yields_none_and_keeps_the_launch_alive(self):
        failures: list[str] = []

        class _ManifestError(RuntimeError):
            code = "platform_tools_manifest_verification_failed"

        def _raise() -> object:
            raise _ManifestError("manifest has expired")

        value = modern_primary_app._load_optional_distribution("platform-tools", _raise, failures)

        self.assertIsNone(value)
        self.assertEqual(["platform-tools: platform_tools_manifest_verification_failed"], failures)

    def test_expired_platform_tools_manifest_no_longer_aborts_startup(self):
        class _ManifestError(RuntimeError):
            code = "platform_tools_manifest_verification_failed"

        captured: dict[str, object] = {}

        class _FakeRuntime:
            @staticmethod
            def open(config_path: Path, **kwargs: object) -> object:
                captured.update(kwargs)
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
                patch.object(modern_primary_app, "ApplicationRuntime", _FakeRuntime),
                patch.object(modern_primary_app, "_show_startup_failure_dialog", lambda message: None),
            ):
                result = modern_primary_app._launch(
                    Path(directory) / "PixelFlasher.json",
                    {"logs": Path(directory) / "logs"},
                    None,
                    interactive=False,
                )

            # The launch reached runtime construction instead of aborting at the
            # manifest, and the unverifiable distribution degraded to "no catalog".
            self.assertEqual(1, result)
            self.assertIn("platform_tools_catalog", captured)
            self.assertIsNone(captured["platform_tools_catalog"])
            self.assertIsNone(captured["platform_tools_downloader"])


class DiagnosticsPathTests(unittest.TestCase):
    def test_config_root_matches_the_roaming_root_the_application_uses(self):
        self.assertEqual(
            Path(user_data_dir(APPNAME, appauthor=False, roaming=True)),
            diagnostics.config_root(),
        )

    def test_system_info_points_at_the_directories_the_application_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(diagnostics, "config_root", return_value=root):
                info = diagnostics._system_info()
            self.assertEqual(str(root), info["config_dir"])
            self.assertEqual(str(root), info["data_dir"])
            self.assertEqual(str(root / "logs"), info["log_dir"])

    def test_session_logs_are_collected_from_the_application_log_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "logs"
            logs.mkdir()
            newest = logs / f"{APPNAME}_2026-07-30_10h00m00s.log"
            newest.write_text("flash plan prepared", encoding="utf-8")
            (logs / f"{APPNAME}_2026-07-29_10h00m00s.log").write_text("older session", encoding="utf-8")
            diagrams = root / "puml"
            diagrams.mkdir()
            (diagrams / "trace.puml").write_text("@startuml\n@enduml", encoding="utf-8")

            with patch.object(diagnostics, "config_root", return_value=root):
                collected = list(diagnostics._candidate_logs(root))

            self.assertIn(newest, collected)
            self.assertIn(logs / f"{APPNAME}_2026-07-29_10h00m00s.log", collected)
            self.assertIn(diagrams / "trace.puml", collected)
            self.assertEqual(newest, collected[0])

    def test_collected_log_count_is_capped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "logs"
            logs.mkdir()
            for index in range(diagnostics.MAX_COLLECTED_LOGS + 12):
                (logs / f"{APPNAME}_2026-07-{index % 28 + 1:02d}_10h{index:02d}m00s.log").write_text(
                    "session",
                    encoding="utf-8",
                )

            with patch.object(diagnostics, "config_root", return_value=root):
                collected = list(diagnostics._candidate_logs(root))

            self.assertEqual(diagnostics.MAX_COLLECTED_LOGS, len(collected))


class SupportPackageDatabaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.public_key = cls.private_key.public_key()

    @staticmethod
    def _legacy_database(path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute(
                "CREATE TABLE PACKAGE (id INTEGER, boot_hash TEXT, type TEXT, "
                "package_sig TEXT, file_path TEXT, epoch INTEGER)"
            )
            connection.execute(
                "INSERT INTO PACKAGE VALUES (?, ?, ?, ?, ?, ?)",
                (1, "a" * 40, "firmware", "factory", "firmware.zip", 1234),
            )
            connection.commit()
        finally:
            connection.close()

    def test_v9_database_name_is_collected_into_the_support_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"safe": "preserved"}), encoding="utf-8")
            self._legacy_database(root / "PixelFlasher4.db")

            service = SupportPackageV2Service(
                config,
                self.public_key,
                key_id="support-prod-2026",
                app_version="10.0-test",
                clock=lambda: NOW,
            )
            destination = root / "support.zip"
            destination_id = service.register_destination(destination)

            result = service.create({"destinationId": destination_id}, snapshot=object())

            self.assertTrue(result.ok, result.message)
            read = SupportPackageReader(self.private_key).read(destination)
            self.assertIn(
                "database/PixelFlasher.sqlite3",
                {entry.archive_name for entry in read.entries},
            )
            self.assertNotIn(
                ("legacy-database", "database", "not_found"),
                {(item.source, item.category, item.reason) for item in read.omissions},
            )


if __name__ == "__main__":
    unittest.main()
