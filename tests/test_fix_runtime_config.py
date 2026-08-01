import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pixelflasher_core.contracts import FlashPlan
from pixelflasher_core.repositories import ArtifactRepository, RepositoryError
from pixelflasher_core.runtime import ApplicationRuntime


def _legacy_tools(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "count": 1,
                "tools": {
                    "1": {
                        "title": "Unsafe old command",
                        "command": "cmd.exe",
                        "arguments": "/c erase everything",
                        "enabled": True,
                    }
                },
            }
        ),
        encoding="iso-8859-1",
    )


class LegacyMigrationStartupTests(unittest.TestCase):
    """BUG-08: a failed 9.x import must never make the application unlaunchable."""

    def test_repository_error_during_migration_degrades_instead_of_aborting(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
            (root / "PixelFlasher4.db").write_bytes(b"database placeholder")

            with patch.object(
                ArtifactRepository,
                "migrate_legacy_v9",
                autospec=True,
                side_effect=RepositoryError("artifact_too_large", "artifact exceeds the import limit"),
            ):
                runtime = ApplicationRuntime.open(config)

            try:
                report = runtime.legacy_migration_report
                self.assertEqual("failed", report.status)
                self.assertEqual(str(root / "PixelFlasher4.db"), report.source_database)
                self.assertEqual(
                    "RepositoryError: artifact exceeds the import limit",
                    runtime.legacy_migration_error,
                )
            finally:
                runtime.shutdown()

    def test_successful_startup_records_no_migration_error(self) -> None:
        with TemporaryDirectory() as directory:
            runtime = ApplicationRuntime.open(Path(directory) / "PixelFlasher.json")
            try:
                self.assertIsNone(runtime.legacy_migration_error)
                self.assertEqual("not_found", runtime.legacy_migration_report.status)
            finally:
                runtime.shutdown()


class CorruptSidecarStartupTests(unittest.TestCase):
    """BUG-35: an unreadable sidecar store is quarantined, never fatal."""

    def test_corrupt_my_tools_store_is_quarantined_and_starts_empty(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            store = root / "my-tools-v1.json"
            store.write_text("{ not json", encoding="utf-8")
            _legacy_tools(root / "mytools.json")

            runtime = ApplicationRuntime.open(config)
            try:
                inventory = runtime.my_tools_repository.inventory()
                self.assertEqual([], inventory["tools"])
                # The quarantined store already consumed the one-time 9.x
                # discovery; recovery must not re-grant migrated legacy tools.
                self.assertEqual([], inventory["legacyRaw"])
                quarantine = root / "my-tools-v1.json.corrupt.bak"
                self.assertTrue(quarantine.is_file())
                self.assertEqual("{ not json", quarantine.read_text(encoding="utf-8"))
                self.assertIn(quarantine, runtime.quarantined_stores)
            finally:
                runtime.shutdown()

    def test_unsupported_my_tools_schema_is_quarantined(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            store = root / "my-tools-v1.json"
            store.write_text(
                json.dumps({"schemaVersion": 99, "tools": [], "legacyRaw": []}),
                encoding="utf-8",
            )

            runtime = ApplicationRuntime.open(config)
            try:
                self.assertEqual([], runtime.my_tools_repository.inventory()["tools"])
                self.assertTrue((root / "my-tools-v1.json.corrupt.bak").is_file())
            finally:
                runtime.shutdown()

    def test_corrupt_pif_favorites_store_is_quarantined(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            favorites = ApplicationRuntime._pif_favorites_path(config)
            favorites.parent.mkdir(parents=True, exist_ok=True)
            favorites.write_text("{ not json", encoding="utf-8")

            runtime = ApplicationRuntime.open(config)
            try:
                self.assertEqual((), runtime.pif_favorites_repository.list())
                self.assertTrue(favorites.with_name(f"{favorites.name}.corrupt.bak").is_file())
            finally:
                runtime.shutdown()

    def test_constructor_failure_after_sqlite_opens_closes_both_repositories(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            closed: list[Path] = []
            real_close = ArtifactRepository.close

            def close(repository: ArtifactRepository) -> None:
                closed.append(repository.database_path)
                real_close(repository)

            with (
                patch(
                    "pixelflasher_core.runtime.MyToolsRepository",
                    side_effect=OSError("injected personal tools failure"),
                ),
                patch.object(
                    ArtifactRepository,
                    "close",
                    autospec=True,
                    side_effect=close,
                ),
            ):
                with self.assertRaisesRegex(OSError, "injected personal tools failure"):
                    ApplicationRuntime.open(config)

            self.assertEqual(1, len(closed))
            # Windows only releases the file once every handle is closed.
            (root / ".PixelFlasher.json.cache" / "backup-repository" / "backups.sqlite3").unlink()


class LegacyMirrorShutdownTests(unittest.TestCase):
    """BUG-48: shutdown never overwrites a 9.x selection it could not resolve."""

    def test_shutdown_preserves_unresolved_legacy_selection(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(
                json.dumps(
                    {
                        "device": "SERIAL-A",
                        "firmware_path": str(root / "raven-ota.zip"),
                        "mode": "wipeData",
                    }
                ),
                encoding="utf-8",
            )

            runtime = ApplicationRuntime.open(config)
            runtime.shutdown()

            persisted = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual("SERIAL-A", persisted["device"])
            self.assertEqual(str(root / "raven-ota.zip"), persisted["firmware_path"])
            self.assertEqual("wipeData", persisted["mode"])

    def test_shutdown_mirrors_an_established_modern_plan(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"mode": "wipeData"}), encoding="utf-8")

            runtime = ApplicationRuntime.open(config)
            runtime.store.update(
                expected_revision=0,
                plan=FlashPlan("keepdata", {}, revision=1, dry_run=False),
            )
            runtime.shutdown()

            persisted = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual("keepData", persisted["mode"])

    def test_shutdown_mirrors_an_established_dry_run_plan(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "PixelFlasher.json"
            config.write_text(json.dumps({"mode": "wipeData"}), encoding="utf-8")

            runtime = ApplicationRuntime.open(config)
            runtime.store.update(
                expected_revision=0,
                plan=FlashPlan("images", {}, revision=1, dry_run=True),
            )
            runtime.shutdown()

            persisted = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual("dryRun", persisted["mode"])

    def test_legacy_mode_mapping_never_guesses_an_unknown_equivalent(self) -> None:
        self.assertIsNone(
            ApplicationRuntime._legacy_flash_mode(FlashPlan("wipedata", {}, revision=0, dry_run=False))
        )
        self.assertEqual(
            "wipeData",
            ApplicationRuntime._legacy_flash_mode(FlashPlan("wipedata", {}, revision=3, dry_run=False)),
        )
        self.assertEqual(
            "OTA",
            ApplicationRuntime._legacy_flash_mode(FlashPlan("sideload", {}, revision=1, dry_run=False)),
        )
        self.assertEqual(
            "customFlash",
            ApplicationRuntime._legacy_flash_mode(FlashPlan("customflash", {}, revision=1, dry_run=False)),
        )
        self.assertIsNone(
            ApplicationRuntime._legacy_flash_mode(FlashPlan("images", {}, revision=1, dry_run=False))
        )


if __name__ == "__main__":
    unittest.main()
