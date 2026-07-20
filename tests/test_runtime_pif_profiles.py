from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.contracts import AppCommand, OperationStatus
from pixelflasher_core.runtime import ApplicationRuntime


def versioned_config(path: Path) -> None:
    path.write_text(json.dumps({"_pixelflasher_core_schema": 1}), encoding="utf-8")


class RuntimePifProfileTests(unittest.TestCase):
    def test_transform_is_revision_bound_bounded_and_does_not_mutate_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path)
            runtime = ApplicationRuntime.open(path)
            result = runtime.execute(AppCommand(
                "root.pif.transform", expected_revision=0,
                payload={
                    "content": "ro.product.brand=google\nro.product.model=Pixel 9\n",
                    "inputFormat": "prop", "outputFormat": "json", "normalize": True,
                    "keepUnknown": False, "sortKeys": True, "firstApi": 35,
                },
            ))
            self.assertEqual(result.status, OperationStatus.SUCCESS)
            self.assertEqual(result.code, "pif_transformed")
            self.assertEqual(json.loads(result.value["content"])["BRAND"], "google")
            self.assertTrue(result.value["bounded"])
            self.assertEqual(runtime.snapshot().revision, 0)
            runtime.shutdown()

    def test_favorite_lifecycle_advances_snapshot_and_repository_revisions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path)
            runtime = ApplicationRuntime.open(path)
            saved = runtime.execute(AppCommand(
                "root.pif.favorites.save", expected_revision=0,
                payload={"label": "Pixel 9", "content": '{"BRAND":"google","MODEL":"Pixel 9"}'},
            ))
            self.assertTrue(saved.ok)
            favorite_id = saved.value["favorite"]["favoriteId"]
            self.assertEqual(saved.value["revision"], 1)
            self.assertEqual(saved.value["snapshotRevision"], 1)

            listed = runtime.execute(AppCommand(
                "root.pif.favorites.list", expected_revision=1, payload={}
            ))
            self.assertEqual(listed.value["count"], 1)
            self.assertNotIn("content", listed.value["favorites"][0])
            loaded = runtime.execute(AppCommand(
                "root.pif.favorites.get", expected_revision=1,
                payload={"favoriteId": favorite_id},
            ))
            self.assertIn('"MODEL": "Pixel 9"', loaded.value["favorite"]["content"])

            deleted = runtime.execute(AppCommand(
                "root.pif.favorites.delete", expected_revision=1,
                payload={"favoriteId": favorite_id},
            ))
            self.assertTrue(deleted.ok)
            self.assertEqual(deleted.value["revision"], 2)
            self.assertEqual(deleted.value["snapshotRevision"], 2)
            self.assertEqual(runtime.pif_favorites_repository.list(), ())
            runtime.shutdown()

    def test_stale_or_invalid_commands_fail_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            versioned_config(path)
            runtime = ApplicationRuntime.open(path)
            missing_revision = runtime.execute(AppCommand(
                "root.pif.favorites.list", payload={}
            ))
            stale = runtime.execute(AppCommand(
                "root.pif.favorites.save", expected_revision=9,
                payload={"label": "Pixel", "content": '{"BRAND":"google"}'},
            ))
            invalid = runtime.execute(AppCommand(
                "root.pif.transform", expected_revision=0,
                payload={
                    "content": '{"nested":{}}', "inputFormat": "json",
                    "outputFormat": "json", "normalize": False,
                    "keepUnknown": True, "sortKeys": False,
                },
            ))
            self.assertEqual(missing_revision.code, "revision_required")
            self.assertEqual(stale.code, "stale_revision")
            self.assertEqual(invalid.code, "pif_profile_invalid")
            self.assertFalse(runtime.pif_favorites_repository.path.exists())
            self.assertEqual(runtime.snapshot().revision, 0)
            runtime.shutdown()

    def test_runtime_imports_legacy_favorites_without_globals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "config.json"
            versioned_config(path)
            (root / "favorite_pifs.json").write_text(json.dumps({
                "legacy": {"label": "Legacy Pixel", "date_added": "2025-01-01",
                           "pif": {"BRAND": "google", "MODEL": "Pixel"}},
            }), encoding="latin-1")
            runtime = ApplicationRuntime.open(path)
            listed = runtime.execute(AppCommand(
                "root.pif.favorites.list", expected_revision=0, payload={}
            ))
            self.assertEqual(listed.value["favorites"][0]["label"], "Legacy Pixel")
            self.assertTrue(runtime.pif_favorites_repository.path.exists())
            runtime.shutdown()


if __name__ == "__main__":
    unittest.main()
