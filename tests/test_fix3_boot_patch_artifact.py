"""The stock boot image lives in the content-addressed store, not as a .img file.

Reported from real hardware: selecting a repository boot image and patching it
failed with `boot_artifact_invalid: selected path has an invalid file type`,
because the compiler demanded a ".img" suffix from an object whose name is the
bare SHA-256. Boot patching was impossible for every image the inventory owns.
"""

from __future__ import annotations

import hashlib
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from pixelflasher_core.boot_patch import BootPatchPlanningError, BootPatchService


class CanonicalBootArtifactSuffixTests(unittest.TestCase):
    def _store_object(self, root: Path, payload: bytes) -> tuple[Path, str]:
        """Write payload the way ArtifactRepository does: sharded, no extension."""

        digest = hashlib.sha256(payload).hexdigest()
        target = root / "objects" / digest[:2] / digest[2:]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target, digest

    def test_extensionless_store_object_is_accepted(self):
        with TemporaryDirectory() as directory:
            stored, digest = self._store_object(Path(directory), b"boot-image-payload")
            self.assertEqual("", stored.suffix)

            resolved = BootPatchService._absolute_existing_file(
                str(stored),
                None,
                "boot_artifact_invalid",
            )

            self.assertEqual(stored.resolve(), resolved)
            self.assertEqual(digest, hashlib.sha256(resolved.read_bytes()).hexdigest())

    def test_the_retired_suffix_requirement_would_have_rejected_it(self):
        with TemporaryDirectory() as directory:
            stored, _ = self._store_object(Path(directory), b"boot-image-payload")

            with self.assertRaises(BootPatchPlanningError) as raised:
                BootPatchService._absolute_existing_file(
                    str(stored),
                    ".img",
                    "boot_artifact_invalid",
                )

            self.assertEqual("boot_artifact_invalid", raised.exception.code)
            self.assertIn("invalid file type", str(raised.exception))

    def test_a_directory_is_still_refused_without_a_suffix_requirement(self):
        with TemporaryDirectory() as directory:
            with self.assertRaises(BootPatchPlanningError) as raised:
                BootPatchService._absolute_existing_file(
                    directory,
                    None,
                    "boot_artifact_invalid",
                )

            self.assertEqual("boot_artifact_invalid", raised.exception.code)

    def test_an_empty_store_object_is_still_refused(self):
        with TemporaryDirectory() as directory:
            stored, _ = self._store_object(Path(directory), b"")

            with self.assertRaises(BootPatchPlanningError) as raised:
                BootPatchService._absolute_existing_file(
                    str(stored),
                    None,
                    "boot_artifact_invalid",
                )

            self.assertEqual("boot_artifact_invalid", raised.exception.code)
            self.assertIn("empty", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
