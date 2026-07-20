from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from pixelflasher_core.patch_resources import (
    PATCH_RUNNER_MARKER,
    load_optional_packaged_patch_resource_registry,
)

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "resources" / "boot-patch" / "runner" / "pf_boot_patch.sh"
MANIFEST = ROOT / "resources" / "boot-patch" / "runtime" / "patch-resources.json"
DIGEST = ROOT / "resources" / "boot-patch" / "runtime" / "patch-resources.sha256"


class PackagedPatchRunnerTests(unittest.TestCase):
    def test_checked_in_distribution_is_hash_bound_and_complete_except_legacy(self) -> None:
        registry = load_optional_packaged_patch_resource_registry(ROOT, hash_chunk_size=4096)

        self.assertIsNotNone(registry)
        assert registry is not None
        self.assertEqual(frozenset({"legacy"}), registry.missing_flavors)
        self.assertEqual(24, len(registry.tool_bundles))
        self.assertEqual(
            {"arm64", "arm", "x86", "x86_64"},
            {bundle.architectures[0] for bundle in registry.tool_bundles},
        )
        self.assertTrue(all(bundle.app_id == "" for bundle in registry.tool_bundles))
        encoded = MANIFEST.read_bytes()
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), DIGEST.read_text("ascii").strip())
        self.assertEqual(3, json.loads(encoded)["schemaVersion"])

    def test_runner_has_closed_protocol_and_secret_transport(self) -> None:
        encoded = RUNNER.read_bytes()
        source = encoded.decode("utf-8")

        self.assertIn(PATCH_RUNNER_MARKER, encoded)
        self.assertIn("IFS= read -r SUPERKEY", source)
        self.assertIn("set -- \"$SUPERKEY\" \"$INPUT\" -K kpatch", source)
        self.assertNotIn("eval ", source)
        self.assertNotIn("sh -c", source)
        self.assertNotIn("su -c", source)
        self.assertNotIn('echo "$SUPERKEY"', source)
        self.assertNotIn("http://", source)
        self.assertNotIn("https://", source)

    def test_absence_is_optional_but_partial_distribution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pf-patch-distribution-") as directory:
            root = Path(directory)
            self.assertIsNone(load_optional_packaged_patch_resource_registry(root))
            (root / "resources" / "boot-patch" / "runtime").mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "digest"):
                load_optional_packaged_patch_resource_registry(root)

    def test_all_packagers_include_the_runner_distribution(self) -> None:
        for name in (
            "build-on-win.spec",
            "build-on-win-arm64.spec",
            "build-on-mac.spec",
            "build-on-mac-intel-only.spec",
            "build-on-linux.spec",
        ):
            with self.subTest(name=name):
                source = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("('resources/boot-patch', 'resources/boot-patch')", source)


if __name__ == "__main__":
    unittest.main()
